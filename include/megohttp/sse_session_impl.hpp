#ifndef MEGOHTTP_SSE_SESSION_IMPL_HPP_INCLUDED
#define MEGOHTTP_SSE_SESSION_IMPL_HPP_INCLUDED

#include <megohttp/format.hpp>
#include <megohttp/response.hpp>

namespace megohttp {

    // -------------------------------------------------------------------------
    // SseSession implementation
    // -------------------------------------------------------------------------

    inline SseSession::SseSession(std::shared_ptr<Executor> executor,
                                  RequestSubmitter submitter,
                                  Request request,
                                  SseReconnectPolicy reconnect_policy)
        : executor_(std::move(executor))
        , submitter_(std::move(submitter))
        , request_(std::move(request))
        , reconnect_policy_(std::move(reconnect_policy))
        , session_start_(Clock::now())
        , flow_(std::make_shared<Request::BodySinkFlow>())
    {
    }

    inline SseSession::~SseSession() {
        cancel();
    }

    inline void SseSession::on_event(EventCallback cb) {
        std::lock_guard<std::mutex> lock(mutex_);
        event_cb_ = std::move(cb);
    }

    inline void SseSession::on_error(ErrorCallback cb) {
        std::lock_guard<std::mutex> lock(mutex_);
        error_cb_ = std::move(cb);
    }

    inline void SseSession::on_complete(CompleteCallback cb) {
        std::lock_guard<std::mutex> lock(mutex_);
        complete_cb_ = std::move(cb);
    }

    inline void SseSession::start() {
        if (active_.exchange(true)) {
            return;  // Already started
        }
        attempt_connection();
    }

    inline void SseSession::cancel() {
        if (cancelled_.exchange(true)) {
            return;  // Already cancelled
        }
        active_.store(false);
        // A paused request has no outstanding read; let the Client drain and
        // finish it so the transport/state is not stranded.
        if (flow_) flow_->resume();
        terminate();
    }

    inline void SseSession::pause_receive() {
        if (flow_) flow_->pause();
    }

    inline void SseSession::resume_receive() {
        if (!flow_ || cancelled_.load() || !active_.load()) return;
        // The Client owns the SSE parser and its retained bytes. Resuming the
        // flow posts the parser replay and read restart onto the I/O context.
        flow_->resume();
    }

    inline bool SseSession::is_receive_paused() const noexcept {
        return flow_ && flow_->is_paused();
    }

    inline std::optional<string> SseSession::last_event_id() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_event_id_;
    }

    inline void SseSession::deliver_event(const SseEvent& event) {
        if (cancelled_.load()) {
            return;
        }

        // Update last event ID. Note: event.id is std::optional<string>, so
        // we check has_value() and then inspect the inner string.
        //
        // Delivering an event is also what proves a reconnect worked, so the
        // retry counter resets here and nowhere else. Resetting it from the
        // request completion callback was wrong: for a close-delimited stream
        // that callback runs after the body sink completed, erasing the count
        // schedule_reconnect had just incremented.
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (event.id.has_value() && !event.id->empty()) {
                last_event_id_ = event.id;
            }
            if (event.retry_ms.has_value()) {
                event_retry_ = event.retry_ms;
            }
            reconnect_attempts_ = 0;
        }

        // Deliver event
        EventCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = event_cb_;
        }
        if (cb) {
            try {
                cb(event);
            } catch (...) {
                // A throwing callback must not unwind through the parser/loop.
            }
        }
    }

    inline void SseSession::attempt_connection() {
        if (cancelled_.load()) {
            return;
        }

        if (!submitter_) {
            terminate(Error{ErrorCode::Cancelled, ErrorPhase::None,
                            string("No request submitter")});
            return;
        }

        // Prepare request with Last-Event-ID. The condition is "do we have an
        // id to resume from", NOT "is this a retry": WHATWG defines the header
        // as the last event id the client saw, whatever the reason for the new
        // connection. Gating on the retry counter made the header disappear as
        // soon as that counter was reset by a delivered event.
        Request req = request_;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (reconnect_policy_.send_last_event_id &&
                last_event_id_ && !last_event_id_->empty()) {
                req.headers().set("Last-Event-ID", *last_event_id_);
            }
        }

        // Let the Client own the SSE parser. That path already implements the
        // HTTP-framing -> Content-Encoding -> SSE order, retained-byte replay
        // on pause, and deferred terminal completion. flow_ turns a
        // pause_receive() into real socket backpressure.
        req.set_sse_callback(
            [this](const SseEvent& event) {
                deliver_event(event);
                return VoidResult{};
            },
            {},
            flow_);

        // Submit request through the injected submitter (no Client dependency).
        submitter_(std::move(req), [this](Result<Response> result) {
            if (cancelled_.load()) {
                return;
            }
            if (!result) {
                if (result.error().code() == ErrorCode::SseInvalidContentType) {
                    terminate(result.error());
                } else {
                    schedule_reconnect(result.error());
                }
                return;
            }

            const Response& response = result.value();
            const int status = response.head().status_code;

            // Terminal statuses: the server has nothing more to send.
            if (status == 204) {
                terminate();
                return;
            }
            if (status < 200 || status >= 300) {
                const Error status_err{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                                       format("SSE server returned status {}", status)};
                // stop_on_http_error == false lets the caller treat a non-2xx
                // answer as a transient failure worth retrying (a proxy 502, a
                // 429 with no Retry-After). With the flag on -- the default --
                // an HTTP error is an answer, and retrying it just repeats it.
                if (!reconnect_policy_.stop_on_http_error) {
                    schedule_reconnect(status_err);
                } else {
                    terminate(status_err);
                }
                return;
            }

            // Content-Type must be text/event-stream. Parameters (a charset,
            // typically) are ignored: WHATWG fixes SSE to UTF-8, and servers do
            // state it. Comparing the whole header value would reject the most
            // common real-world response.
            const auto ct = response.head().headers.get("content-type");
            bool is_sse = false;
            if (ct) {
                const string_view v = *ct;
                const size_t semi = v.find(';');
                is_sse = detail::ascii_iequals(
                    (semi == string_view::npos) ? v : v.substr(0, semi),
                    "text/event-stream");
            }
            if (!is_sse) {
                terminate(Error{ErrorCode::SseInvalidContentType, ErrorPhase::Receive,
                                string("SSE server did not return text/event-stream")});
                return;
            }

            // NOTE: the retry counter is NOT reset here. This callback runs
            // from the Client's terminal path, which for a close-delimited SSE
            // stream fires AFTER the body sink completed -- resetting here
            // would erase the count that schedule_reconnect had just
            // incremented, and the next attempt would send no Last-Event-ID.
            // The reset belongs to deliver_event(), i.e. to actually receiving
            // an event, which is what proves the reconnect worked.
            if (!reconnect_policy_.auto_reconnect) {
                terminate();
            } else {
                schedule_reconnect(Error{ErrorCode::ConnectionClosed,
                                         ErrorPhase::Receive,
                                         string("SSE stream ended")});
            }
        });
    }

    inline void SseSession::schedule_reconnect(const Error& err) {
        if (cancelled_.load()) {
            return;
        }

        if (!reconnect_policy_.auto_reconnect) {
            terminate(err);
            return;
        }

        const Duration elapsed = Clock::now() - session_start_;
        if (reconnect_detail::budget_exhausted(reconnect_policy_.backoff,
                                               reconnect_attempts_, elapsed)) {
            terminate(err);
            return;
        }

        size_t next_attempt = reconnect_attempts_ + 1;
        Duration delay = reconnect_detail::backoff_delay(
            reconnect_policy_.backoff, next_attempt,
            static_cast<uint32_t>(next_attempt * 7919u));

        // If the server sent a retry field (and we honour it), override the
        // backoff seed for this reconnect only. The server value is in
        // milliseconds, and is clamped by max_delay.
        std::optional<int> server_retry;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            server_retry = event_retry_;
        }
        if (reconnect_policy_.honor_server_retry && server_retry.has_value() &&
            *server_retry >= 0) {
            Duration sv = std::chrono::duration_cast<Duration>(
                std::chrono::milliseconds(*server_retry));
            if (sv > reconnect_policy_.backoff.max_delay)
                sv = reconnect_policy_.backoff.max_delay;
            delay = sv;
        }

        ++reconnect_attempts_;

        if (!executor_) {
            terminate(Error{ErrorCode::Cancelled, ErrorPhase::None,
                            string("No executor available for reconnect")});
            return;
        }

        auto self = shared_from_this();
        executor_->schedule_after(delay, [this, self]() {
            if (!cancelled_.load()) {
                attempt_connection();
            }
        });
    }

    inline void SseSession::terminate(const Error& err) {
        active_.store(false);

        ErrorCallback err_cb;
        CompleteCallback done_cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            err_cb = error_cb_;
            done_cb = complete_cb_;
            error_cb_ = nullptr;
            complete_cb_ = nullptr;
        }
        if (err_cb) {
            try { err_cb(err); } catch (...) {}
        }
        if (done_cb) {
            try { done_cb(); } catch (...) {}
        }
    }

    inline void SseSession::terminate() {
        active_.store(false);

        CompleteCallback done_cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            done_cb = complete_cb_;
            error_cb_ = nullptr;
            complete_cb_ = nullptr;
        }
        if (done_cb) {
            try { done_cb(); } catch (...) {}
        }
    }

} // namespace megohttp

#endif // MEGOHTTP_SSE_SESSION_IMPL_HPP_INCLUDED

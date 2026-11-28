#ifndef MEGOHTTP_FUTURE_HPP_INCLUDED
#define MEGOHTTP_FUTURE_HPP_INCLUDED

// Future-based request API (S2.7-01, S2.7-02).
//
// Reuses the callback core: a FutureRequest is just a std::promise wired to
// Client::request's completion callback. No second state machine, as spec 6.1
// requires.
//
// Usage:
//     auto op = client.request(req);            // future overload
//     // ... can call op.cancel() from any thread ...
//     Result<Response> r = op.get();          // blocks until the terminal callback
//
// Lifetime notes:
//   • get() blocks the calling thread. It must NOT be called from the thread that
//     drives the Client's executor, or it will wait for a callback that can only
//     run on that same thread (a deadlock). Use try_get/wait_for with a timeout,
//     or run the executor on another thread.
//   • get() may be called once. The Result is moved out.
//   • cancel() is thread-safe and may be called before or after get().

#include <megohttp/client.hpp>
#include <megohttp/error.hpp>
#include <megohttp/response.hpp>

#include <chrono>
#include <future>
#include <memory>
#include <utility>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // FutureRequest: the operation object returned by Client::request(req).
    //
    // Carries BOTH the future and the cancel handle, so a caller never ends up
    // holding one without the other (spec 6.1).
    // ---------------------------------------------------------------------------
    class FutureRequest {
    public:
        FutureRequest() = default;

        FutureRequest(std::shared_future<Result<Response>> fut, CancelHandle cancel)
            : future_(std::move(fut)), cancel_(std::move(cancel)) {}

        // Blocks until the request completes. Safe to call once.
        Result<Response> get() { return future_.get(); }

        // Blocks up to `timeout`. Returns nullopt when the request is still
        // running; the operation stays valid and can be waited on again.
        std::optional<Result<Response>> wait_for(std::chrono::milliseconds timeout) {
            if (future_.wait_for(timeout) != std::future_status::ready) return std::nullopt;
            return future_.get();
        }

        // Non-blocking poll.
        bool is_ready() const {
            return future_.valid() &&
                   future_.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
        }

        bool ready() const { return is_ready(); }

        // Thread-safe. Ends the request with ErrorCode::Cancelled; the future
        // still becomes ready (the completion callback fires exactly once).
        void cancel() { cancel_.cancel(); }

        bool is_cancelled() const { return cancel_.is_cancelled(); }

        // The underlying cancel handle, for callers that want to share it.
        const CancelHandle& cancel_handle() const noexcept { return cancel_; }

        bool valid() const noexcept { return future_.valid(); }

    private:
        std::shared_future<Result<Response>> future_;
        CancelHandle cancel_;
    };

// ---------------------------------------------------------------------------
// FutureRequest implementation (inline, needs the full Client)
// ---------------------------------------------------------------------------

inline FutureRequest Client::request(const Request& req) {
    // std::promise is move-only and std::function (the callback carrier) requires
    // a copyable target, so the promise lives in a shared_ptr captured by value.
    auto promise = std::make_shared<std::promise<Result<Response>>>();
    auto shared = promise->get_future().share();

    auto handle = this->request(req,
        [promise](Result<Response> r) {
            // The completion callback runs exactly once, so set_value cannot throw
            // with future_error here; guard anyway so a stray second call can
            // never propagate out of the I/O thread.
            try { promise->set_value(std::move(r)); } catch (...) {}
        });

    return FutureRequest(std::move(shared), std::move(handle));
}

inline FutureRequest Client::get(string_view url) {
    Request req(Method::Get, url);
    return request(req);
}

inline Result<Response> Client::request_sync(const Request& req) {
    // S2.7-04: detect the "caller == loop thread" deadlock.
    //
    // Backend-neutral, and it asks the executor rather than the backend:
    //   • libuv internal loop, Asio internal io_context -> the executor started
    //     the thread, knows its id, and answers accurately (including when the
    //     executor was supplied by the caller instead of created by the Client).
    //   • external loop (libuv uv_loop_t* or Asio io_context&) -> no single
    //     driver thread to compare against, so the contract answer is false and
    //     this cannot misfire. The caller must not block on the loop thread.
    if (impl_->executor && impl_->executor->is_in_loop_thread()) {
        return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                     string("request_sync called from the executor loop thread (would deadlock)")};
    }
    return request(req).get();
}

inline Result<Response> Client::get_sync(string_view url) {
    Request req(Method::Get, url);
    return request_sync(req);
}

} // namespace megohttp

#endif // MEGOHTTP_FUTURE_HPP_INCLUDED

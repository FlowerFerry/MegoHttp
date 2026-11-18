#ifndef MEGOHTTP_WEBSOCKET_RECONNECT_IMPL_HPP_INCLUDED
#define MEGOHTTP_WEBSOCKET_RECONNECT_IMPL_HPP_INCLUDED

namespace megohttp {

    inline ReconnectingWebSocket::ReconnectingWebSocket(
        std::shared_ptr<Executor> executor,
        WsStreamProvider provider,
        WebSocketOptions ws_options,
        WebSocketReconnectPolicy policy,
        TestHooks test_hooks)
        : executor_(std::move(executor))
        , provider_(std::move(provider))
        , ws_options_(std::move(ws_options))
        , policy_(std::move(policy))
        , hooks_(std::move(test_hooks)) {}

    inline ReconnectingWebSocket::~ReconnectingWebSocket() {
        terminate();
    }

    inline void ReconnectingWebSocket::on_open(OpenCallback cb) {
        std::lock_guard<std::mutex> lk(mutex_);
        open_cb_ = std::move(cb);
    }
    inline void ReconnectingWebSocket::on_message(MessageCallback cb) {
        std::lock_guard<std::mutex> lk(mutex_);
        message_cb_ = std::move(cb);
    }
    inline void ReconnectingWebSocket::on_close(CloseCallback cb) {
        std::lock_guard<std::mutex> lk(mutex_);
        close_cb_ = std::move(cb);
    }
    inline void ReconnectingWebSocket::on_error(ErrorCallback cb) {
        std::lock_guard<std::mutex> lk(mutex_);
        error_cb_ = std::move(cb);
    }
    inline void ReconnectingWebSocket::on_session_end(SessionEndCallback cb) {
        std::lock_guard<std::mutex> lk(mutex_);
        end_cb_ = std::move(cb);
    }
    inline void ReconnectingWebSocket::set_reconnect_events(ReconnectEvents e) {
        std::lock_guard<std::mutex> lk(mutex_);
        events_ = std::move(e);
    }

    inline void ReconnectingWebSocket::start(string host, string path,
                                             Headers extra_headers) {
        if (started_.exchange(true)) return;
        host_ = std::move(host);
        path_ = std::move(path);
        extra_headers_ = std::move(extra_headers);
        // The total-duration budget runs from the start of the LOGICAL session.
        // It is deliberately not refreshed on reconnect: a server that accepts
        // and immediately drops would otherwise reset the budget every time.
        session_start_ = now();
        attempt_connect();
    }

    inline void ReconnectingWebSocket::attempt_connect() {
        if (stopped_.load()) return;

        if (!provider_) {
            finish_session(Error{ErrorCode::WsHandshakeFailed, ErrorPhase::None,
                                 string("no stream provider configured")});
            return;
        }

        auto self = shared_from_this();
        // The provider is asynchronous: it resolves, connects and possibly
        // stacks TLS, then hands back a usable byte stream.
        provider_(host_, path_,
                   [self](Result<std::shared_ptr<AsyncByteStream>> r) {
                       if (self->stopped_.load()) {
                           if (r && r.value()) r.value()->async_close(nullptr);
                           return;
                       }
                       if (!r) {
                           self->handle_disconnect(r.error());
                           return;
                       }
                       auto stream = r.value();
                       if (!stream) {
                           self->handle_disconnect(
                               Error{ErrorCode::WsHandshakeFailed, ErrorPhase::None,
                                     string("stream provider returned an empty stream")});
                           return;
                       }

                       // A fresh WebSocketSession per physical connection: the
                       // zlib contexts and frame decoder must not be carried over.
                       auto session = std::make_shared<WebSocketSession>(
                           stream, self->ws_options_, self->executor_);
                       self->attach(session);
                       session->start(self->host_, self->path_, self->extra_headers_,
                                      [self](const Error& e) {
                                          if (self->stopped_.load()) return;
                                          if (e) {
                                              self->handle_disconnect(e);
                                              return;
                                          }
                                          self->reconnecting_.store(false);
                                          // The generation was already assigned
                                          // in attach(); bumping it again here
                                          // would make the is_current() check
                                          // in this connection's own callbacks
                                          // fail immediately.
                                          self->connected_at_ = self->now();
                                          const bool first = !self->ever_connected_;
                                          self->ever_connected_ = true;

                                          OpenCallback cb;
                                          {
                                              std::lock_guard<std::mutex> lk(self->mutex_);
                                              cb = self->open_cb_;
                                          }
                                          if (first && cb) {
                                              try { cb(e); } catch (...) {}
                                          } else if (cb) {
                                              // A reconnect that succeeded is reported
                                              // through the reconnect events, not as a
                                              // second "opened" -- the logical session
                                              // was already open once.
                                          }

                                          ReconnectEvents ev;
                                          {
                                              std::lock_guard<std::mutex> lk(self->mutex_);
                                              ev = self->events_;
                                          }
                                          if (!first && ev.on_succeeded) {
                                              try {
                                                  ev.on_succeeded(self->attempts_.load(),
                                                                  self->generation_.load());
                                              } catch (...) {}
                                          }
                                      });
                   });
    }

    inline void ReconnectingWebSocket::attach(std::shared_ptr<WebSocketSession> session) {
        // Every physical connection gets its own generation. All callbacks
        // captured below carry this number and drop themselves when it is no
        // longer the CURRENT generation: a late error or close frame from a
        // retired connection must not drive a reconnect that a newer
        // connection already owns (task book 12.2).
        const uint64_t gen = generation_.fetch_add(1) + 1;
        {
            std::lock_guard<std::mutex> lk(session_mutex_);
            session_ = session;
        }

        auto self = shared_from_this();

        // True when this callback's connection is still the active one.
        auto is_current = [self, gen]() {
            return !self->stopped_.load() && self->generation_.load() == gen;
        };

        session->on_message([self, is_current](WsMessageType t, const std::vector<uint8_t>& d) {
            if (!is_current()) return;
            MessageCallback cb;
            {
                std::lock_guard<std::mutex> lk(self->mutex_);
                cb = self->message_cb_;
            }
            if (cb) { try { cb(t, d); } catch (...) {} }
        });

        session->on_close([self, is_current](uint16_t code, const string& reason) {
            {
                CloseCallback cb;
                {
                    std::lock_guard<std::mutex> lk(self->mutex_);
                    cb = self->close_cb_;
                }
                if (cb) { try { cb(code, reason); } catch (...) {} }
            }

            // Late close from a retired connection: the caller already saw the
            // terminal for it, and a newer connection owns the session now.
            if (!is_current()) return;
            // A deliberate close from the local side already stopped us; any
            // other close frame means the peer ended the connection. Whether
            // that is retryable is a CLOSE-CODE question, not an Error one.
            if (!ws_reconnect_detail::is_retryable_close_code(code)) {
                self->finish_session(Error{ErrorCode::ConnectionClosed,
                                           ErrorPhase::TargetProtocol,
                                           string("peer closed the connection")});
                return;
            }
            self->handle_disconnect(Error{ErrorCode::ConnectionClosed,
                                          ErrorPhase::TargetProtocol,
                                          string("peer closed the connection")});
        });

        session->on_error([self, is_current](const Error& e) {
            if (!is_current()) return;
            // Per-connection error notification; the session-level decision
            // happens in handle_disconnect below.
            ErrorCallback cb;
            {
                std::lock_guard<std::mutex> lk(self->mutex_);
                cb = self->error_cb_;
            }
            if (cb) { try { cb(e); } catch (...) {} }
            self->handle_disconnect(e);
        });
    }

    inline void ReconnectingWebSocket::handle_disconnect(const Error& err) {
        if (stopped_.load()) return;

        // Retire the physical connection so nothing drains into a dead session.
        {
            std::lock_guard<std::mutex> lk(session_mutex_);
            if (session_) {
                session_->terminate();
                session_.reset();
            }
        }

        // Budget decay: a connection that stayed up long enough decays the
        // failure count; a short-lived one does not, which is what stops a
        // flapping server from retrying forever.
        if (ever_connected_) {
            const Duration lifetime = now() - connected_at_;
            if (ws_reconnect_detail::was_stable(policy_, lifetime)) {
                attempts_.store(ws_reconnect_detail::decay_failures(
                    policy_, attempts_.load()));
            }
        }

        if (!policy_.enabled) {
            finish_session(err);
            return;
        }
        if (!ws_reconnect_detail::should_retry(policy_, err)) {
            finish_session(err);
            return;
        }

        // The FIRST connect failure is a separate policy question (task book
        // 12.2): a caller may want a bad URL or a refused port to fail at once
        // instead of being retried. "First" means no attempt has ever reached
        // the open state and no retry has been counted yet.
        const bool first_connect_failure =
            !ever_connected_ && attempts_.load() == 0;
        if (first_connect_failure && !policy_.retry_initial_connect_failure) {
            finish_session(err);
            return;
        }

        const size_t done = attempts_.load();
        // The total-duration budget is measured from the START of the logical
        // session, not from the last successful connect: connected_at_ is
        // refreshed on every successful handshake, so using it here made
        // max_total_duration restart with each reconnect and a flapping server
        // could retry forever. session_start_ is set once in start().
        const Duration elapsed = now() - session_start_;
        if (reconnect_detail::budget_exhausted(policy_.backoff, done, elapsed)) {
            ReconnectEvents ev;
            {
                std::lock_guard<std::mutex> lk(mutex_);
                ev = events_;
            }
            if (ev.on_gave_up) {
                try { ev.on_gave_up(err, done, true); } catch (...) {}
            }
            finish_session(err);
            return;
        }

        const size_t next_attempt = done + 1;
        const Duration delay = reconnect_detail::backoff_delay(
            policy_.backoff, next_attempt, static_cast<uint32_t>(next_attempt * 7919u));
        attempts_.store(next_attempt);
        reconnecting_.store(true);

        ReconnectEvents ev;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            ev = events_;
        }
        if (ev.on_attempt_failed) {
            try { ev.on_attempt_failed(next_attempt, err); } catch (...) {}
        }
        if (ev.on_scheduled) {
            try { ev.on_scheduled(next_attempt, delay); } catch (...) {}
        }

        auto self = shared_from_this();
        schedule_after(delay, [self]() {
            if (!self->stopped_.load()) self->attempt_connect();
        });
    }

    inline void ReconnectingWebSocket::finish_session(const Error& reason) {
        if (stopped_.exchange(true)) return;
        reconnecting_.store(false);

        {
            std::lock_guard<std::mutex> lk(session_mutex_);
            if (session_) {
                session_->terminate();
                session_.reset();
            }
        }

        SessionEndCallback cb;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            cb = end_cb_;
            end_cb_ = nullptr;
        }
        if (cb) {
            // The pointer is valid only for this call; a caller that keeps it
            // must copy. Null is impossible here (we always carry a reason) but
            // the signature keeps the door open for a clean end.
            try { cb(&reason); } catch (...) {}
        }
    }

    inline void ReconnectingWebSocket::finish_session_clean() {
        if (stopped_.exchange(true)) return;
        reconnecting_.store(false);

        {
            std::lock_guard<std::mutex> lk(session_mutex_);
            if (session_) {
                session_->terminate();
                session_.reset();
            }
        }

        SessionEndCallback cb;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            cb = end_cb_;
            end_cb_ = nullptr;
        }
        if (cb) { try { cb(nullptr); } catch (...) {} }
    }

    inline bool ReconnectingWebSocket::send_text(
        const string& text, std::function<void(const Error&)> on_complete) {
        std::shared_ptr<WebSocketSession> s;
        {
            std::lock_guard<std::mutex> lk(session_mutex_);
            s = session_;
        }
        if (!s || !s->is_open()) {
            // Rejecting while disconnected is the documented default: a
            // queued message would be delivered on a connection the caller
            // never saw, and its delivery state would be unknowable.
            if (on_complete) {
                on_complete(Error{ErrorCode::WsNotOpen, ErrorPhase::TargetProtocol,
                                  string("no open connection")});
            }
            return false;
        }
        s->send_text(text, std::move(on_complete));
        return true;
    }

    inline bool ReconnectingWebSocket::send_binary(
        const std::vector<uint8_t>& data, std::function<void(const Error&)> on_complete) {
        std::shared_ptr<WebSocketSession> s;
        {
            std::lock_guard<std::mutex> lk(session_mutex_);
            s = session_;
        }
        if (!s || !s->is_open()) {
            if (on_complete) {
                on_complete(Error{ErrorCode::WsNotOpen, ErrorPhase::TargetProtocol,
                                  string("no open connection")});
            }
            return false;
        }
        s->send_binary(data, std::move(on_complete));
        return true;
    }

    inline void ReconnectingWebSocket::close(uint16_t code, const string& reason) {
        // Mark stopped FIRST: the close callback must not be mistaken for a
        // peer-initiated drop and trigger a reconnect.
        if (stopped_.exchange(true)) return;
        reconnecting_.store(false);

        std::shared_ptr<WebSocketSession> s;
        {
            std::lock_guard<std::mutex> lk(session_mutex_);
            s = session_;
        }
        if (s) s->close(code, reason);

        finish_session_clean();
    }

    inline void ReconnectingWebSocket::terminate() {
        if (stopped_.exchange(true)) return;
        reconnecting_.store(false);
        {
            std::lock_guard<std::mutex> lk(session_mutex_);
            if (session_) {
                session_->terminate();
                session_.reset();
            }
        }
    }

    inline bool ReconnectingWebSocket::is_open() const noexcept {
        std::lock_guard<std::mutex> lk(session_mutex_);
        return session_ && session_->is_open();
    }

} // namespace megohttp

#endif // MEGOHTTP_WEBSOCKET_RECONNECT_IMPL_HPP_INCLUDED

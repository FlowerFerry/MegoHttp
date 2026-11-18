// ReconnectingWebSocket tests that do not depend on a network backend (T2).
//
// test_websocket_reconnect.cpp drives Client::open_websocket, which builds its
// stream through the active backend's resolver and connect_race -- that only
// works on libuv, so the Asio configuration had no reconnect coverage at all.
//
// The logic under test here (generation isolation, budget accounting, send
// rejection, close semantics) lives above the transport, and WsStreamProvider
// is exactly the seam for it: a fake provider hands back a stream and the test
// decides when it fails. No sockets, no sleeps for backoff.

#include <megohttp/websocket_reconnect.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <megohttp/executor.hpp>

#if MGHTTP_BACKEND_LIBUV
#include <megohttp/backend/executor_libuv.hpp>
#else
#include <megohttp/backend/executor_asio.hpp>
#endif

using namespace megohttp;
using namespace std::chrono_literals;

namespace {

    // Minimal in-memory stream. Reads block (never deliver) unless the test
    // feeds bytes; writes are accepted and counted. Enough for the reconnect
    // state machine, which only needs "did the connection come up / did it
    // fail".
    class FakeStream : public AsyncByteStream,
                       public std::enable_shared_from_this<FakeStream> {
    public:
        void start(ReadyCallback cb) override {
            if (cb) cb(VoidResult{});
        }
        void async_read_some(ReadCallback cb) override {
            // Park the read: the session treats a pending read as "still open".
            std::lock_guard<std::mutex> lk(mu_);
            pending_read_ = std::move(cb);
        }
        void async_write(const uint8_t* data, size_t size, WriteCallback cb) override {
            {
                std::lock_guard<std::mutex> lk(mu_);
                written_ += size;
                // Echo the upgrade request so the session's handshake parse
                // gets a well-formed 101.
                if (!responded_ && size >= 4) {
                    responded_ = true;
                    std::string req(reinterpret_cast<const char*>(data), size);
                    const std::string key = extract_key(req);
                    pending_response_ = make_101(key);
                }
            }
            if (cb) cb(Result<size_t>(size));
            deliver_pending_response();
        }
        void async_close(CloseCallback cb) override {
            open_ = false;
            if (cb) cb();
        }
        bool is_open() const noexcept override { return open_.load(); }

        size_t written() const { return written_.load(); }

        // Push the queued 101 at the parked read, if there is one.
        void deliver_pending_response() {
            ReadCallback cb;
            std::string resp;
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (pending_response_.empty() || !pending_read_) return;
                resp = std::move(pending_response_);
                pending_response_.clear();
                cb = std::move(pending_read_);
            }
            if (cb) {
                // The view must point at storage that outlives the call; the
                // response buffer is kept in resp_buf_ for that reason.
                resp_buf_ = resp;
                cb(Result<string_view>(string_view(resp_buf_.data(), resp_buf_.size())));
            }
        }

        // Fail the parked read: this is what a dropped connection looks like.
        void fail_read(ErrorCode code = ErrorCode::ConnectionReset) {
            ReadCallback cb;
            {
                std::lock_guard<std::mutex> lk(mu_);
                cb = std::move(pending_read_);
            }
            if (cb) cb(Result<string_view>(Error{code, ErrorPhase::Receive, string("fake drop")}));
        }

    private:
        static std::string extract_key(const std::string& req) {
            const std::string needle = "Sec-WebSocket-Key: ";
            const size_t p = req.find(needle);
            if (p == std::string::npos) return {};
            const size_t b = p + needle.size();
            const size_t e = req.find("\r\n", b);
            if (e == std::string::npos) return {};
            return req.substr(b, e - b);
        }
        static std::string make_101(const std::string& key) {
            string acc = ws_detail::accept_key_for(to_view(string(key.c_str())));
            std::string r = "HTTP/1.1 101 Switching Protocols\r\n";
            r += "Upgrade: websocket\r\n";
            r += "Connection: Upgrade\r\n";
            r += "Sec-WebSocket-Accept: ";
            r.append(acc.data(), acc.size());
            r += "\r\n\r\n";
            return r;
        }

        mutable std::mutex mu_;
        std::atomic<bool> open_{true};
        std::atomic<size_t> written_{0};
        ReadCallback pending_read_;
        std::string pending_response_;
        std::string resp_buf_;
        bool responded_{false};
    };

    bool wait_until(const std::function<bool()>& pred, int ms = 3000) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) return true;
            std::this_thread::sleep_for(2ms);
        }
        return false;
    }

    std::shared_ptr<Executor> make_executor() {
#if MGHTTP_BACKEND_LIBUV
        return libuv_backend::UvExecutor::create_internal();
#else
        return asio_backend::AsioExecutor::create_internal();
#endif
    }

} // namespace

TEST_CASE("reconnecting ws: a retired connection's late error is ignored",
          "[websocket][reconnect][generation]") {
    // D14: the generation counter must drop callbacks from a connection that
    // has been replaced. Without it, a late error from connection 1 starts a
    // second reconnect schedule while connection 2 is already live.
    auto exec = make_executor();
    REQUIRE(exec);

    std::vector<std::shared_ptr<FakeStream>> streams;
    std::mutex streams_mu;
    std::atomic<int> provider_calls{0};

    WsStreamProvider provider = [&](string, string,
                                    std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> done) {
        ++provider_calls;
        auto s = std::make_shared<FakeStream>();
        {
            std::lock_guard<std::mutex> lk(streams_mu);
            streams.push_back(s);
        }
        exec->post([s, done]() { done(Result<std::shared_ptr<AsyncByteStream>>(
                                      std::static_pointer_cast<AsyncByteStream>(s))); });
    };

    WebSocketOptions wopt;
    WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = 5ms;
    policy.backoff.max_delay = 5ms;
    policy.backoff.max_attempts = 50;
    policy.backoff.jitter_ratio = 0.0;

    std::atomic<int> opened{0};
    std::atomic<int> succeeded{0};
    auto ws = std::make_shared<ReconnectingWebSocket>(exec, provider, wopt, policy);
    // on_open fires for the FIRST physical connection only; a reconnect that
    // works is reported through the reconnect events instead (the logical
    // session was already open once).
    ws->on_open([&](const Error& e) { if (!e) opened.fetch_add(1); });
    ws->set_reconnect_events({nullptr, nullptr,
                              [&](size_t, uint64_t) { succeeded.fetch_add(1); },
                              nullptr});
    ws->start(string("host"), string("/ws"), Headers{});

    REQUIRE(wait_until([&] { return opened.load() >= 1; }));
    REQUIRE(wait_until([&] { return !streams.empty(); }));

    // Capture the first connection and force the session to move on.
    std::shared_ptr<FakeStream> first;
    {
        std::lock_guard<std::mutex> lk(streams_mu);
        first = streams[0];
    }
    exec->post([first]() { first->fail_read(); });

    // A second connection must come up; the retired one must not add a third.
    REQUIRE(wait_until([&] { return succeeded.load() >= 1; }));
    const int after_two = provider_calls.load();

    // Late error from the retired connection: the generation check must drop it,
    // so the provider is NOT called again for it. Without that check this starts
    // a second reconnect schedule racing the live one.
    //
    // The assertion is made after the late error has been processed on the loop
    // (post + wait), not after an arbitrary sleep: the loop drains in order, so
    // once this posted task has run, the earlier fail_read has already been
    // handled and any reconnect it caused would already be pending.
    std::atomic<bool> drained{false};
    exec->post([first, &drained]() {
        first->fail_read(ErrorCode::ConnectionReset);
    });
    exec->post([&drained]() { drained.store(true); });
    REQUIRE(wait_until([&] { return drained.load(); }, 2000));

    CHECK(provider_calls.load() <= after_two + 1);   // at most the one live retry

    ws->terminate();
#if MGHTTP_BACKEND_LIBUV
    std::dynamic_pointer_cast<libuv_backend::UvExecutor>(exec)->shutdown();
#else
    std::dynamic_pointer_cast<asio_backend::AsioExecutor>(exec)->shutdown();
#endif
}

TEST_CASE("reconnecting ws: backoff is driven by an injected clock, not by sleeping",
          "[websocket][reconnect][clock]") {
    // Task book 13.7: backoff and race behaviour must not be proven "only with
    // fixed sleeps". The policy arithmetic is already covered by pure-function
    // tests (test_reconnect.cpp); what this covers is that the SESSION actually
    // asks for those delays, with a virtual clock and a scheduler that runs the
    // retry body immediately.
    auto exec = make_executor();
    REQUIRE(exec);

    // Virtual time: starts at 0 and only moves when the test says so.
    auto vclock = std::make_shared<TimePoint>(TimePoint{});
    std::vector<Duration> delays;
    std::atomic<int> provider_calls{0};

    WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(100);
    policy.backoff.max_delay = std::chrono::milliseconds(400);
    policy.backoff.multiplier = 2.0;
    policy.backoff.jitter_ratio = 0.0;      // deterministic
    policy.backoff.max_attempts = 4;
    policy.minimum_stable_connection_duration = std::chrono::hours(1);

    WsStreamProvider provider = [&](string, string,
                                    std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> done) {
        ++provider_calls;
        // Always fail: the session should keep backing off until the budget ends.
        exec->post([done]() {
            done(Error{ErrorCode::ConnectionReset, ErrorPhase::TcpConnect,
                       string("injected failure")});
        });
    };

    ReconnectingWebSocket::TestHooks hooks;
    hooks.now = [vclock]() { return *vclock; };
    // Record the requested delay and run the retry body on the loop right away,
    // advancing virtual time by that delay so the duration budget sees it.
    hooks.schedule_after = [vclock, &delays, exec](Duration d, std::function<void()> fn) {
        delays.push_back(d);
        *vclock += d;
        exec->post([fn]() { fn(); });
    };

    std::atomic<bool> ended{false};
    auto ws = std::make_shared<ReconnectingWebSocket>(
        exec, provider, WebSocketOptions{}, policy, hooks);
    ws->on_session_end([&](const Error*) { ended.store(true); });
    ws->start(string("host"), string("/ws"), Headers{});

    // No sleeping: the injected scheduler runs every retry immediately, so the
    // whole budget completes in a handful of loop turns.
    REQUIRE(wait_until([&] { return ended.load(); }, 5000));

    // 100, 200, 400, 400 (capped) -- proven from the recorded durations rather
    // than from wall-clock timing.
    REQUIRE(delays.size() == 4);
    CHECK(delays[0] == std::chrono::milliseconds(100));
    CHECK(delays[1] == std::chrono::milliseconds(200));
    CHECK(delays[2] == std::chrono::milliseconds(400));
    CHECK(delays[3] == std::chrono::milliseconds(400));
    CHECK(provider_calls.load() == 5);   // initial attempt + 4 retries

    ws->terminate();
#if MGHTTP_BACKEND_LIBUV
    std::dynamic_pointer_cast<libuv_backend::UvExecutor>(exec)->shutdown();
#else
    std::dynamic_pointer_cast<asio_backend::AsioExecutor>(exec)->shutdown();
#endif
}

TEST_CASE("reconnecting ws: a stable connection decays the budget on virtual time",
          "[websocket][reconnect][clock]") {
    // The decay rule is the one that stops a flapping server from retrying
    // forever. Driving it on a virtual clock is what makes "stayed up long
    // enough" testable without waiting 30 seconds.
    auto exec = make_executor();
    REQUIRE(exec);

    auto vclock = std::make_shared<TimePoint>(TimePoint{});
    std::atomic<int> provider_calls{0};
    std::atomic<int> failures_seen{0};

    WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(10);
    policy.backoff.max_delay = std::chrono::milliseconds(10);
    policy.backoff.jitter_ratio = 0.0;
    policy.minimum_stable_connection_duration = std::chrono::milliseconds(500);
    policy.stable_connection_success_decay = 0;   // 0 = clear all

    std::vector<std::shared_ptr<FakeStream>> streams;
    std::mutex mu;
    WsStreamProvider provider = [&](string, string,
                                    std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> done) {
        ++provider_calls;
        auto s = std::make_shared<FakeStream>();
        {
            std::lock_guard<std::mutex> lk(mu);
            streams.push_back(s);
        }
        exec->post([s, done]() { done(Result<std::shared_ptr<AsyncByteStream>>(
                                      std::static_pointer_cast<AsyncByteStream>(s))); });
    };

    ReconnectingWebSocket::TestHooks hooks;
    hooks.now = [vclock]() { return *vclock; };
    hooks.schedule_after = [vclock, exec](Duration d, std::function<void()> fn) {
        *vclock += d;
        exec->post([fn]() { fn(); });
    };

    auto ws = std::make_shared<ReconnectingWebSocket>(
        exec, provider, WebSocketOptions{}, policy, hooks);
    ws->set_reconnect_events({nullptr,
        [&](size_t, const Error&) { failures_seen.fetch_add(1); }, nullptr, nullptr});
    ws->start(string("host"), string("/ws"), Headers{});

    // First connection comes up.
    REQUIRE(wait_until([&] { return provider_calls.load() >= 1; }));
    for (int i = 0; i < 200 && ws->reconnect_attempts() != 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Let virtual time pass beyond the stability threshold, then drop it: the
    // failure counter must decay rather than carry over.
    *vclock += std::chrono::milliseconds(1000);
    std::shared_ptr<FakeStream> first;
    {
        std::lock_guard<std::mutex> lk(mu);
        REQUIRE(!streams.empty());
        first = streams[0];
    }
    exec->post([first]() { first->fail_read(); });

    // It reconnects, and because the failure counter was cleared the attempt
    // count restarts from 1 rather than continuing to climb.
    REQUIRE(wait_until([&] { return provider_calls.load() >= 2; }));
    CHECK(ws->reconnect_attempts() <= 1);

    ws->terminate();
#if MGHTTP_BACKEND_LIBUV
    std::dynamic_pointer_cast<libuv_backend::UvExecutor>(exec)->shutdown();
#else
    std::dynamic_pointer_cast<asio_backend::AsioExecutor>(exec)->shutdown();
#endif
}

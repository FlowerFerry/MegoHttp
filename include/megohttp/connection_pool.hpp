#ifndef MEGOHTTP_CONNECTION_POOL_HPP_INCLUDED
#define MEGOHTTP_CONNECTION_POOL_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Connection pool (task book 8.1, phase 5 item S5.1-*).
//
// HTTP/1.1 allows a connection to carry a second exchange only after the first
// completed cleanly: the response body must have been framed to its end and the
// server must not have closed it. So a pooled connection is one reusable
// AsyncByteStream plus the facts needed to decide whether it is still usable.
//
// What this file deliberately does NOT do:
//   - It does not decide when a connection is reusable. That is a framing
//     question (Content-Length satisfied, chunked terminator seen, multipart
//     epilogue consumed) and the answer lives where the response is parsed.
//     The pool only records the verdict.
//   - It does not parse anything, so parser-only tests cannot substitute for
//     tests that drive the real client and count server-side accepts.
//
// Threading: every method must be called on the executor thread. Connections
// are AsyncByteStreams, which are not thread safe, and the pool hands the same
// stream to exactly one exchange at a time.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/transport.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace megohttp {

    // ---------------------------------------------------------------------
    // PoolKey
    //
    // Two connections are interchangeable only when every fact that affects the
    // security boundary matches. Task book 8.1 lists them explicitly, and the
    // reason is asymmetric risk: reusing a tunnel built for one target for a
    // different target would send the second target's bytes over a connection
    // authenticated as the first. The proxy/TLS fields are therefore part of the
    // key from the start, even though the proxy layer lands later -- a key that
    // grows later would silently reuse across identities during the interim.
    // ---------------------------------------------------------------------
    struct PoolKey {
        string scheme;         // "http" or "https" (lowercase)
        string host;           // normalised: lowercase, IDNA A-label
        uint16_t port{0};

        // Proxy identity. Empty when connecting directly.
        string proxy_type;     // "http", "https", "socks5"; empty = direct
        string proxy_host;
        uint16_t proxy_port{0};
        // Credentials are represented by a caller-supplied opaque token, never
        // the password itself: a key gets logged and compared, and task book
        // 8.1 forbids recording or serialising the raw secret.
        string proxy_auth_token;

        // TLS facts. Two TLS sessions with different trust or client-cert
        // settings are not interchangeable even to the same host/port.
        string tls_ca_token;       // opaque token for the CA / trust configuration
        string tls_client_cert_token;
        bool tls_verify_peer{true};

        // The PROXY layer's TLS trust material, separate from the target's
        // (task book 9.3 forbids one object driving both identities). Only
        // meaningful for an HTTPS proxy; empty for every other proxy type and
        // for a direct connection.
        string proxy_tls_token;

        bool operator==(const PoolKey& o) const noexcept {
            return port == o.port && proxy_port == o.proxy_port &&
                   tls_verify_peer == o.tls_verify_peer &&
                   scheme == o.scheme && host == o.host &&
                   proxy_type == o.proxy_type && proxy_host == o.proxy_host &&
                   proxy_auth_token == o.proxy_auth_token &&
                   proxy_tls_token == o.proxy_tls_token &&
                   tls_ca_token == o.tls_ca_token &&
                   tls_client_cert_token == o.tls_client_cert_token;
        }
        bool operator!=(const PoolKey& o) const noexcept { return !(*this == o); }

        // Readable form for diagnostics. Never includes proxy_auth_token.
        string describe() const;
    };

    struct PoolKeyHash {
        std::size_t operator()(const PoolKey& k) const noexcept;
    };

    // ---------------------------------------------------------------------
    // PoolOptions
    // ---------------------------------------------------------------------
    struct PoolOptions {
        // 0 = no limit for that dimension. A zero limit on both is a plain
        // "always open a new connection", which is the pre-phase-5 behaviour.
        size_t max_total_connections{0};
        size_t max_connections_per_origin{0};

        // How long an idle connection may sit in the pool before it is closed
        // proactively. 0 = no idle sweeping (the server may still close it, and
        // a reuse attempt that finds a dead socket must open a new one).
        Duration idle_timeout{std::chrono::seconds(60)};

        // Bounded wait queue. A request that cannot get a connection waits here
        // instead of failing immediately; 0 means "no queueing, fail at once".
        size_t max_waiting{64};

        // There is deliberately no separate acquire timeout: queueing time is
        // covered by the request total_timeout, which is the single logical
        // deadline spanning pool wait, DNS, connect, TLS and receive (S5.8-01).
        // A second knob here would let the two disagree about when the request
        // is over.
    };

    // ---------------------------------------------------------------------
    // PooledConnection
    //
    // One reusable connection. `reusable()` is the framing verdict described at
    // the top of this file; the pool refuses to hand out anything else.
    // ---------------------------------------------------------------------
    struct PooledConnection {
        std::shared_ptr<AsyncByteStream> stream;
        PoolKey key;
        // Set when the connection was created. Used for idle sweeping.
        std::chrono::steady_clock::time_point idle_since;
        // Bumped every time the connection is handed out, so a late close from a
        // previous lessee cannot retire a connection a newer lessee now owns.
        uint64_t generation{0};

        bool usable() const noexcept { return stream && stream->is_open(); }
    };

    // ---------------------------------------------------------------------
    // ConnectionPool
    //
    // Not thread safe: the caller (Client) drives it from the executor thread.
    // The mutex protects only the counters that shutdown() may inspect from
    // another thread; the container itself is single-threaded.
    // ---------------------------------------------------------------------
    class ConnectionPool : public std::enable_shared_from_this<ConnectionPool> {
    public:
        // Called with a connection when one becomes available. The pool has
        // already removed it from the idle list, so a caller that fails to use
        // it must give it back (put()) or close it.
        using AcquireCallback = std::function<void(Result<PooledConnection>)>;

        ConnectionPool(std::shared_ptr<Executor> executor, PoolOptions options);

        // Attempt to take a reusable connection for `key`.
        //
        // Three outcomes, in order:
        //   1. An idle connection exists            -> callback now, synchronously.
        //   2. Capacity remains                     -> callback with
        //      ErrorCode::NotFound meaning "open a new one"; the pool has already
        //      reserved the slot so a concurrent acquire cannot overshoot.
        //   3. Neither                              -> the request is queued and
        //      the callback fires when a connection is returned or capacity frees.
        //
        // The callback always runs on the executor thread.
        void acquire(const PoolKey& key, AcquireCallback on_result);

        // Return a connection for reuse. `finished_cleanly == false` closes it
        // instead of pooling it -- that is the S2.1-03 rule (a connection whose
        // framing did not complete must never go back into the pool).
        void put(PooledConnection conn, bool finished_cleanly);

        // Close every idle connection. In-flight connections are untouched: they
        // are owned by their exchange and will be closed when it finishes.
        void clear_idle();

        // Close idle connections older than idle_timeout. Returns how many were
        // closed, so a test can assert the sweep happened instead of inferring.
        size_t sweep_idle(std::chrono::steady_clock::time_point now);

        // Idle connections currently held.
        size_t idle_count() const noexcept;
        // Connections in use (reserved or handed out and not yet returned).
        size_t busy_count() const noexcept;
        // Requests waiting for a connection.
        size_t waiting_count() const noexcept;

        const PoolOptions& options() const noexcept { return options_; }

        // Drop every waiter with `code`. Used by Client::shutdown().
        void fail_waiters(ErrorCode code, const char* message);

    private:
        struct Waiter {
            PoolKey key;
            AcquireCallback callback;
        };

        // Frees a reserved slot and, if anyone is waiting, hands the slot over.
        void release_slot(const PoolKey& key);
        // Reserve a slot for `key`; false when a limit would be exceeded.
        bool try_reserve(const PoolKey& key);
        // Give the next compatible waiter a chance to proceed.
        void serve_waiters();

        std::shared_ptr<Executor> executor_;
        PoolOptions options_;

        std::unordered_map<PoolKey, std::deque<PooledConnection>, PoolKeyHash> idle_;
        std::unordered_map<PoolKey, size_t, PoolKeyHash> busy_per_key_;
        size_t busy_total_{0};
        std::deque<Waiter> waiters_;

        // Guards the counters above against shutdown() running on another
        // thread. The containers are still only touched on the executor thread;
        // this keeps a cross-thread read from tearing a 64-bit counter.
        mutable std::mutex stats_mutex_;
    };

} // namespace megohttp

#include <megohttp/connection_pool_impl.hpp>

#endif // MEGOHTTP_CONNECTION_POOL_HPP_INCLUDED

#ifndef MEGOHTTP_RESOLVER_DOT_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_DOT_HPP_INCLUDED

// DNS over TLS resolver (task book section 9-A.2, phase 5A).
//
// RFC 7858: a TCP stream wrapped in TLS, where each DNS query/response is
// length-prefixed (2 bytes big-endian). Multiple queries can share one TCP
// connection (pipelined), each identified by its DNS message ID.
//
// This file holds the resolver layer: it owns the TCP+TLS connection, the
// message-ID bookkeeping and the cancellation / late-response logic. The DNS
// wire codec (build_query / parse_message) lives in dns_wire.hpp.

#include <megohttp/config.hpp>

#if MEGOHTTP_HAS_DOT

#include <megohttp/dns_cache.hpp>
#include <megohttp/dns_wire.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/resolver.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/tls_stream.hpp>
#include <megohttp/transport.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace megohttp {

    // Fully-qualified alias: inside a nested class MSVC resolves a bare `dns::`
    // against the class scope first, so naming the namespace once here keeps
    // every later use unambiguous.
    namespace dnswire = ::megohttp::dns;

    // Configuration for one DoT endpoint. `server_name` is used for SNI and
    // certificate validation; `bootstrap_ip` is an optional numeric IP to dial
    // instead of resolving `server_name`. If neither is an IP literal, the
    // caller must provide a bootstrap address or the resolver will fail.
    struct DotOptions {
        string server_name;                 // SNI + cert identity (e.g. "dns.quad9.net")
        string bootstrap_ip;                // optional numeric IP to connect to
        uint16_t port{853};                 // RFC 7858 default
        Duration connect_timeout{std::chrono::seconds(10)};
        TlsConfig tls;                      // CA, client cert, verify settings

        // Whether this endpoint accepts NXDOMAIN and NODATA as valid answers
        // (RFC 7858 §4.1). A strict-mode endpoint that refuses to cache NXDOMAIN
        // would set this false, but the default follows the RFC.
        bool accept_no_data{true};

        // TTL-driven answer cache (task book 9-A.6). Positive entries expire on
        // the record TTL, negative entries on the SOA MINIMUM (RFC 2308).
        DnsCacheOptions cache{};
    };

    // DNS over TLS resolver. One resolver owns one long-lived TLS connection to
    // a single DNS server. If the connection drops, the resolver reports
    // DnsResolveFailed and the caller must create a new instance -- DoT is
    // deliberately NOT reconnecting itself (that is the job of the higher-level
    // CachingResolver).
    //
    // Message IDs are allocated per-lookup and de-allocated when the answer
    // arrives. If the connection is lost, all pending lookups receive an error.
    // A late response that arrives after a timeout or cancel is silently dropped.
    class DotResolver final : public Resolver,
                              public std::enable_shared_from_this<DotResolver> {
    public:
        DotResolver(std::shared_ptr<Executor> executor, DotOptions options);
        ~DotResolver() override;

        DotResolver(const DotResolver&) = delete;
        DotResolver& operator=(const DotResolver&) = delete;

        CancelHandle resolve(string host, uint16_t port, Callback cb) override;
        const char* name() const noexcept override { return "dot"; }

    private:
        class Connection;   // forward declaration

        // One outstanding query.
        struct Query {
            uint16_t id;
            string host;
            uint16_t qport;
            // A typed enum, spelled fully so no namespace alias or lookup rule
            // can silently change which enum this is.
            ::megohttp::dns::RecordType qtype;
            Callback cb;
            std::shared_ptr<CancelState> cancel;
            std::shared_ptr<Query> self;  // kept alive while upstream is running
            // Set once the framed query has been handed to the stream. Without
            // this, a second lookup on an already-open connection would re-send
            // every pending query, including ones already in flight.
            bool written{false};
        };

        std::shared_ptr<Executor> executor_;
        DotOptions options_;

        // All members below are accessed ONLY on the executor thread (except for
        // cancel checks in resolve()). That is why there is no mutex: the loop
        // serializes every mutation.
        std::shared_ptr<Connection> conn_;

        // The next DNS message ID to allocate. 0 is reserved (the protocol uses
        // it only in queries the client didn't write), so start at 1.
        uint16_t next_id_{1};

        // True while a read is outstanding on the connection. Only one read may
        // be in flight: the stream hands out one buffer at a time.
        bool read_in_flight_{false};

        // Same for writes: AsyncByteStream allows one outstanding write, so a
        // burst of lookups is serialised through this queue.
        bool write_in_flight_{false};
        std::vector<std::shared_ptr<Query>> write_queue_;

        // TTL-driven answer cache (task book 9-A.6). Positive entries expire on
        // the record TTL, negative entries on the SOA MINIMUM (RFC 2308).
        mutable DnsCache cache_;

        // Queries waiting for an answer.
        std::unordered_map<uint16_t, std::shared_ptr<Query>> pending_;

        // Maximum concurrent queries on one connection. RFC 7858 doesn't specify
        // a limit, but a server can cap it. 64 is generous enough for normal use.
        static constexpr size_t kMaxInFlight = 64;

        // How many bytes we buffer before handing a complete message to the parser.
        static constexpr size_t kReadBufSize = 4096;

        void ensure_connection();
        void on_connection_ready();
        void on_connection_failed(const Error&);
        void submit_queries();
        void pump_writes();
        void read_response();
        void on_read_complete(Result<string_view>);
        void dispatch_answer(uint16_t id, const byte_buffer& payload);
    };

    // The underlying TCP+TLS stream for a DoT connection. Held by shared_ptr so
    // it can outlive the resolver if the resolver is destroyed while the stream
    // has pending callbacks.
    class DotResolver::Connection : public std::enable_shared_from_this<DotResolver::Connection> {
    public:
        Connection(std::shared_ptr<Executor> executor, DotOptions options)
            : executor_(std::move(executor)), options_(std::move(options)) {}

        // Begin connecting: TCP -> TLS -> read loop.
        // on_ready fires exactly once with success or failure.
        void connect(std::function<void(const Error*)> on_ready);

        // Write a DNS message (already length-prefixed by the caller).
        // The buffer must stay valid until the callback fires.
        void write(byte_buffer data, std::function<void(const Error*)> on_done);

        // Read one DNS message from the TLS stream. The payload is returned
        // without the 2-byte length prefix.
        void read(std::function<void(Result<byte_buffer>)> on_msg);

        // Close the connection. After this, no more callbacks will fire.
        void close();

        bool is_open() const noexcept { return state_ == State::Open; }

    private:
        enum class State { Connecting, Open, Closed, Failed };
        State state_{State::Connecting};
        std::shared_ptr<Executor> executor_;
        DotOptions options_;
        std::shared_ptr<TcpStream> tcp_;
        std::shared_ptr<TlsStream> tls_;

        std::function<void(const Error*)> connect_cb_;
        std::function<void(Result<byte_buffer>)> read_cb_;

        byte_buffer read_buf_;
        uint16_t expected_len_{0};
        bool reading_header_{true};
    };

} // namespace megohttp

#include <megohttp/resolver_dot_impl.hpp>

#endif // MEGOHTTP_HAS_DOT
#endif // MEGOHTTP_RESOLVER_DOT_HPP_INCLUDED

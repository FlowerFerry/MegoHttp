#ifndef MEGOHTTP_RESOLVER_DOH_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_DOH_HPP_INCLUDED

// DNS over HTTPS resolver (task book section 9-A.3, phase 5A).
//
// RFC 8484: DNS queries sent over HTTPS. Two methods:
//   - POST: Content-Type: application/dns-message, body is raw DNS wire
//   - GET: ?dns=<base64url(query)> without padding
//
// Default is POST. GET is smaller but may hit URL length limits.
//
// HTTP/1.1 only: this implementation records that limitation and does not
// attempt HTTP/2 or HTTP/3.
//
// DoH internal requests are isolated:
//   - No Cookie/Authorization from business requests
//   - No following redirects (or explicit safe limits)
//   - Independent resource budget (timeout, body size)
//
// This file holds the resolver layer. The DNS wire codec lives in dns_wire.hpp.

#include <megohttp/config.hpp>

#if MEGOHTTP_HAS_DOH

#include <megohttp/dns_cache.hpp>
#include <megohttp/dns_wire.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/resolver.hpp>
#include <megohttp/response.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/tls_stream.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace megohttp {

    // Alias for the dns namespace (same pattern as DotResolver)
    namespace dnswire = ::megohttp::dns;

    // DoH method preference
    enum class DohMethod {
        Post,   // default; RFC 8484 recommended
        Get,    // for small queries; URL length limits apply
    };

    // Configuration for one DoH endpoint.
    //
    // `endpoint_url` is the full HTTPS URL (e.g., "https://dns.google/dns-query").
    // The path is preserved; query parameters from the URL are kept.
    //
    // `bootstrap_ip` is optional numeric IP to dial instead of resolving
    // the host from `endpoint_url`. Used for strict bootstrap mode.
    struct DohOptions {
        string endpoint_url;                // Full HTTPS URL (path preserved)
        string bootstrap_ip;                // Optional numeric IP to connect to
        DohMethod method{DohMethod::Post};  // POST or GET
        Duration connect_timeout{std::chrono::seconds(10)};
        Duration request_timeout{std::chrono::seconds(30)};
        Duration total_timeout{std::chrono::seconds(60)};

        // TLS config for the HTTPS connection
        // If empty, uses system default trust
        std::optional<TlsConfig> tls;

        // Maximum DNS response size (wire bytes before decompression)
        size_t max_response_bytes{65535};

        // Whether to follow redirects (default: false for isolation)
        bool follow_redirects{false};

        // Maximum redirects to follow (only if follow_redirects is true)
        size_t max_redirects{3};

        // Bootstrap mode (task book 9-A.4). When false (default, strict mode),
        // a named endpoint with no bootstrap_ip is a ConfigurationError.
        // When true, the endpoint hostname is resolved via system DNS.
        bool use_system_bootstrap{false};

        // TTL-driven answer cache (task book 9-A.6). Positive entries expire on
        // the record TTL, negative entries on the SOA MINIMUM (RFC 2308).
        //
        // DoH additionally must respect the HTTP cache age on top of the DNS
        // TTL: a response served from an intermediary cache has already spent
        // part of its lifetime, so the effective TTL is `min(dns_ttl,
        // remaining_age)`.
        DnsCacheOptions cache{};
    };

    // DNS over HTTPS resolver.
    //
    // Each DoH request is an independent HTTP/1.1 request. HTTP keep-alive
    // is used when possible via the underlying connection pool.
    //
    // DoH queries do not share message IDs like DoT; each HTTP request/response
    // pair is self-contained. The resolver serializes the query into the HTTP
    // body (POST) or URL parameter (GET), and deserializes the response.
    class DohResolver final : public Resolver,
                              public std::enable_shared_from_this<DohResolver> {
    public:
        DohResolver(std::shared_ptr<Executor> executor, DohOptions options);
        ~DohResolver() override;

        DohResolver(const DohResolver&) = delete;
        DohResolver& operator=(const DohResolver&) = delete;

        CancelHandle resolve(string host, uint16_t port, Callback cb) override;
        const char* name() const noexcept override { return "doh"; }

    private:
        // Internal HTTP client for DoH (isolated from business Client)
        class HttpClient;

        struct Query {
            uint16_t id;
            string host;
            uint16_t qport;
            ::megohttp::dns::RecordType qtype;
            Callback cb;
            std::shared_ptr<CancelState> cancel;
            bool responded{false};
        };

        // Build the HTTP request for a query
        Result<std::pair<string, byte_buffer>> build_request(const Query& q);

        // Parse HTTP response body into DNS answer
        Result<AddressList> parse_response(const byte_buffer& body,
                                           const Query& q);

        // Extract minimum TTL from response (for caching)
        std::optional<Duration> extract_ttl(const byte_buffer& body);

        // URL helpers
        Result<string> encode_get_url(const string& base_url,
                                      const byte_buffer& dns_payload);

        // Completion handler for HTTP request
        void on_http_complete(std::shared_ptr<Query> q,
                              Result<Response> r);

        // Fail all pending queries
        void fail_all_pending(const Error& e);

        std::shared_ptr<Executor> executor_;
        DohOptions options_;

        // Pending queries (by DNS message ID for matching)
        std::mutex pending_mutex_;
        std::unordered_map<uint16_t, std::shared_ptr<Query>> pending_;

        // Next DNS message ID
        uint16_t next_id_{1};

        // TTL-driven answer cache (task book 9-A.6).
        mutable DnsCache cache_;

        // HTTP client (owned, isolated)
        std::unique_ptr<HttpClient> http_client_;

        // Connection generation for isolation
        uint64_t generation_{0};
    };

} // namespace megohttp

#include <megohttp/resolver_doh_impl.hpp>

#endif // MEGOHTTP_HAS_DOH

#endif // MEGOHTTP_RESOLVER_DOH_HPP_INCLUDED

#ifndef MEGOHTTP_RESOLVER_DOH_IMPL_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_DOH_IMPL_HPP_INCLUDED

#include <megohttp/resolver_doh.hpp>

#if MEGOHTTP_HAS_DOH

#include <megohttp/client.hpp>
#include <megohttp/dns_wire_impl.hpp>
#include <megohttp/url.hpp>

#include <cctype>

namespace megohttp {

    // Base64url encoding (RFC 4648 §5) without padding
    inline std::string base64url_encode(const uint8_t* data, size_t len) {
        static const char table[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        out.reserve((len * 4 + 2) / 3);
        size_t i = 0;
        while (i + 3 <= len) {
            uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
            out.push_back(table[(v >> 18) & 0x3f]);
            out.push_back(table[(v >> 12) & 0x3f]);
            out.push_back(table[(v >> 6) & 0x3f]);
            out.push_back(table[v & 0x3f]);
            i += 3;
        }
        if (i + 2 == len) {
            uint32_t v = (uint32_t(data[i]) << 8) | data[i + 1];
            out.push_back(table[(v >> 10) & 0x3f]);
            out.push_back(table[(v >> 4) & 0x3f]);
            out.push_back(table[(v << 2) & 0x3f]);
        } else if (i + 1 == len) {
            uint32_t v = data[i];
            out.push_back(table[(v >> 2) & 0x3f]);
            out.push_back(table[(v << 4) & 0x3f]);
        }
        return out;
    }

    // Internal HTTP client for DoH.
    // Uses the public Client class but with isolated options.
    class DohResolver::HttpClient {
    public:
        HttpClient(std::shared_ptr<Executor> executor, const DohOptions& opts)
            : executor_(executor), options_(opts) {
            init_client();
        }

        ~HttpClient() {
            if (client_) {
                client_->shutdown();
            }
        }

        void request(const string& method,
                     const string& url,
                     const Headers& headers,
                     const std::optional<byte_buffer>& body,
                     std::function<void(Result<Response>)> cb) {
            if (!client_) {
                cb(Error{ErrorCode::ConfigurationError, ErrorPhase::None,
                       string("DoH HTTP client not initialized")});
                return;
            }

            Request req;
            if (method == "POST") {
                req.set_method(Method::Post);
            } else if (method == "GET") {
                req.set_method(Method::Get);
            } else {
                cb(Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                       string("unsupported HTTP method for DoH")});
                return;
            }

            req.set_url(string_view(url.c_str(), url.size()));

            // Copy headers
            for (const auto& kv : headers) {
                req.headers().add(string_view(kv.first.c_str(), kv.first.size()),
                                  string_view(kv.second.c_str(), kv.second.size()));
            }

            // Set body for POST
            if (body.has_value() && method == "POST") {
                req.set_body(string_view(
                    reinterpret_cast<const char*>(body->data()),
                    body->size()));
            }

            // Execute request. The client was built with the isolated options
            // (no cookie jar, no redirect following, its own TLS config).
            client_->request(req, std::move(cb));
        }

    private:
        void init_client() {
            ClientOptions copts;
            copts.connect_timeout = options_.connect_timeout;
            copts.total_timeout = options_.total_timeout;

            if (options_.tls.has_value()) {
                copts.tls = options_.tls.value();
            }

            // Isolation, RFC 8484: DoH never follows redirects by default, and
            // it must never carry business cookies or Authorization headers.
            // A null cookie_jar (the default) already guarantees the cookie half.
            copts.redirects.follow = options_.follow_redirects;
            copts.redirects.max_redirects = options_.max_redirects;
            copts.redirects.allow_https_to_http = false;

            // Bound the response so a hostile endpoint cannot stream forever.
            copts.max_response_body = options_.max_response_bytes;

            // S5A.4-03: resource isolation is structural rather than a pool cap
            // here: the DoH internal Client is a separate object with its own
            // executor, its own TLS config and no cookie jar, so it neither
            // shares nor waits on the business pool. Deliberately left
            // unpooled (one connection per DoH request, closed afterwards),
            // because a pooled keep-alive connection to a DoH endpoint is an
            // extra failure mode (stale/reused connection -> non-200) that buys
            // nothing for short DNS exchanges.

            client_ = std::make_unique<Client>(copts);
        }

        std::shared_ptr<Executor> executor_;
        DohOptions options_;
        std::unique_ptr<Client> client_;
    };

    inline DohResolver::DohResolver(std::shared_ptr<Executor> executor,
                                     DohOptions options)
        : executor_(executor), options_(options), cache_(options.cache) {
        http_client_ = std::make_unique<HttpClient>(executor, options);
    }

    inline DohResolver::~DohResolver() {
        // Cancel all pending
        fail_all_pending(Error{ErrorCode::Cancelled, ErrorPhase::Resolve,
                               string("DoH resolver destroyed")});
    }

    inline CancelHandle DohResolver::resolve(string host, uint16_t port,
                                              Callback cb) {
        auto cancel = std::make_shared<CancelState>();

        // An IP literal needs no DNS at all.
        if (auto lits = parse_ip_literal(to_view(host), port); !lits.empty()) {
            executor_->post([cb, lits, cancel]() {
                if (cancel && cancel->is_cancelled()) return;
                if (cb) cb(AddressList(lits));
            });
            return CancelHandle{cancel};
        }

        // Check the TTL-driven cache first (task book 9-A.6).
        if (auto cached = cache_.get(
                host, port, static_cast<uint16_t>(dnswire::RecordType::A))) {
            executor_->post([cb, answers = std::move(*cached), cancel]() {
                if (cancel && cancel->is_cancelled()) return;
                if (cb) cb(answers);
            });
            return CancelHandle{cancel};
        }

        // Allocate query ID
        uint16_t qid = 0;
        {
            std::lock_guard<std::mutex> lk(pending_mutex_);
            const uint16_t start = next_id_;
            do {
                qid = next_id_++;
                if (next_id_ == 0) next_id_ = 1;
            } while (pending_.find(qid) != pending_.end() && next_id_ != start);

            if (pending_.find(qid) != pending_.end()) {
                // All IDs in use
                cb(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                       string("DoH query ID space exhausted")});
                return CancelHandle{cancel};
            }
        }

        auto q = std::make_shared<Query>();
        q->id = qid;
        q->host = host;
        q->qport = port;
        // Resolver interface carries no query type, so an A lookup is issued.
        // AAAA can be reached by constructing the resolver with a different
        // policy once the interface grows a record-type parameter.
        q->qtype = dnswire::RecordType::A;
        q->cb = cb;
        q->cancel = cancel;

        // Build DNS query payload
        auto msg = dnswire::build_query(qid, string_view(host.c_str(), host.size()),
                                         q->qtype);
        if (!msg) {
            cb(Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                   msg.error().message()});
            return CancelHandle{cancel};
        }

        // Store pending
        {
            std::lock_guard<std::mutex> lk(pending_mutex_);
            pending_[qid] = q;
        }

        // Build and send HTTP request
        auto req_result = build_request(*q);
        if (!req_result) {
            std::lock_guard<std::mutex> lk(pending_mutex_);
            pending_.erase(qid);
            cb(req_result.error());
            return CancelHandle{cancel};
        }

        const string& method = req_result.value().first;
        const byte_buffer& body = req_result.value().second;

        Headers headers;
        headers.add("Accept", "application/dns-message");
        if (method == "POST") {
            headers.add("Content-Type", "application/dns-message");
        }

        // The GET form carries the query in the URL, so no body is sent.
        string url = options_.endpoint_url;
        std::optional<byte_buffer> out_body;
        if (method == "POST") {
            out_body = body;
        } else {
            auto enc = encode_get_url(options_.endpoint_url, body);
            if (!enc) {
                std::lock_guard<std::mutex> lk(pending_mutex_);
                pending_.erase(qid);
                cb(enc.error());
                return CancelHandle{cancel};
            }
            url = enc.value();
        }

        // Capture self weakly for callback safety
        std::weak_ptr<DohResolver> wself = shared_from_this();
        http_client_->request(
            method, url, headers, out_body,
            [wself, q](Result<Response> r) {
                auto self = wself.lock();
                if (!self) return;
                self->on_http_complete(q, r);
            });

        return CancelHandle{cancel};
    }

    inline Result<std::pair<string, byte_buffer>>
    DohResolver::build_request(const Query& q) {
        // Build the DNS wire payload once. For POST it becomes the request body;
        // for GET it is base64url-encoded into the `dns` query parameter.
        auto msg = dnswire::build_query(
            q.id, string_view(q.host.c_str(), q.host.size()), q.qtype);
        if (!msg) {
            return msg.error();
        }

        const string method = (options_.method == DohMethod::Post) ? "POST" : "GET";
        return std::make_pair(method, std::move(msg.value()));
    }

    inline Result<string> DohResolver::encode_get_url(
        const string& base_url,
        const byte_buffer& dns_payload) {
        // RFC 8484: the `dns` parameter is base64url-encoded WITHOUT padding.
        const std::string encoded = base64url_encode(
            dns_payload.data(), dns_payload.size());

        // The parameter is appended, so an endpoint URL that already carries
        // query parameters keeps them (it must not be replaced wholesale).
        string_builder b;
        const string_view base = to_view(base_url);
        detail::sb_append(b, base);
        const bool has_query =
            base.find('?') != string_view::npos;
        detail::sb_append(b, has_query ? "&dns=" : "?dns=");
        detail::sb_append(b, string_view(encoded.c_str(), encoded.size()));
        return b.release();
    }

    inline void DohResolver::on_http_complete(std::shared_ptr<Query> q,
                                                 Result<Response> r) {
        // Check cancel
        if (q->cancel->is_cancelled()) {
            std::lock_guard<std::mutex> lk(pending_mutex_);
            pending_.erase(q->id);
            return;
        }

        if (!r) {
            std::lock_guard<std::mutex> lk(pending_mutex_);
            pending_.erase(q->id);
            if (q->cb) q->cb(r.error());
            return;
        }

        const auto& resp = r.value();
        int status = resp.head().status_code;

        // Check HTTP status
        if (status != 200) {
            std::lock_guard<std::mutex> lk(pending_mutex_);
            pending_.erase(q->id);
            if (q->cb) {
                q->cb(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                            string("DoH endpoint returned a non-200 status")});
            }
            return;
        }

        // Check Content-Type
        auto ct = resp.head().headers.get("content-type");
        if (!ct || ct.value() != "application/dns-message") {
            std::lock_guard<std::mutex> lk(pending_mutex_);
            pending_.erase(q->id);
            if (q->cb) {
                q->cb(Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                            string("DoH invalid Content-Type")});
            }
            return;
        }

        // Parse response body as DNS message
        const auto& body = resp.body_bytes();
        byte_buffer body_buf(body.begin(), body.end());

        auto result = parse_response(body_buf, *q);

        // Cache the answer before delivering it (task book 9-A.6). Only a
        // definitive DNS answer is cached -- parse_response already filters out
        // SERVFAIL/REFUSED and reports them as errors, so `result` being a value
        // means the answer is cacheable.
        if (result) {
            const uint16_t qtype = static_cast<uint16_t>(q->qtype);
            auto parsed = dnswire::parse_message(body_buf);
            if (parsed && !result.value().empty()) {
                if (auto ttl = dnswire::min_ttl(parsed.value().answers)) {
                    uint32_t effective = *ttl;
                    // RFC 8484: an HTTP intermediary may have already aged the
                    // response. Age is a lower bound on how much of the DNS TTL
                    // has been consumed; honour it so the cache never outlives
                    // the record.
                    auto age_header = resp.head().headers.get("age");
                    if (age_header) {
                        uint64_t age = 0;
                        const auto& av = age_header.value();
                        bool digits = !av.empty();
                        for (size_t i = 0; i < av.size(); ++i) {
                            const char c = av[i];
                            if (c < '0' || c > '9') { digits = false; break; }
                            if (age > (UINT64_MAX - 9) / 10) { digits = false; break; }
                            age = age * 10 + static_cast<uint64_t>(c - '0');
                        }
                        if (digits) {
                            if (age >= effective) {
                                effective = 0;   // fully aged: do not cache
                            } else {
                                effective -= static_cast<uint32_t>(age);
                            }
                        }
                    }
                    if (effective > 0) {
                        cache_.put_positive(q->host, q->qport, qtype,
                                            result.value(), effective);
                    }
                }
            } else if (parsed && result.value().empty()) {
                // NODATA: a definitive "no records of this type" answer.
                if (auto neg = dnswire::negative_cache_ttl(parsed.value())) {
                    cache_.put_negative(q->host, q->qport, qtype, *neg);
                }
            }
        }

        std::lock_guard<std::mutex> lk(pending_mutex_);
        pending_.erase(q->id);

        if (q->cb) {
            if (result) {
                q->cb(result.value());
            } else {
                q->cb(result.error());
            }
        }
    }

    inline Result<AddressList>
    DohResolver::parse_response(const byte_buffer& body, const Query& q) {
        using namespace ::megohttp::dns;

        // Check size limit
        if (body.size() > options_.max_response_bytes) {
            return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                         string("DoH response exceeds max size")};
        }

        // Parse DNS message
        auto parsed = parse_message(body);
        if (!parsed) {
            return parsed.error();
        }

        const auto& msg = parsed.value();

        // An HTTP 200 does not make the DNS answer valid, so the RCODE is
        // inspected before anything is extracted (RFC 8484 section 4.2).
        switch (msg.rcode) {
            case ResponseCode::NoError:
                break;
            case ResponseCode::NxDomain:
                return AddressList{};
            case ResponseCode::ServFail:
                return Error{ErrorCode::DnsServerFailure, ErrorPhase::Resolve,
                             string("DoH SERVFAIL")};
            case ResponseCode::Refused:
                return Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                             string("DoH REFUSED")};
            default:
                return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                             string("DoH rejected response code")};
        }

        // Extract addresses, following a bounded CNAME chain
        auto answers = extract_addresses(msg, q.qtype);
        if (!answers) {
            return answers.error();
        }

        const size_t want =
            (q.qtype == ::megohttp::dns::RecordType::A) ? 4u : 16u;
        AddressList out;
        for (const auto& raw : answers.value().addresses) {
            if (raw.size() != want) continue;
            ResolvedAddress a;
            a.family = (want == 4) ? ResolvedAddress::Family::IPv4
                                   : ResolvedAddress::Family::IPv6;
            a.port = q.qport;
            a.bytes = raw;
            char buf[64] = {0};
            if (inet_ntop(want == 4 ? AF_INET : AF_INET6, raw.data(), buf, sizeof buf)) {
                a.text = to_string(buf);
            }
            out.push_back(std::move(a));
        }

        // NOERROR with no address records is NODATA: a valid answer meaning
        // "this name has no records of that type" (9-A.5), not a failure.
        return out;
    }

    inline std::optional<Duration>
    DohResolver::extract_ttl(const byte_buffer& body) {
        auto parsed = dnswire::parse_message(body);
        if (!parsed) return std::nullopt;
        auto ttl = dnswire::min_ttl(parsed.value().answers);
        if (!ttl.has_value()) return std::nullopt;
        return std::chrono::seconds(ttl.value());
    }

    inline void DohResolver::fail_all_pending(const Error& e) {
        std::lock_guard<std::mutex> lk(pending_mutex_);
        for (auto& [id, q] : pending_) {
            if (q && q->cb) {
                q->cb(e);
            }
        }
        pending_.clear();
    }

} // namespace megohttp

#endif // MEGOHTTP_HAS_DOH

#endif // MEGOHTTP_RESOLVER_DOH_IMPL_HPP_INCLUDED

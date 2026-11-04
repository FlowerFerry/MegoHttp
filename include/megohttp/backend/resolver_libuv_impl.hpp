#ifndef MEGOHTTP_RESOLVER_LIBUV_IMPL_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_LIBUV_IMPL_HPP_INCLUDED

// Included at the end of backend/resolver_libuv.hpp.

#include <atomic>
#include <cstring>
#include <memory>

#if defined(_WIN32)
#   include <ws2tcpip.h>
#else
#   include <arpa/inet.h>
#endif

namespace MegoHttp {
namespace Detail {

    inline string format_ip(const sockaddr* sa) {
        char buf[INET6_ADDRSTRLEN] = {0};
        if (sa->sa_family == AF_INET) {
            const auto* v4 = reinterpret_cast<const sockaddr_in*>(sa);
            if (inet_ntop(AF_INET, &v4->sin_addr, buf, sizeof buf) == nullptr) return string();
        } else if (sa->sa_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(sa);
            if (inet_ntop(AF_INET6, &v6->sin6_addr, buf, sizeof buf) == nullptr) return string();
        } else {
            return string();
        }
        return string(buf, static_cast<string::size_type>(std::strlen(buf)));
    }

    inline uint16_t address_port(const sockaddr* sa) noexcept {
        if (sa->sa_family == AF_INET) {
            return ntohs(reinterpret_cast<const sockaddr_in*>(sa)->sin_port);
        }
        if (sa->sa_family == AF_INET6) {
            return ntohs(reinterpret_cast<const sockaddr_in6*>(sa)->sin6_port);
        }
        return 0;
    }

    inline std::vector<uint8_t> address_bytes(const sockaddr* sa) {
        std::vector<uint8_t> out;
        if (sa->sa_family == AF_INET) {
            const auto* v4 = reinterpret_cast<const sockaddr_in*>(sa);
            const auto* p = reinterpret_cast<const uint8_t*>(&v4->sin_addr);
            out.assign(p, p + 4);
        } else if (sa->sa_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(sa);
            const auto* p = reinterpret_cast<const uint8_t*>(&v6->sin6_addr);
            out.assign(p, p + 16);
        }
        return out;
    }

    // One in-flight lookup.
    //
    // Self-owning, same shape as the libuv timer Node: `self` keeps the request
    // alive until the callback runs, and the callback clears it. That is what makes
    // a cancelled request safe -- libuv still invokes the callback for a request it
    // could not abort, and by then the caller may be long gone (spec 5.4.2: a late
    // system result must be discarded, never delivered).
    struct AddrInfoRequest {
        uv_getaddrinfo_t req{};
        Resolver::Callback cb;
        uint16_t port{0};
        // std::string on purpose: the C API needs a stable NUL-terminated buffer,
        // and this never crosses a public API boundary.
        std::string host;
        std::string service;
        std::atomic<bool> cancelled{false};
        std::shared_ptr<AddrInfoRequest> self;
    };

    inline void addrinfo_cb(uv_getaddrinfo_t* r, int status, addrinfo* res) {
        auto* raw = static_cast<AddrInfoRequest*>(r->data);
        if (raw == nullptr) return;

        // Keep the request alive across this call, then break the self-hold.
        std::shared_ptr<AddrInfoRequest> self = raw->self;
        raw->self.reset();
        r->data = nullptr;

        // libuv handed us ownership of the list; release it on every path.
        struct FreeGuard {
            addrinfo* p;
            ~FreeGuard() { if (p != nullptr) uv_freeaddrinfo(p); }
        } guard{res};

        const bool was_cancelled = self->cancelled.load();
        auto cb = std::move(self->cb);

        if (was_cancelled) {
            // Nobody is waiting any more. Drop the result silently: do not notify,
            // and do not touch anything the caller owns.
            return;
        }

        if (status < 0) {
            if (cb) {
                const ErrorCode code =
                    (status == UV_EAI_NONAME) ? ErrorCode::DnsNameNotFound
                                              : ErrorCode::DnsResolveFailed;
                cb(Error{code, ErrorPhase::Resolve,
                         format("getaddrinfo failed: {}", uv_strerror(status))});
            }
            return;
        }

        AddressList out;
        for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) continue;
            ResolvedAddress a;
            a.family = (ai->ai_family == AF_INET6) ? ResolvedAddress::Family::IPv6
                                                   : ResolvedAddress::Family::IPv4;
            a.text = format_ip(ai->ai_addr);
            if (a.text.empty()) continue;
            a.port = (self->port != 0) ? self->port : address_port(ai->ai_addr);
            a.bytes = address_bytes(ai->ai_addr);
            out.push_back(std::move(a));
        }

        if (out.empty()) {
            if (cb) {
                cb(Error{ErrorCode::DnsNoData, ErrorPhase::Resolve,
                         string("getaddrinfo returned no usable address")});
            }
            return;
        }
        if (cb) cb(AddressList(std::move(out)));
    }

} // namespace Detail

    inline SystemResolverImpl::~SystemResolverImpl() = default;

    inline CancelHandle SystemResolverImpl::resolve(string host, uint16_t port,
                                                    Resolver::Callback cb) {
        auto state = std::make_shared<CancelState>();
        CancelHandle handle(state);

        // A numeric literal never goes to DNS (spec 5.4.1). Answer it directly,
        // but still through the executor so the callback thread stays consistent.
        {
            AddressList literal = parse_ip_literal(to_view(host), port);
            if (!literal.empty()) {
                executor_->post([cb, literal, state]() mutable {
                    if (state->is_cancelled()) return;
                    if (cb) cb(AddressList(std::move(literal)));
                });
                return handle;
            }
        }

        // uv_getaddrinfo must be started on the loop thread, which is why this is
        // marshalled rather than called inline.
        auto uv_exec = std::dynamic_pointer_cast<libuv_backend::UvExecutor>(executor_);
        uv_loop_t* loop = (uv_exec != nullptr) ? uv_exec->loop() : nullptr;
        if (loop == nullptr) {
            auto st = state;
            executor_->post([cb, st]() mutable {
                if (st->is_cancelled()) return;
                if (cb) {
                    cb(Error{ErrorCode::NotImplemented, ErrorPhase::Resolve,
                             string("system resolver requires a libuv executor")});
                }
            });
            return handle;
        }

        executor_->post([loop, host, port, cb, state]() mutable {
            if (state->is_cancelled()) return;

            auto req = std::make_shared<Detail::AddrInfoRequest>();
            req->self = req;                 // self-hold until the callback clears it
            req->cb = std::move(cb);
            req->port = port;
            req->host.assign(host.data(), static_cast<size_t>(host.size()));

            char port_buf[8] = {0};
            std::snprintf(port_buf, sizeof port_buf, "%u", static_cast<unsigned>(port));
            req->service.assign(port_buf);

            // Cancellation flips the flag; a result that arrives afterwards is
            // dropped instead of delivered.
            state->on_cancel([req] {
                req->cancelled.store(true);
                // uv_cancel only succeeds for requests still queued in the thread
                // pool; a running getaddrinfo cannot be interrupted. Either way the
                // callback fires and the flag discards it.
                uv_cancel(reinterpret_cast<uv_req_t*>(&req->req));
            });

            addrinfo hints{};
            hints.ai_family = AF_UNSPEC;      // let the system return both v4 and v6
            hints.ai_socktype = SOCK_STREAM;  // TCP
            hints.ai_protocol = IPPROTO_TCP;

            req->req.data = req.get();
            const int rc = uv_getaddrinfo(loop, &req->req,
                                          &Detail::addrinfo_cb,
                                          req->host.c_str(), req->service.c_str(), &hints);
            if (rc < 0) {
                // Starting failed: no callback will come, so release here.
                req->self.reset();
                const bool was_cancelled = state->is_cancelled();
                auto c = std::move(req->cb);
                if (!was_cancelled && c) {
                    c(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                            format("uv_getaddrinfo failed to start: {}", uv_strerror(rc))});
                }
            }
        });

        return handle;
    }

} // namespace MegoHttp

#endif // MEGOHTTP_RESOLVER_LIBUV_IMPL_HPP_INCLUDED

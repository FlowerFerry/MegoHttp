#ifndef MEGOHTTP_PROXY_TUNNEL_IMPL_HPP_INCLUDED
#define MEGOHTTP_PROXY_TUNNEL_IMPL_HPP_INCLUDED

#include <megohttp/resolver.hpp>

#include <charconv>
#include <memory>
#include <string>

namespace megohttp {
    namespace proxy_tunnel {
        namespace detail {

            // Reads until the proxy's head is complete ("\r\n\r\n"). Bytes after
            // that point belong to the tunnel and are returned separately: the
            // origin may answer the instant the tunnel opens, and dropping those
            // bytes truncates the very first read.
            struct HeadReader {
                static void run(const std::shared_ptr<AsyncByteStream>& stream,
                                size_t max_bytes,
                                std::shared_ptr<std::string> acc,
                                std::function<void(Result<std::string>)> done) {
                    if (acc->find("\r\n\r\n") != std::string::npos) {
                        done(*acc);
                        return;
                    }
                    if (acc->size() > max_bytes) {
                        done(Error{ErrorCode::ProxyProtocolError, ErrorPhase::ProxyConnect,
                                   string("proxy response head is too large")});
                        return;
                    }
                    stream->async_read_some(
                        [stream, max_bytes, acc, done](Result<string_view> r) {
                            if (!r) { done(r.error()); return; }
                            const string_view v = r.value();
                            if (v.empty()) {
                                done(Error{ErrorCode::ConnectionClosed,
                                           ErrorPhase::ProxyConnect,
                                           string("proxy closed before its head completed")});
                                return;
                            }
                            acc->append(v.data(), v.size());
                            HeadReader::run(stream, max_bytes, acc, done);
                        });
                }
            };

            // Splits the proxy head into status + trailing bytes.
            inline Result<int> parse_connect_status(const std::string& head,
                                                    byte_buffer& leftover) {
                const size_t sp1 = head.find(' ');
                if (sp1 == std::string::npos) {
                    return Error{ErrorCode::ProxyProtocolError, ErrorPhase::ProxyConnectTunnel,
                                 string("CONNECT response has no status line")};
                }
                const size_t sp2 = head.find(' ', sp1 + 1);
                const std::string code =
                    head.substr(sp1 + 1, sp2 == std::string::npos ? std::string::npos
                                                                  : sp2 - sp1 - 1);
                int status = 0;
                // from_chars, not atoi: the status comes from an untrusted proxy
                // and atoi has undefined behaviour on overflow.
                const char* b = code.data();
                const char* e = code.data() + code.size();
                auto fr = std::from_chars(b, e, status);
                if (fr.ec != std::errc{} || fr.ptr != e || status < 100 || status > 999) {
                    return Error{ErrorCode::ProxyProtocolError, ErrorPhase::ProxyConnectTunnel,
                                 string("CONNECT response has invalid status code")};
                }

                const size_t end = head.find("\r\n\r\n");
                if (end != std::string::npos) {
                    const size_t body_at = end + 4;
                    if (body_at < head.size()) {
                        leftover.assign(
                            reinterpret_cast<const uint8_t*>(head.data()) + body_at,
                            reinterpret_cast<const uint8_t*>(head.data()) + head.size());
                    }
                }
                return status;
            }

            // Writes a buffer and then reads the proxy head.
            inline void exchange_head(const std::shared_ptr<AsyncByteStream>& stream,
                                      std::shared_ptr<string> request,
                                      size_t max_bytes,
                                      std::function<void(Result<std::string>)> done) {
                stream->async_write(
                    reinterpret_cast<const uint8_t*>(request->data()), request->size(),
                    [stream, request, max_bytes, done](Result<size_t> w) mutable {
                        (void)request;
                        if (!w) {
                            done(Error{ErrorCode::ProxyConnectFailed, ErrorPhase::ProxyConnect,
                                       string("failed to send the CONNECT request")});
                            return;
                        }
                        HeadReader::run(stream, max_bytes,
                                        std::make_shared<std::string>(), done);
                    });
            }

            // ---- SOCKS5 ----
            //
            // Binary protocol: the reply is a fixed structure and anything past it
            // is tunnel data that must be preserved. Driven as a small state
            // machine because a reply may arrive in pieces.

            inline void read_at_least(const std::shared_ptr<AsyncByteStream>& stream,
                                      std::shared_ptr<byte_buffer> acc,
                                      size_t need,
                                      std::function<void(VoidResult)> done) {
                if (acc->size() >= need) { done(VoidResult{}); return; }
                stream->async_read_some(
                    [stream, acc, need, done](Result<string_view> r) {
                        if (!r) { done(r.error()); return; }
                        const string_view v = r.value();
                        if (v.empty()) {
                            done(Error{ErrorCode::Socks5HandshakeFailed,
                                       ErrorPhase::ProxyConnect,
                                       string("SOCKS5 proxy closed the connection")});
                            return;
                        }
                        acc->insert(acc->end(),
                                    reinterpret_cast<const uint8_t*>(v.data()),
                                    reinterpret_cast<const uint8_t*>(v.data()) + v.size());
                        read_at_least(stream, acc, need, done);
                    });
            }

            inline size_t socks5_reply_total(uint8_t atyp, size_t have,
                                             const byte_buffer& buf) {
                size_t addr_len = 0;
                switch (atyp) {
                    case proxy_detail::socks5::kAtypIpv4: addr_len = 4; break;
                    case proxy_detail::socks5::kAtypIpv6: addr_len = 16; break;
                    case proxy_detail::socks5::kAtypDomain:
                        if (have < 5) return 0;
                        addr_len = 1 + static_cast<size_t>(buf[4]);
                        break;
                    default: return 0;
                }
                return 4 + addr_len + 2;
            }

            inline void socks5_send_connect(std::shared_ptr<AsyncByteStream> transport,
                                            string host,
                                            uint16_t port,
                                            TunnelCallback done) {
                using namespace proxy_detail::socks5;
                // An address literal must use the IPv4/IPv6 ATYP. Sending
                // "127.0.0.1" as kAtypDomain makes the proxy interpret it as a
                // DNS name; some proxies then fail, and a local-DNS mode that
                // asked for an address on the wire has not been honoured.
                auto literal = parse_ip_literal(to_view(host), port);
                std::shared_ptr<byte_buffer> req;
                if (!literal.empty() &&
                    literal.front().family == ResolvedAddress::Family::IPv4) {
                    req = std::make_shared<byte_buffer>(build_connect(
                        kAtypIpv4, {}, literal.front().bytes.data(),
                        literal.front().bytes.size(), port));
                } else if (!literal.empty() &&
                           literal.front().family == ResolvedAddress::Family::IPv6) {
                    req = std::make_shared<byte_buffer>(build_connect(
                        kAtypIpv6, {}, literal.front().bytes.data(),
                        literal.front().bytes.size(), port));
                } else {
                    req = std::make_shared<byte_buffer>(build_connect(
                        kAtypDomain, to_view(host), nullptr, 0, port));
                }
                transport->async_write(
                    req->data(), req->size(),
                    [transport, req, done](Result<size_t> w) mutable {
                        (void)req;
                        if (!w) {
                            done(Error{ErrorCode::Socks5HandshakeFailed,
                                       ErrorPhase::ProxyConnect,
                                       string("failed to send the SOCKS5 CONNECT")});
                            return;
                        }
                        auto rep = std::make_shared<byte_buffer>();
                        read_at_least(transport, rep, 4,
                            [transport, rep, done](VoidResult r) mutable {
                                if (!r) { done(r.error()); return; }
                                if ((*rep)[0] != proxy_detail::socks5::kVersion) {
                                    done(Error{ErrorCode::Socks5HandshakeFailed,
                                               ErrorPhase::ProxyConnect,
                                               string("SOCKS5 reply version mismatch")});
                                    return;
                                }
                                if ((*rep)[1] != 0x00) {
                                    done(Error{ErrorCode::Socks5HandshakeFailed,
                                               ErrorPhase::ProxyConnect,
                                               format("SOCKS5 CONNECT refused with reply {}",
                                                      (*rep)[1])});
                                    return;
                                }
                                const uint8_t atyp = (*rep)[3];
                                if (atyp != proxy_detail::socks5::kAtypIpv4 &&
                                    atyp != proxy_detail::socks5::kAtypIpv6 &&
                                    atyp != proxy_detail::socks5::kAtypDomain) {
                                    done(Error{ErrorCode::Socks5HandshakeFailed,
                                               ErrorPhase::ProxyConnect,
                                               string("SOCKS5 reply has an unknown address type")});
                                    return;
                                }
                                auto go = [transport, rep, atyp, done]() mutable {
                                    const size_t total =
                                        socks5_reply_total(atyp, rep->size(), *rep);
                                    read_at_least(transport, rep, total,
                                        [transport, rep, total, done](VoidResult r2) mutable {
                                            if (!r2) { done(r2.error()); return; }
                                            byte_buffer leftover(rep->begin() + total,
                                                                 rep->end());
                                            done(TunnelResult{transport,
                                                              std::move(leftover)});
                                        });
                                };
                                // The domain form needs its length byte before the
                                // total can be computed.
                                if (atyp == proxy_detail::socks5::kAtypDomain &&
                                    rep->size() < 5) {
                                    read_at_least(transport, rep, 5,
                                        [go](VoidResult) mutable { go(); });
                                    return;
                                }
                                go();
                            });
                    });
            }

            inline void socks5_tunnel(std::shared_ptr<AsyncByteStream> transport,
                                      string host,
                                      uint16_t port,
                                      const ProxyOptions& proxy,
                                      TunnelCallback done) {
                using namespace proxy_detail::socks5;
                const bool with_auth = proxy.proxy.has_credentials();
                auto greeting = std::make_shared<byte_buffer>(build_greeting(with_auth));
                transport->async_write(
                    greeting->data(), greeting->size(),
                    [transport, greeting, with_auth, proxy, host, port, done]
                    (Result<size_t> w) mutable {
                        (void)greeting;
                        if (!w) {
                            done(Error{ErrorCode::Socks5HandshakeFailed,
                                       ErrorPhase::ProxyConnect,
                                       string("failed to send the SOCKS5 greeting")});
                            return;
                        }
                        auto acc = std::make_shared<byte_buffer>();
                        read_at_least(transport, acc, 2,
                            [acc, transport, with_auth, proxy, host, port, done]
                            (VoidResult r) mutable {
                                if (!r) { done(r.error()); return; }
                                const uint8_t chosen = (*acc)[1];
                                if (chosen == kAuthNoAcceptable) {
                                    done(Error{ErrorCode::Socks5AuthFailed,
                                               ErrorPhase::ProxyAuth,
                                               string("SOCKS5 proxy accepted no auth method")});
                                    return;
                                }
                                if (chosen != kAuthNone && chosen != kAuthUserPass) {
                                    done(Error{ErrorCode::Socks5HandshakeFailed,
                                               ErrorPhase::ProxyConnect,
                                               string("SOCKS5 proxy chose an unknown method")});
                                    return;
                                }
                                if (with_auth && chosen != kAuthUserPass) {
                                    done(Error{ErrorCode::Socks5AuthFailed,
                                               ErrorPhase::ProxyAuth,
                                               string("SOCKS5 proxy refused username/password")});
                                    return;
                                }
                                if (chosen == kAuthUserPass) {
                                    auto auth = std::make_shared<byte_buffer>(
                                        build_user_pass(to_view(proxy.proxy.username),
                                                        to_view(proxy.proxy.password)));
                                    transport->async_write(
                                        auth->data(), auth->size(),
                                        [auth, transport, host, port, done]
                                        (Result<size_t> wa) mutable {
                                            (void)auth;
                                            if (!wa) {
                                                done(Error{ErrorCode::Socks5AuthFailed,
                                                           ErrorPhase::ProxyAuth,
                                                           string("failed to send SOCKS5 credentials")});
                                                return;
                                            }
                                            auto ar = std::make_shared<byte_buffer>();
                                            read_at_least(transport, ar, 2,
                                                [ar, transport, host, port, done]
                                                (VoidResult r6) mutable {
                                                    if (!r6) { done(r6.error()); return; }
                                                    if ((*ar)[1] != 0x00) {
                                                        done(Error{ErrorCode::Socks5AuthFailed,
                                                                   ErrorPhase::ProxyAuth,
                                                                   string("SOCKS5 credentials rejected")});
                                                        return;
                                                    }
                                                    socks5_send_connect(transport, host,
                                                                        port, done);
                                                });
                                        });
                                    return;
                                }
                                socks5_send_connect(transport, host, port, done);
                            });
                    });
            }

        } // namespace detail

        // ---------------------------------------------------------------------
        inline void establish(std::shared_ptr<AsyncByteStream> stream,
                              const ProxyOptions& proxy,
                              string_view target_host,
                              uint16_t target_port,
                              string_view user_agent,
                              PhaseHook on_phase,
                              TunnelCallback done) {
            if (!stream) {
                done(Error{ErrorCode::ProxyConnectFailed, ErrorPhase::ProxyConnect,
                           string("no stream to tunnel through")});
                return;
            }
            if (!proxy.proxy.is_set()) {
                done(TunnelResult{std::move(stream), {}});
                return;
            }
            if (!proxy.proxy.host.empty() && proxy.proxy.port == 0) {
                done(Error{ErrorCode::InvalidArgument, ErrorPhase::ProxyConnect,
                           string("proxy has no port")});
                return;
            }

            auto phase = [on_phase](ErrorPhase p) {
                if (on_phase) on_phase(p);
            };

            // WebSocket targets are wss://, so an HTTP-speaking proxy must carry
            // them through a tunnel.
            const bool needs_tunnel = proxy_detail::needs_connect(proxy.proxy.type, true);

            auto after_transport =
                [proxy, host = to_string(target_host), target_port, user_agent,
                 needs_tunnel, phase, done]
                (std::shared_ptr<AsyncByteStream> transport) {
                    if (!transport) {
                        done(Error{ErrorCode::TlsHandshakeFailed, ErrorPhase::ProxyTls,
                                   string("proxy TLS handshake failed")});
                        return;
                    }

                    if (proxy.proxy.type == ProxyType::Socks5) {
                        phase(ErrorPhase::ProxyConnectTunnel);
                        detail::socks5_tunnel(std::move(transport), host, target_port,
                                              proxy, done);
                        return;
                    }

                    if (!needs_tunnel) {
                        done(TunnelResult{transport, {}});
                        return;
                    }

                    phase(ErrorPhase::ProxyConnectTunnel);
                    auto req = std::make_shared<string>(
                        proxy_detail::build_connect_request(
                            to_view(host), target_port, proxy.proxy, user_agent));
                    detail::exchange_head(transport, req, 64 * 1024,
                        [transport, done](Result<std::string> head) {
                            if (!head) { done(head.error()); return; }
                            byte_buffer leftover;
                            auto st = detail::parse_connect_status(head.value(), leftover);
                            if (!st) { done(st.error()); return; }
                            if (st.value() != 200) {
                                done(Error{ErrorCode::ProxyConnectFailed,
                                           ErrorPhase::ProxyConnectTunnel,
                                           format("CONNECT was refused with {}", st.value())});
                                return;
                            }
                            done(TunnelResult{transport, std::move(leftover)});
                        });
                };

            // The proxy layer itself may be TLS (HTTPS proxy): wrap first, then
            // run the handshake above the wrapped stream.
            if (proxy_detail::uses_proxy_tls(proxy.proxy.type)) {
                phase(ErrorPhase::ProxyTls);
                TlsConfig cfg = proxy.tls;
                if (cfg.hostname.empty()) cfg.hostname = proxy.proxy.host;
                auto tls = make_tls_stream(std::move(stream), cfg);
                if (!tls) {
                    done(Error{ErrorCode::TlsHandshakeFailed, ErrorPhase::ProxyTls,
                               string("failed to create the proxy TLS stream")});
                    return;
                }
                tls->set_error_phase(ErrorPhase::ProxyTls, ErrorPhase::ProxyTls);
                tls->start([tls, after_transport](VoidResult r) {
                    if (!r) {
                        // The TLS layer already produced the specific reason; a
                        // generic tunnel error would hide a certificate problem
                        // behind "connect failed".
                        after_transport(nullptr);
                        return;
                    }
                    after_transport(std::static_pointer_cast<AsyncByteStream>(tls));
                });
                return;
            }

            after_transport(std::move(stream));
        }

    } // namespace proxy_tunnel
} // namespace megohttp

#endif // MEGOHTTP_PROXY_TUNNEL_IMPL_HPP_INCLUDED

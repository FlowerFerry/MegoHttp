#ifndef MEGOHTTP_BACKEND_RESOLVER_ASIO_IMPL_HPP_INCLUDED
#define MEGOHTTP_BACKEND_RESOLVER_ASIO_IMPL_HPP_INCLUDED

#include <megohttp/backend/resolver_asio.hpp>

#include <asio.hpp>
#include <asio/ip/tcp.hpp>

namespace MegoHttp {
namespace Detail {

    // Shared ownership of the async resolver request: it self-holds until the
    // callback fires, so a cancel racing the completion cannot destroy it.
    struct AsioResolveRequest
        : std::enable_shared_from_this<AsioResolveRequest> {
        asio::ip::tcp::resolver resolver;
        Resolver::Callback cb;
        std::shared_ptr<CancelState> state;
        uint16_t port{0};
        std::atomic<bool> cancelled{false};

        template<typename Executor>
        AsioResolveRequest(Executor& ex, uint16_t p,
                           Resolver::Callback c, std::shared_ptr<CancelState> st)
            : resolver(asio::make_strand(ex.get_executor())),
              cb(std::move(c)),
              state(std::move(st)),
              port(p) {}

        void start(string host) {
            std::string h(host.data(), host.size());
            std::string service = std::to_string(port);
            resolver.async_resolve(h, service,
                [self = shared_from_this()](const asio::error_code& ec,
                    asio::ip::tcp::resolver::results_type results) {
                    self->on_result(ec, std::move(results));
                });
        }

    private:
        void on_result(const asio::error_code& ec,
                       asio::ip::tcp::resolver::results_type results) {
            if (cancelled.load()) return;
            auto cb_copy = std::move(cb);
            if (!cb_copy) return;

            if (ec == asio::error::operation_aborted) return;
            if (ec) {
                const ErrorCode code =
                    (ec == asio::error::host_not_found) ? ErrorCode::DnsNameNotFound
                                                       : ErrorCode::DnsResolveFailed;
                cb_copy(Error{code, ErrorPhase::Resolve,
                              format("async_resolve failed: {}", ec.message())});
                return;
            }

            AddressList out;
            for (const auto& ep : results) {
                auto addr = ep.endpoint().address();
                if (!addr.is_v4() && !addr.is_v6()) continue;
                ResolvedAddress a;
                a.family = addr.is_v6() ? ResolvedAddress::Family::IPv6
                                        : ResolvedAddress::Family::IPv4;
                const std::string text = addr.to_string();
                a.text = to_string(text.data(), text.size());
                if (a.text.empty()) continue;
                a.port = (port != 0) ? port : ep.endpoint().port();
                if (addr.is_v4()) {
                    const auto v4 = addr.to_v4().to_bytes();
                    a.bytes.assign(v4.begin(), v4.end());
                } else {
                    const auto v6 = addr.to_v6().to_bytes();
                    a.bytes.assign(v6.begin(), v6.end());
                }
                out.push_back(std::move(a));
            }

            if (out.empty()) {
                cb_copy(Error{ErrorCode::DnsNoData, ErrorPhase::Resolve,
                              string("async_resolve returned no usable address")});
                return;
            }
            cb_copy(AddressList(std::move(out)));
        }
    };

} // namespace Detail

    inline SystemResolverImpl::~SystemResolverImpl() = default;

    inline CancelHandle SystemResolverImpl::resolve(string host, uint16_t port,
                                                    Resolver::Callback cb) {
        auto state = std::make_shared<CancelState>();
        CancelHandle handle(state);

        // Numeric literal: answer directly (spec 5.4.1).
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

        auto asio_exec = std::dynamic_pointer_cast<asio_backend::AsioExecutor>(executor_);
        if (asio_exec == nullptr) {
            auto st = state;
            executor_->post([cb, st]() mutable {
                if (st->is_cancelled()) return;
                if (cb) {
                    cb(Error{ErrorCode::NotImplemented, ErrorPhase::Resolve,
                             string("system resolver requires an Asio executor")});
                }
            });
            return handle;
        }

        // The resolver request self-holds through the async call.
        auto req = std::make_shared<Detail::AsioResolveRequest>(
            *asio_exec->context(), port, std::move(cb), state);

        state->on_cancel([req]() {
            req->cancelled.store(true);
            req->resolver.cancel();
        });

        req->start(host);
        return handle;
    }

} // namespace MegoHttp

#endif

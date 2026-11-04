#ifndef MEGOHTTP_BACKEND_RESOLVER_ASIO_HPP_INCLUDED
#define MEGOHTTP_BACKEND_RESOLVER_ASIO_HPP_INCLUDED

// standalone Asio implementation of SystemResolverImpl.
//
// Same role as the libuv one: the async lookup is the only genuinely
// backend-specific part, so the shared SystemResolver / StaticResolver /
// ChainedResolver above it do not branch on backend.
//
// Uses asio::ip::tcp::resolver::async_resolve so a synchronous getaddrinfo is
// never run on the loop thread (spec 5.4.1).
#include <megohttp/resolver.hpp>
#include <megohttp/backend/executor_asio.hpp>

#if !defined(MGHTTP_BACKEND_ASIO)
#   error "resolver_asio.hpp requires MGHTTP_BACKEND_ASIO"
#endif

#include <asio/ip/tcp.hpp>

#include <memory>

namespace MegoHttp {

    class SystemResolverImpl {
    public:
        explicit SystemResolverImpl(std::shared_ptr<Executor> ex)
            : executor_(std::move(ex)) {}
        ~SystemResolverImpl();

        CancelHandle resolve(string host, uint16_t port, Resolver::Callback cb);

    private:
        std::shared_ptr<Executor> executor_;
    };

} // namespace MegoHttp

#include <megohttp/backend/resolver_asio_impl.hpp>

#endif // MEGOHTTP_BACKEND_RESOLVER_ASIO_HPP_INCLUDED

#ifndef MEGOHTTP_RESOLVER_LIBUV_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_LIBUV_HPP_INCLUDED

#include <megohttp/resolver.hpp>
#include <megohttp/backend/executor_libuv.hpp>

#if !MGHTTP_BACKEND_LIBUV
#   error "resolver_libuv.hpp requires MGHTTP_BACKEND_LIBUV"
#endif

#include <uv.h>

namespace megohttp {

    // The libuv implementation of the async lookup: uv_getaddrinfo runs the
    // platform resolver on libuv's thread pool, so the loop thread never blocks on
    // getaddrinfo (spec 5.4.1 forbids calling the blocking API there).
    class SystemResolverImpl {
    public:
        explicit SystemResolverImpl(std::shared_ptr<Executor> ex)
            : executor_(std::move(ex)) {}
        ~SystemResolverImpl();

        CancelHandle resolve(string host, uint16_t port, Resolver::Callback cb);

    private:
        std::shared_ptr<Executor> executor_;
    };

#define MEGOHTTP_SYSTEM_RESOLVER_IMPL_DEFINED 1

} // namespace megohttp

#include <megohttp/backend/resolver_libuv_impl.hpp>

#endif // MEGOHTTP_RESOLVER_LIBUV_HPP_INCLUDED

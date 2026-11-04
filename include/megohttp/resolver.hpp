#ifndef MEGOHTTP_RESOLVER_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <functional>
#include <cstring>
#include <memory>
#include <vector>

#if defined(_WIN32)
    // winsock2.h must precede ws2tcpip.h on MinGW, or inet_pton/inet_ntop are
    // left undeclared. In the libuv backend <uv.h> happens to include it first;
    // the Asio backend does not, so make the order explicit here.
#   include <winsock2.h>
#   include <ws2tcpip.h>
#else
#   include <arpa/inet.h>
#endif

namespace MegoHttp {

    // One resolved address. Kept protocol-agnostic: no sockaddr in the public API,
    // so a consumer never has to include a platform header.
    struct ResolvedAddress {
        enum class Family { IPv4, IPv6 };

        Family family{Family::IPv4};
        // Numeric form as text: "192.0.2.1" or "2001:db8::1" (no brackets).
        // Owning, so the list outlives the resolver's internal buffers.
        string text;
        uint16_t port{0};

        // Socket address bytes in network order, for the backend to hand straight
        // to connect(). 4 bytes for IPv4, 16 for IPv6. Empty when the backend
        // prefers to re-parse `text`.
        std::vector<uint8_t> bytes;
    };

    // DNS result set. `addresses` is ordered: the connection layer walks it in
    // order (Happy Eyeballs interleaving happens there, not here).
    using AddressList = std::vector<ResolvedAddress>;

    // All callbacks below run on the executor's loop thread. Exactly one of them
    // fires per resolve() call unless cancelled, in which case none fires and the
    // handle simply stops caring.

    // Injected resolver interface (spec 5.4.4): lets tests supply a fixed answer
    // list, lets an application override addresses, and is the seam DoT/DoH plug
    // into later.
    class Resolver {
    public:
        using Callback = std::function<void(Result<AddressList>)>;

        virtual ~Resolver() = default;

        // Begin an asynchronous lookup of `host`. `port` is copied into every
        // produced ResolvedAddress.
        //
        // Contract:
        //   • Must not block the calling thread.
        //   • The callback runs on the executor's loop thread.
        //   • Cancelling the handle means "do not call back"; a late result from a
        //     system lookup is discarded, never delivered.
        virtual CancelHandle resolve(string host, uint16_t port, Callback cb) = 0;

        // Human-readable identifier, for diagnostics and cache keying.
        virtual const char* name() const noexcept = 0;
    };

    // ---------------------------------------------------------------------------
    // SystemResolver: wraps the platform's getaddrinfo through the backend's
    // asynchronous facility, so the loop thread never blocks.
    // ---------------------------------------------------------------------------

    // Backend-supplied implementation. Declared here, defined by
    // backend/resolver_<backend>.hpp, because the async lookup mechanism is the
    // one genuinely backend-specific piece: uv_getaddrinfo on libuv,
    // asio::ip::tcp::resolver on Asio.
    class SystemResolverImpl;

    class SystemResolver final : public Resolver,
                                 public std::enable_shared_from_this<SystemResolver> {
    public:
        // `executor` must outlive the resolver.
        explicit SystemResolver(std::shared_ptr<Executor> executor);
        ~SystemResolver() override;

        CancelHandle resolve(string host, uint16_t port, Callback cb) override;
        const char* name() const noexcept override { return "system"; }

    private:
        std::shared_ptr<SystemResolverImpl> impl_;
    };

    // ---------------------------------------------------------------------------
    // StaticResolver: a fixed answer table. The test seam, and also the address
    // override mechanism (spec 5.4.4: an override changes only the connect
    // target, never the Host header, SNI or certificate identity).
    // ---------------------------------------------------------------------------
    class StaticResolver final : public Resolver {
    public:
        StaticResolver(std::shared_ptr<Executor> executor, AddressList answers);

        // Every host resolves to the same list.
        CancelHandle resolve(string host, uint16_t port, Callback cb) override;
        const char* name() const noexcept override { return "static"; }

        void set_answers(AddressList answers);

    private:
        std::shared_ptr<Executor> executor_;
        AddressList answers_;
    };

    // ---------------------------------------------------------------------------
    // Resolver chain: tries each resolver in order until one succeeds. Used for
    // "custom resolver first, system resolver as the fallback".
    //
    // This is NOT a DNS-fallback-to-plaintext path: an encrypted-DNS resolver's
    // strictness is its own business, and this chain only decides what to try when
    // a resolver returns an error.
    // ---------------------------------------------------------------------------
    class ChainedResolver final : public Resolver {
    public:
        explicit ChainedResolver(std::vector<std::shared_ptr<Resolver>> chain);

        CancelHandle resolve(string host, uint16_t port, Callback cb) override;
        const char* name() const noexcept override { return "chain"; }

    private:
        std::vector<std::shared_ptr<Resolver>> chain_;
    };

    // Parses a numeric address literal without touching DNS. Returns an empty list
    // when `host` is a name rather than a literal.
    AddressList parse_ip_literal(const string_view& host, uint16_t port);

} // namespace MegoHttp

#if defined(MGHTTP_BACKEND_LIBUV)
#   include <megohttp/backend/resolver_libuv.hpp>
#elif defined(MGHTTP_BACKEND_ASIO)
#   include <megohttp/backend/resolver_asio.hpp>
#endif
#include <megohttp/resolver_impl.hpp>

#endif // MEGOHTTP_RESOLVER_HPP_INCLUDED

#ifndef MEGOHTTP_RESOLVER_IMPL_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_IMPL_HPP_INCLUDED

// Included at the end of resolver.hpp. Header-only, all definitions inline.

#include <utility>

namespace megohttp {

    // --- SystemResolver ------------------------------------------------------
    // The body lives in backend/resolver_<backend>.hpp because the async lookup
    // mechanism is backend-specific; resolver.hpp already pulled that header in.

#if defined(MEGOHTTP_SYSTEM_RESOLVER_IMPL_DEFINED)
    // SystemResolverImpl lives in the selected backend header. That header sets
    // MEGOHTTP_SYSTEM_RESOLVER_IMPL_DEFINED after its class definition, which is
    // how this file tells "in scope" from "merely forward-declared": a TU that
    // includes the backend header directly sets the backend's own include guard,
    // so resolver.hpp's #include of it becomes a no-op on the way back here.
    inline SystemResolver::SystemResolver(std::shared_ptr<Executor> executor)
        : impl_(std::make_shared<SystemResolverImpl>(std::move(executor))) {}

    inline SystemResolver::~SystemResolver() = default;

    inline CancelHandle SystemResolver::resolve(string host, uint16_t port, Callback cb) {
        return impl_->resolve(std::move(host), port, std::move(cb));
    }
#endif

    // --- parse_ip_literal ----------------------------------------------------
    inline AddressList parse_ip_literal(const string_view& host, uint16_t port) {
        AddressList out;
        const size_t n = static_cast<size_t>(host.size());
        const char* p = host.data();
        if (n == 0) return out;

        // Brackets are stripped by the URL parser, but accept them here too so this
        // helper is usable on raw user input.
        string_view bare = host;
        if (n >= 2 && p[0] == '[' && p[n - 1] == ']') {
            bare = string_view(p + 1, static_cast<string_view::size_type>(n - 2));
        }

        ResolvedAddress a;
        a.port = port;
        a.bytes.resize(16);

        // IPv4
        {
            unsigned char buf[4];
            std::vector<char> tmp(static_cast<size_t>(bare.size()) + 1, '\0');
            std::memcpy(tmp.data(), bare.data(), static_cast<size_t>(bare.size()));
            if (inet_pton(AF_INET, tmp.data(), buf) == 1) {
                a.family = ResolvedAddress::Family::IPv4;
                a.text = to_string(bare);
                a.bytes.assign(buf, buf + 4);
                out.push_back(std::move(a));
                return out;
            }
        }
        // IPv6
        {
            unsigned char buf[16];
            std::vector<char> tmp(static_cast<size_t>(bare.size()) + 1, '\0');
            std::memcpy(tmp.data(), bare.data(), static_cast<size_t>(bare.size()));
            if (inet_pton(AF_INET6, tmp.data(), buf) == 1) {
                a.family = ResolvedAddress::Family::IPv6;
                a.text = to_string(bare);
                a.bytes.assign(buf, buf + 16);
                out.push_back(std::move(a));
                return out;
            }
        }
        return out;   // not a literal
    }

    // --- StaticResolver ------------------------------------------------------
    inline StaticResolver::StaticResolver(std::shared_ptr<Executor> executor, AddressList answers)
        : executor_(std::move(executor)), answers_(std::move(answers)) {}

    inline void StaticResolver::set_answers(AddressList answers) {
        answers_ = std::move(answers);
    }

    inline CancelHandle StaticResolver::resolve(string host, uint16_t port, Callback cb) {
        (void)host;
        auto state = std::make_shared<CancelState>();
        CancelHandle handle(state);

        AddressList answers = answers_;
        for (auto& a : answers) a.port = port;

        // Deliver through the executor so the callback thread matches every other
        // resolver -- a synchronous call would break the "callbacks run on the loop
        // thread" contract that the rest of the library relies on.
        executor_->post([cb, answers, state]() mutable {
            if (state->is_cancelled()) return;
            if (answers.empty()) {
                if (cb) {
                    cb(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                             string("static resolver has no answer for this host")});
                }
                return;
            }
            if (cb) cb(AddressList(std::move(answers)));
        });
        return handle;
    }

    // --- ChainedResolver -----------------------------------------------------
    inline ChainedResolver::ChainedResolver(std::vector<std::shared_ptr<Resolver>> chain)
        : chain_(std::move(chain)) {}

    inline CancelHandle ChainedResolver::resolve(string host, uint16_t port, Callback cb) {
        auto state = std::make_shared<CancelState>();
        CancelHandle handle(state);
        if (chain_.empty()) {
            if (cb) {
                cb(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                         string("resolver chain is empty")});
            }
            return handle;
        }

        // Walk the chain; the first success wins, the last error is reported.
        auto index = std::make_shared<size_t>(0);
        auto last_error = std::make_shared<Error>(ErrorCode::Unknown);
        auto self = std::make_shared<std::function<void()>>();

        *self = [chain = chain_, index, last_error, cb, state, host, port, self]() mutable {
            if (state->is_cancelled()) return;
            if (*index >= chain.size()) {
                if (cb) cb(*last_error);
                return;
            }
            auto& r = chain[(*index)++];
            r->resolve(host, port, [last_error, cb, state, self]
                                     (Result<AddressList> result) mutable {
                if (state->is_cancelled()) return;
                if (result) {
                    if (cb) cb(std::move(result));
                } else {
                    *last_error = result.error();
                    (*self)();
                }
            });
        };
        (*self)();
        return handle;
    }

} // namespace megohttp

#endif // MEGOHTTP_RESOLVER_IMPL_HPP_INCLUDED

#ifndef MEGOHTTP_HEADERS_HPP_INCLUDED
#define MEGOHTTP_HEADERS_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/string_adapter.hpp>

#include <optional>
#include <utility>
#include <vector>

namespace MegoHttp {


    // Ordered multimap of header fields.
    //
    // Design decisions that matter for correctness:
    //   • Names are compared case-insensitively for every lookup and remove.
    //   • Duplicate fields are preserved (Set-Cookie, Vary, Warning, ...).
    //     add() appends; set() replaces ALL existing values of that name.
    //   • Insertion order is preserved, so a caller can reproduce the wire order.
    //   • All storage is owning `string`, so a Headers can outlive any parser buffer.
    class Headers {
    public:
        using value_type = std::pair<string, string>;
        using container_type = std::vector<value_type>;
        using iterator = container_type::iterator;
        using const_iterator = container_type::const_iterator;

        Headers() = default;

        // --- Mutation ---
        void add(string_view name, string_view value);
        void add(const char* name, const char* value);
        void set(string_view name, string_view value);   // replaces all with that name
        bool remove(string_view name);                   // true if anything was erased

        void clear() noexcept { fields_.clear(); }

        // --- Query ---
        bool contains(string_view name) const noexcept;
        std::optional<string_view> get(string_view name) const noexcept;
        std::vector<string_view> get_all(string_view name) const;

        // Convenience typed-ish accessors used by the HTTP layer. They return
        // nullopt when absent or unparsable; they never guess.
        std::optional<uint64_t> get_uint(string_view name) const noexcept;

        // --- Iteration / size ---
        const_iterator begin() const noexcept { return fields_.begin(); }
        const_iterator end() const noexcept { return fields_.end(); }
        iterator begin() noexcept { return fields_.begin(); }
        iterator end() noexcept { return fields_.end(); }

        bool empty() const noexcept { return fields_.empty(); }
        size_t size() const noexcept { return fields_.size(); }

        // Total bytes of all names + values, for header-size accounting.
        size_t byte_size() const noexcept;

        // Direct field access for the parser (avoids re-lowercasing on insert).
        const container_type& fields() const noexcept { return fields_; }

    private:
        container_type fields_;
    };

    // A header value must not contain CR/LF/NUL; a name must be a valid token.
    // The HTTP layer uses these to reject request-smuggling attempts.
    bool is_valid_header_name(string_view name) noexcept;
    bool is_valid_header_value(string_view value) noexcept;

} // namespace MegoHttp

#include <megohttp/headers_impl.hpp>

#endif // MEGOHTTP_HEADERS_HPP_INCLUDED

#ifndef MEGOHTTP_STRING_ADAPTER_HPP_INCLUDED
#define MEGOHTTP_STRING_ADAPTER_HPP_INCLUDED

#include <megohttp/config.hpp>

#if MEGOHTTP_HAS_MEMESTRING
#   include <memepp/string.hpp>
#   include <memepp/string_view.hpp>
#   include <memepp/string_span.hpp>
#else
#   include <string>
#   include <string_view>
#   include <cstddef>
#endif

#include <cstdint>
#include <cstring>
#include <vector>

namespace MegoHttp {

    // Unified string adapter. Two modes selected by MGHTTP_USE_MEMESTRING.
    //
    // Ownership model (required by the spec's string-switching rules):
    //   string       - owning. Any text the library stores across I/O stages.
    //   string_view  - borrowed. Callback parameters and short-lived access only.
    //   string_span  - borrowed, non-owning, never shared. Parsing input only.
    //
    // A string_view/string_span must NEVER be captured into an async operation;
    // copy into a `string` before handing text to the library.
#if MEGOHTTP_HAS_MEMESTRING
    using string      = memepp::string;
    using string_view = memepp::string_view;
    using string_span = memepp::string_span;
#else
    using string      = std::string;
    using string_view = std::string_view;
    using string_span = std::string_view;
#endif

    // --- Builder -------------------------------------------------------------
    // memepp::string is IMMUTABLE: it has no append / operator+= / operator[]
    // (only reset()). Composing text therefore cannot go through `string`;
    // it must go through a builder. std::string, by contrast, is its own builder.
    //
    // Exposed as a uniform interface so protocol code never branches on the mode.
#if MEGOHTTP_HAS_MEMESTRING
    using string_builder = memepp::string_builder;
#else
    class string_builder {
    public:
        string_builder() = default;
        // Implicit construction so `string_builder sb = "x"` style stays valid.
        string_builder(const string& s) : buf_(s) {}
        string_builder(const char* s) : buf_(s) {}

        string_builder& operator+=(const string& s) { buf_ += s; return *this; }
        string_builder& operator+=(string_view s) { buf_.append(s.data(), s.size()); return *this; }
        string_builder& operator+=(const char* s) { buf_ += s; return *this; }
        string_builder& operator+=(char c) { buf_ += c; return *this; }

        string release() { return string(std::move(buf_)); }
        string generate() const { return buf_; }

        size_t size() const noexcept { return buf_.size(); }
        bool empty() const noexcept { return buf_.empty(); }
        void reserve_parts(size_t) noexcept {}
        void clear() noexcept { buf_.clear(); }

    private:
        std::string buf_;
    };
#endif

    namespace detail {
        // Append a borrowed view to a builder without spelling the mode-specific
        // overload at every call site.
        inline string_builder& sb_append(string_builder& b, string_view v) {
            b += v;
            return b;
        }

        inline string_builder& sb_append(string_builder& b, const char* v) {
            b += v;
            return b;
        }

        inline string_builder& sb_append(string_builder& b, char c) {
            b += c;
            return b;
        }

        inline string_builder& sb_append(string_builder& b, const string& s) {
            b += s;
            return b;
        }

        // Terminate a builder into an owning string.
        inline string sb_release(string_builder& b) {
            return b.release();
        }

        inline string sb_generate(const string_builder& b) {
            return b.generate();
        }
    } // namespace detail

    // Byte buffers are for raw network bytes, TLS ciphertext, compressed data and
    // file contents. They are deliberately NOT the string type: the string-switch
    // requirement applies to TEXT, and bytes must not be smuggled through it.
    using byte_buffer = std::vector<uint8_t>;

    namespace detail {

        // Size type differs between backends (memepp uses mmint_t = int32_t).
        inline size_t to_size(string_view v) noexcept {
#if MEGOHTTP_HAS_MEMESTRING
            return static_cast<size_t>(v.size());
#else
            return v.size();
#endif
        }

        // ASCII case-insensitive compare. Every header-name lookup and every
        // scheme/token comparison goes through this; non-ASCII bytes never fold.
        //
        // MemeString already provides case-insensitive search, so the comparison
        // is delegated to it instead of re-walking the bytes here. std mode uses
        // the standard-library-free constexpr lowering below.
#if MEGOHTTP_HAS_MEMESTRING
        inline bool ascii_iequals(string_view a, string_view b) noexcept {
            // Equal length plus a case-insensitive match starting at 0 is an
            // exact compare; the length check rules out a proper prefix.
            if (a.size() != b.size()) return false;
            return a.index_of(b, memepp::case_sensitivity_t::all_insensitive) == 0;
        }

        inline bool ascii_iequals(string_view a, const char* b) noexcept {
            return a.index_of(b, memepp::case_sensitivity_t::all_insensitive) == 0
                && a.size() == static_cast<string_view::size_type>(std::strlen(b));
        }
#else
        inline bool ascii_iequals(string_view a, string_view b) noexcept {
            if (a.size() != b.size()) {
                return false;
            }

            constexpr auto ascii_lower = [](unsigned char c) noexcept -> unsigned char {
                return (c >= 'A' && c <= 'Z')
                    ? static_cast<unsigned char>(c + ('a' - 'A'))
                    : c;
            };

            for (size_t i = 0; i < a.size(); ++i) {
                if (ascii_lower(static_cast<unsigned char>(a[i])) !=
                    ascii_lower(static_cast<unsigned char>(b[i]))) {
                    return false;
                }
            }

            return true;
        }

        inline bool ascii_iequals(string_view a, const char* b) noexcept {
            const unsigned char* pb = reinterpret_cast<const unsigned char*>(b);
            if (a.size() != std::strlen(b)) {
                return false;
            }

            constexpr auto ascii_lower = [](unsigned char c) noexcept -> unsigned char {
                return (c >= 'A' && c <= 'Z')
                    ? static_cast<unsigned char>(c + ('a' - 'A'))
                    : c;
            };

            for (size_t i = 0; i < a.size(); ++i) {
                if (ascii_lower(static_cast<unsigned char>(a[i])) !=
                    ascii_lower(pb[i])) {
                    return false;
                }
            }

            return true;
        }
#endif

    } // namespace detail

    // --- Conversions -----------------------------------------------------------
    // Constructing an owning string from a borrowed view. Both modes support this;
    // the overload set is spelled out so callers do not depend on an implicit path.
    inline string to_string(string_view v) {
#if MEGOHTTP_HAS_MEMESTRING
        return v.to_string();
#else
        return string(v);
#endif
    }

#if MEGOHTTP_HAS_MEMESTRING
    // In std mode string_span IS string_view (both std::string_view), so this
    // overload would redefine the one above. MemeString mode has distinct types.
    inline string to_string(string_span v) {
        return v.to_string();
    }
#endif

    // Owning string -> borrowed view. The view aliases `s`; it dies with `s`.
    inline string_view to_view(const string& s) noexcept {
#if MEGOHTTP_HAS_MEMESTRING
        return string_view(s);
#else
        return string_view(s.data(), s.size());
#endif
    }

    // For raw bytes that are known to be text (e.g. a parsed header value that
    // lives in the parser's buffer). Copies into an owning string.
    inline string to_string(const char* data, size_t size) {
#if MEGOHTTP_HAS_MEMESTRING
        return string(data, static_cast<string::size_type>(size));
#else
        return string(data, size);
#endif
    }

    namespace literals {

        // Owned literal, e.g. `using namespace MegoHttp::literals; "abc"_s`
#if MEGOHTTP_HAS_MEMESTRING
        inline string operator""_s(const char* p, size_t n) {
            return string(p, static_cast<string::size_type>(n));
        }
#else
        inline string operator""_s(const char* p, size_t n) {
            return string(p, n);
        }
#endif

    } // namespace literals

} // namespace MegoHttp

// Lower-case spelling for the string layer only: every type name here is already
// lower-case (string / string_view / string_span), so a matching lower-case
// namespace keeps `megohttp::string` reading naturally without renaming anything
// in the rest of the library.
namespace megohttp {
    using MegoHttp::string;
    using MegoHttp::string_view;
    using MegoHttp::string_span;
    using MegoHttp::string_builder;
    using MegoHttp::byte_buffer;
    using MegoHttp::to_string;
    using MegoHttp::to_view;
    namespace literals = MegoHttp::literals;
}

#endif // MEGOHTTP_STRING_ADAPTER_HPP_INCLUDED

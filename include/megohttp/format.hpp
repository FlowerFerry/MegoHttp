#ifndef MEGOHTTP_FORMAT_HPP_INCLUDED
#define MEGOHTTP_FORMAT_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/string_adapter.hpp>

#include <fmt/format.h>

#if MEGOHTTP_HAS_MEMESTRING
// Registers fmt::formatter<memepp::string> / <memepp::string_view> and the
// memepp::convert::into<fmt::string_view> bridge, plus fmt::runtime() overloads
// for memepp strings. Included here so every formatting call site in this
// library can pass library strings directly.
#   include <memepp/convert/fmt.hpp>
#   include <memepp/convert/std/string.hpp>
#endif

#include <utility>

// ---------------------------------------------------------------------------
// Formatting bridge.
//
// fmt is the only formatter this library uses: no std::ostringstream, no
// snprintf, no hand-rolled digit appenders. That matters for the string-switch
// requirement -- an ostringstream would quietly reintroduce a std::string
// storage path even in MemeString mode.
//
// The two modes differ in ONE place: fmt::format always returns a std::string,
// so MemeString mode has to move that result into its owning string type. The
// conversion goes through MemeString's own convert layer (memepp::from), not an
// ad-hoc (ptr, len) construction, so MemeString decides the storage policy
// (small/medium/large, buffer takeover) rather than this library guessing.
// ---------------------------------------------------------------------------

namespace MegoHttp {
namespace Detail {

    // Convert any fmt-formattable argument into an owning `string`.
    //
    // Two modes:
    //   std    : the fmt result IS the string type -- move it, no copy.
    //   memepp : fmt produced a std::string; convert via memepp::from which
    //            takes over the heap buffer for large results instead of copying.
    template<typename... Args>
    inline string format_string(fmt::format_string<Args...> f, Args&&... args) {
#if MEGOHTTP_HAS_MEMESTRING
        std::string tmp = fmt::format(f, std::forward<Args>(args)...);
        return memepp::from(std::move(tmp));
#else
        return fmt::format(f, std::forward<Args>(args)...);
#endif
    }

} // namespace Detail

    // Public spelling, so callers and the library share one entry point.
    template<typename... Args>
    inline string format(fmt::format_string<Args...> f, Args&&... args) {
        return Detail::format_string(f, std::forward<Args>(args)...);
    }

} // namespace MegoHttp

#endif // MEGOHTTP_FORMAT_HPP_INCLUDED

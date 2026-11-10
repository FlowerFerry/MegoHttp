#ifndef MEGOHTTP_IDNA_HPP_INCLUDED
#define MEGOHTTP_IDNA_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/string_adapter.hpp>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // IDNA (Internationalized Domain Names) support.
    //
    // Scope, stated honestly:
    //   • This implements RFC 3492 Punycode plus the subset of IDNA2008 needed to
    //     turn a UTF-8 domain into its ASCII A-label form ("中文.com" ->
    //     "xn--fiq228c.com"). It does NOT implement the full IDNA2008 Unicode
    //     tables (bidi rules, contextual joining, script mixing, NFC folding).
    //   • Because of that, parse_url() REJECTS a non-ASCII host by default
    //     (task book 5.4.1 forbids an incomplete conversion). Convert with a
    //     conforming IDNA library first and pass the A-label; that path goes
    //     through the normal ASCII host checks.
    //   • These functions remain available for callers that have decided the
    //     subset is enough for their input. A domain that survives conversion is
    //     safe to put on the wire; exotic cases IDNA2008 would reject may be
    //     accepted here, which is why the URL parser does not call it implicitly.
    //   • Already-encoded A-labels ("xn--...") pass through unchanged, so the
    //     function is idempotent.
    // ---------------------------------------------------------------------------

    // True when every byte is ASCII (< 0x80).
    bool is_ascii(const string_view& text) noexcept;

    // Encode a UTF-8 host name into its ASCII (A-label) form.
    //   • ASCII input is returned unchanged (each label validated as a host label).
    //   • Each non-ASCII label gets the "xn--" prefix plus its Punycode encoding.
    //   • An empty label, a label longer than 63 bytes after encoding, or a total
    //     length over 253 bytes is an error, not a silent truncation.
    Result<string> idna_encode(const string_view& host);

    // Punycode RFC 3492 encoder for a single label (UTF-8 in, ASCII out).
    // Exposed separately because it is the part worth unit-testing on its own and
    // because a caller may want to encode a label without the host rules.
    Result<string> punycode_encode(const string_view& utf8_label);

    namespace detail {

        // Decode one UTF-8 code point starting at `i`; advances `i`.
        // Returns false on an invalid or truncated sequence.
        // Uses byte-range guards (overlong / surrogate checks are done inline)
        // so the caller gets a single call-site with no post-loop value tests.
        bool utf8_next(const char* p, size_t n, size_t& i, uint32_t& cp) noexcept;

    } // namespace detail

} // namespace megohttp

#include <megohttp/idna_impl.hpp>

#endif // MEGOHTTP_IDNA_HPP_INCLUDED

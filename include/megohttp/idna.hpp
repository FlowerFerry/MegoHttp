#ifndef MEGOHTTP_IDNA_HPP_INCLUDED
#define MEGOHTTP_IDNA_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/string_adapter.hpp>

namespace MegoHttp {

    // ---------------------------------------------------------------------------
    // IDNA (Internationalized Domain Names) support.
    //
    // Scope, stated honestly:
    //   • This implements RFC 3492 Punycode plus the subset of IDNA2008 needed to
    //     turn a UTF-8 domain into its ASCII A-label form ("中文.com" ->
    //     "xn--fiq228c.com"). It does NOT implement the full IDNA2008 Unicode
    //     tables (bidi rules, contextual joining, script mixing, NFC folding).
    //   • Therefore: a domain that survives conversion is safe to put on the wire;
    //     exotic cases that IDNA2008 would reject may be accepted here. Callers
    //     who need full conformance must pre-convert with a real IDNA library --
    //     this is a convenience for the common case, not a claim of completeness.
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

    namespace Detail {

        // Decode one UTF-8 code point starting at `i`; advances `i`.
        // Returns false on an invalid or truncated sequence.
        bool utf8_next(const char* p, size_t n, size_t& i, uint32_t& cp) noexcept;

        // Encode one code point as UTF-8 into `out` (which must have room for 4).
        // Returns the number of bytes written.
        size_t utf8_encode(uint32_t cp, char* out) noexcept;

    } // namespace Detail

} // namespace MegoHttp

#include <megohttp/idna_impl.hpp>

#endif // MEGOHTTP_IDNA_HPP_INCLUDED

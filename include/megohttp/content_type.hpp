#ifndef MEGOHTTP_CONTENT_TYPE_HPP_INCLUDED
#define MEGOHTTP_CONTENT_TYPE_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/string_adapter.hpp>

#include <optional>
#include <vector>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // Content-Type parsing (S3.4-24)
    //
    // The multipart response parser needs the boundary out of the response's
    // Content-Type header. Doing that split here means the parser itself only has
    // to deal with bytes, and callers get one tested implementation of the MIME
    // parameter grammar (RFC 2045 5.1) instead of rolling their own.
    //
    // Grammar handled:
    //   media-type := type "/" subtype *( OWS ";" OWS parameter )
    //   parameter  := attribute "=" value
    //   value      := token / quoted-string
    //
    // Quoted strings support the two backslash escapes RFC 2045 allows inside
    // them (quoted-pair); anything else after a backslash is kept verbatim, which
    // is what the MIME grammar asks for.
    // ---------------------------------------------------------------------------
    struct MediaType {
        string type;       // lowercased, e.g. "multipart"
        string subtype;    // lowercased, e.g. "byteranges"
        string value;      // the full lowercased "type/subtype", for convenience

        // First occurrence of each parameter, lowercased name, value unquoted.
        // A parameter that appears twice is a ContentTypeError, not a silent
        // pick — see parse_media_type's contract.
        std::vector<std::pair<string, string>> parameters;

        bool is_multipart() const noexcept { return type == string("multipart"); }

        // Returns the parameter's value, or nullopt when it is absent.
        std::optional<string_view> parameter(string_view name) const noexcept;
    };

    // Parses a Content-Type field value.
    //
    // Rejects (ContentTypeInvalid unless noted):
    //   - an empty value, or one with no "/" in the media type
    //   - a type or subtype containing anything outside the RFC 2045 token set
    //   - a parameter with no "=", an empty name, or an unterminated quoted string
    //   - a duplicated parameter name that carries a DIFFERENT value (an exact
    //     repeat is collapsed: some servers emit the same parameter twice)
    Result<MediaType> parse_media_type(string_view value);

    // Convenience: extracts the multipart boundary, validating everything the
    // multipart response parser depends on.
    //
    // Rejects with MultipartMediaTypeInvalid when:
    //   - the media type is not multipart/*
    //   - there is no boundary parameter
    //   - the boundary parameter appears twice with different values
    //   - the boundary is empty, longer than 70 characters (RFC 2046), or contains
    //     a byte outside the bchars set
    //
    // `expected_subtypes` restricts which multipart subtypes are accepted; an
    // empty list means "any multipart subtype".
    Result<string> parse_multipart_boundary(string_view content_type,
                                            const std::vector<string>& expected_subtypes = {});

} // namespace megohttp

#include <megohttp/content_type_impl.hpp>

#endif // MEGOHTTP_CONTENT_TYPE_HPP_INCLUDED

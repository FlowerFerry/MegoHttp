#ifndef MEGOHTTP_CONTENT_RANGE_HPP_INCLUDED
#define MEGOHTTP_CONTENT_RANGE_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <optional>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // Content-Range parsing (S3.5)
    //
    // Two forms exist in RFC 7233:
    //   Content-Range: bytes 0-499/1234        (a satisfied range)
    //   Content-Range: bytes */1234            (unsatisfied, used with 416)
    //
    // `end` and `total` are optional because either may be "*". `end` unknown is
    // only legal in the unsatisfied form; a real range needs both ends.
    // ---------------------------------------------------------------------------
    struct ContentRange {
        enum class Kind {
            Bytes,      // "bytes ..."
            Unsupported // some other unit; the numbers are not interpreted
        };

        Kind kind{Kind::Bytes};

        // Present for the "bytes */N" (unsatisfied) form, and absent when total is "*".
        std::optional<uint64_t> first;
        std::optional<uint64_t> last;
        std::optional<uint64_t> total;

        // True for "bytes */N": a range was requested but nothing is satisfiable.
        bool unsatisfied{false};

        bool is_known_length() const noexcept {
            return total.has_value() && !unsatisfied;
        }

        // Number of bytes this range covers. Requires first and last.
        std::optional<uint64_t> length() const noexcept {
            if (!first.has_value() || !last.has_value()) return std::nullopt;
            if (last.value() < first.value()) return std::nullopt;
            return std::optional<uint64_t>(last.value() - first.value() + 1);
        }
    };

    // Parses a Content-Range field value.
    //
    // Rejects: a non-"bytes" unit is reported as Kind::Unsupported rather than an
    // error, because that is a caller decision; anything malformed in the bytes
    // form is MultipartContentRangeInvalid.
    Result<ContentRange> parse_content_range(string_view value);

    // Checks a part's actual byte count against its Content-Range.
    // A range with a known length must match exactly; an unsatisfied range must
    // carry no bytes. `expected_total` is checked against `total` when both exist.
    VoidResult validate_content_range(const ContentRange& range,
                                      uint64_t part_bytes,
                                      std::optional<uint64_t> expected_total = std::nullopt);

} // namespace megohttp

#include <megohttp/content_range_impl.hpp>

#endif // MEGOHTTP_CONTENT_RANGE_HPP_INCLUDED

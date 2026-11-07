#ifndef MEGOHTTP_CONTENT_RANGE_IMPL_HPP_INCLUDED
#define MEGOHTTP_CONTENT_RANGE_IMPL_HPP_INCLUDED

// Included at the end of content_range.hpp. Header-only: every definition inline.

#include <megohttp/http.hpp>

#include <charconv>

namespace megohttp {

    namespace content_range_detail {

        inline string_view trim(string_view v) noexcept {
            return http_detail::trim_ows(v);
        }

        // Parses a non-negative decimal with overflow detection.
        inline Result<uint64_t> parse_u64(string_view s) {
            if (s.empty()) {
                return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                             string("Content-Range has an empty number")};
            }
            const char* p = s.data();
            const size_t n = static_cast<size_t>(s.size());
            for (size_t i = 0; i < n; ++i) {
                if (p[i] < '0' || p[i] > '9') {
                    return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                                 string("Content-Range number is not decimal")};
                }
            }
            uint64_t acc = 0;
            const auto res = std::from_chars(p, p + n, acc, 10);
            if (res.ec == std::errc::result_out_of_range) {
                return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                             string("Content-Range number overflows uint64")};
            }
            if (res.ec != std::errc{} || res.ptr != p + n) {
                return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                             string("Content-Range number is malformed")};
            }
            return acc;
        }

    } // namespace content_range_detail

    inline Result<ContentRange> parse_content_range(string_view value) {
        using namespace content_range_detail;

        const string_view v = trim(value);
        if (v.empty()) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range is empty")};
        }

        // --- unit ---
        const char* p = v.data();
        const size_t n = static_cast<size_t>(v.size());
        size_t sp = 0;
        while (sp < n && p[sp] != ' ') ++sp;
        if (sp == 0 || sp >= n) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range has no unit or value")};
        }
        const string_view unit(p, static_cast<string_view::size_type>(sp));
        if (!detail::ascii_iequals(unit, "bytes")) {
            // A different unit is not an error here: the caller decides whether it
            // can use the range. The numbers are left uninterpreted.
            ContentRange out;
            out.kind = ContentRange::Kind::Unsupported;
            return out;
        }

        const string_view rest = trim(string_view(p + sp, static_cast<string_view::size_type>(n - sp)));
        if (rest.empty()) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range has no range")};
        }

        // --- split on '/' ---
        const char* rp = rest.data();
        const size_t rn = static_cast<size_t>(rest.size());
        size_t slash = rn;
        for (size_t i = 0; i < rn; ++i) {
            if (rp[i] == '/') { slash = i; break; }
        }
        if (slash == rn) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range is missing the '/' separator")};
        }

        const string_view range_part(rp, static_cast<string_view::size_type>(slash));
        const string_view total_part = trim(string_view(rp + slash + 1,
                                                        static_cast<string_view::size_type>(rn - slash - 1)));
        if (total_part.empty()) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range has an empty total")};
        }

        ContentRange out;

        // --- total: "*" or a number ---
        if (total_part.data()[0] == '*') {
            if (total_part.size() != 1) {
                return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                             string("Content-Range total has trailing characters after '*'")};
            }
            // total unknown, stays nullopt
        } else {
            auto t = parse_u64(total_part);
            if (!t) return t.error();
            out.total = t.value();
        }

        // --- range: "*/" or "first-last" ---
        const string_view range_trimmed = trim(range_part);
        if (range_trimmed.empty()) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range has an empty range")};
        }

        if (range_trimmed.data()[0] == '*') {
            if (range_trimmed.size() != 1) {
                return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                             string("Content-Range range has trailing characters after '*'")};
            }
            out.unsatisfied = true;
            return out;
        }

        // first-last
        const char* q = range_trimmed.data();
        const size_t qn = static_cast<size_t>(range_trimmed.size());
        size_t dash = qn;
        for (size_t i = 0; i < qn; ++i) {
            if (q[i] == '-') { dash = i; break; }
        }
        if (dash == qn) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range is missing the '-' separator")};
        }

        auto first = parse_u64(string_view(q, static_cast<string_view::size_type>(dash)));
        if (!first) return first.error();
        auto last = parse_u64(string_view(q + dash + 1,
                                          static_cast<string_view::size_type>(qn - dash - 1)));
        if (!last) return last.error();

        if (last.value() < first.value()) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range last byte precedes the first")};
        }
        // last must be strictly inside the resource when the total is known.
        if (out.total.has_value() && last.value() >= out.total.value()) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range last byte is outside the resource")};
        }

        out.first = first.value();
        out.last = last.value();
        return out;
    }

    inline VoidResult validate_content_range(const ContentRange& range,
                                             uint64_t part_bytes,
                                             std::optional<uint64_t> expected_total) {
        if (range.kind != ContentRange::Kind::Bytes) {
            // Not our unit: nothing to check.
            return VoidResult{};
        }

        if (range.unsatisfied) {
            if (part_bytes != 0) {
                return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                             string("unsatisfied Content-Range carried data")};
            }
            return VoidResult{};
        }

        if (!range.first.has_value() || !range.last.has_value()) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range has no byte range")};
        }

        if (expected_total.has_value()) {
            if (!range.total.has_value()) {
                return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                             string("Content-Range omits the total that the response declared")};
            }
            if (range.total.value() != expected_total.value()) {
                return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                             string("Content-Range total disagrees with the response")};
            }
        }

        const auto expected_len = range.length();
        if (!expected_len.has_value()) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("Content-Range has an invalid span")};
        }
        if (expected_len.value() != part_bytes) {
            return Error{ErrorCode::MultipartContentRangeInvalid, ErrorPhase::Receive,
                         string("part byte count does not match its Content-Range")};
        }
        return VoidResult{};
    }

} // namespace megohttp

#endif // MEGOHTTP_CONTENT_RANGE_IMPL_HPP_INCLUDED

#ifndef MEGOHTTP_DNS_WIRE_IMPL_HPP_INCLUDED
#define MEGOHTTP_DNS_WIRE_IMPL_HPP_INCLUDED

// DNS wire-format codec implementation (task book section 9-A.5).
//
// Every read goes through `Reader`, which bounds-checks. That is deliberate:
// the alternative (index arithmetic at each call site) is exactly the shape of
// code that has produced every DNS parser CVE.

#include <megohttp/dns_wire.hpp>

#include <cstring>

namespace megohttp {
namespace dns {

    namespace dns_detail {

        // Bounds-checked big-endian reader. Every field read goes through here,
        // so an over-read is impossible rather than "unlikely".
        class Reader {
        public:
            Reader(const uint8_t* p, size_t n) : p_(p), n_(n) {}

            size_t pos() const noexcept { return i_; }
            size_t size() const noexcept { return n_; }
            size_t remaining() const noexcept { return n_ - i_; }
            bool eof() const noexcept { return i_ >= n_; }
            bool skip(size_t k) noexcept {
                if (!has(k)) return false;
                i_ += k;
                return true;
            }

            bool has(size_t k) const noexcept { return k <= n_ - i_; }

            bool u8(uint8_t& out) noexcept {
                if (!has(1)) return false;
                out = p_[i_++];
                return true;
            }
            bool u16(uint16_t& out) noexcept {
                if (!has(2)) return false;
                out = static_cast<uint16_t>((static_cast<uint16_t>(p_[i_]) << 8) |
                                            static_cast<uint16_t>(p_[i_ + 1]));
                i_ += 2;
                return true;
            }
            bool u32(uint32_t& out) noexcept {
                if (!has(4)) return false;
                out = (static_cast<uint32_t>(p_[i_]) << 24) |
                      (static_cast<uint32_t>(p_[i_ + 1]) << 16) |
                      (static_cast<uint32_t>(p_[i_ + 2]) << 8) |
                      static_cast<uint32_t>(p_[i_ + 3]);
                i_ += 4;
                return true;
            }

            // Verbatim bytes into a byte_buffer.
            bool bytes(size_t k, byte_buffer& out) noexcept {
                if (!has(k)) return false;
                out.assign(p_ + i_, p_ + i_ + k);
                i_ += k;
                return true;
            }

            // A view of the remaining bytes, without consuming.
            const uint8_t* data_at(size_t offset) const noexcept { return p_ + offset; }

            // Set the cursor absolutely. Used to follow a compression pointer;
            // the caller has already validated the target.
            bool seek(size_t offset) noexcept {
                if (offset > n_) return false;
                i_ = offset;
                return true;
            }

        private:
            const uint8_t* p_;
            size_t n_;
            size_t i_{0};
        };

        // Decodes a (possibly compressed) name starting at the reader's cursor.
        //
        // The cursor is left AFTER the name's in-line bytes: following a pointer
        // must not move the caller's read position, or the next field would be
        // read from inside the pointed-at name.
        //
        // Compression rules enforced:
        //   - a pointer must point strictly BACKWARDS (offset < the pointer's own
        //     position). A forward pointer can only be a loop or a lie.
        //   - at most `max_hops` pointers are followed.
        //   - the decoded name may not exceed `max_length`.
        inline bool read_name(Reader& r, string& out, size_t max_hops, size_t max_length) {
            out = string{};
            string_builder b;
            size_t cursor = r.pos();
            size_t hops = 0;
            size_t total = 0;
            bool jumped = false;
            size_t end_of_name = 0;   // where the caller's cursor must end up

            for (;;) {
                if (cursor >= r.size()) return false;
                const uint8_t len = r.data_at(cursor)[0];

                if (len == 0) {
                    // Root label: end of name.
                    if (!jumped) end_of_name = cursor + 1;
                    break;
                }

                if ((len & 0xC0) == 0xC0) {
                    // Compression pointer: two bytes.
                    if (cursor + 2 > r.size()) return false;
                    const size_t target =
                        (static_cast<size_t>(len & 0x3F) << 8) |
                        static_cast<size_t>(r.data_at(cursor)[1]);
                    if (!jumped) end_of_name = cursor + 2;

                    // Backwards only. Equal-to-self or forward is a loop.
                    if (target >= cursor) return false;
                    if (++hops > max_hops) return false;

                    jumped = true;
                    cursor = target;
                    continue;
                }

                if ((len & 0xC0) != 0) return false;   // 0x40/0x80 are not labels

                // Ordinary label.
                if (cursor + 1 + static_cast<size_t>(len) > r.size()) return false;
                if (len > 63) return false;

                total += static_cast<size_t>(len) + 1;   // +1 for the dot
                if (total > max_length) return false;

                if (!b.empty()) b += '.';
                for (size_t k = 1; k <= static_cast<size_t>(len); ++k) {
                    uint8_t c = r.data_at(cursor)[k];
                    // DNS names compare case-insensitively; lowercase as we go so
                    // every downstream comparison is a plain byte compare.
                    if (c >= 'A' && c <= 'Z') c = static_cast<uint8_t>(c - 'A' + 'a');
                    b += static_cast<char>(c);
                }
                cursor += 1 + static_cast<size_t>(len);
                if (!jumped) end_of_name = cursor;
            }

            if (end_of_name == 0) return false;
            if (!r.seek(end_of_name)) return false;
            out = b.release();
            return true;
        }

        inline string_view trim_dot(string_view s) noexcept {
            if (!s.empty() && s.data()[s.size() - 1] == '.') {
                return string_view(s.data(), s.size() - 1);
            }
            return s;
        }

    } // namespace dns_detail

    // -----------------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------------

    inline Result<byte_buffer> encode_name(string_view name) {
        using namespace dns_detail;
        byte_buffer out;
        const string_view n = trim_dot(name);

        if (n.empty()) {
            out.push_back(0);       // root
            return out;
        }

        size_t start = 0;
        size_t total = 0;
        for (;;) {
            const size_t dot = n.find('.', start);
            const size_t end = (dot == string_view::npos) ? n.size() : dot;
            const size_t len = end - start;

            if (len == 0) {
                return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                             string("DNS name contains an empty label")};
            }
            if (len > 63) {
                return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                             string("DNS label exceeds 63 bytes")};
            }
            total += len + 1;
            if (total > 255) {
                return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                             string("DNS name exceeds 255 bytes")};
            }

            out.push_back(static_cast<uint8_t>(len));
            for (size_t i = start; i < end; ++i) {
                out.push_back(static_cast<uint8_t>(n.data()[i]));
            }

            if (dot == string_view::npos) break;
            start = dot + 1;
        }
        out.push_back(0);   // root terminator
        return out;
    }

    inline Result<byte_buffer> build_query(uint16_t id, string_view name,
                                           RecordType type, RecordClass klass) {
        auto qname = encode_name(name);
        if (!qname) return qname.error();

        byte_buffer out;
        const byte_buffer& q = qname.value();
        out.reserve(12 + q.size() + 4);

        auto put16 = [&out](uint16_t v) {
            out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(v & 0xFF));
        };

        put16(id);
        put16(0x0100);            // RD=1, opcode=0 (query)
        put16(1);                 // QDCOUNT
        put16(0);                 // ANCOUNT
        put16(0);                 // NSCOUNT
        put16(0);                 // ARCOUNT
        out.insert(out.end(), q.begin(), q.end());
        put16(static_cast<uint16_t>(type));
        put16(static_cast<uint16_t>(klass));
        return out;
    }

    // -----------------------------------------------------------------------
    // Parsing
    // -----------------------------------------------------------------------

    inline Result<Message> parse_message(const uint8_t* data, size_t size,
                                         ParseLimits limits) {
        using namespace dns_detail;

        if (!data || size < 12) {
            return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                         string("DNS message is too short for a header")};
        }

        Reader r(data, size);
        Message m;

        uint16_t flags = 0, qd = 0, an = 0, ns = 0, ar = 0;
        if (!r.u16(m.id) || !r.u16(flags) || !r.u16(qd) || !r.u16(an) ||
            !r.u16(ns) || !r.u16(ar)) {
            return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                         string("DNS header is truncated")};
        }

        m.is_response = (flags & 0x8000) != 0;
        m.truncated = (flags & 0x0200) != 0;
        m.recursion_desired = (flags & 0x0100) != 0;
        m.recursion_available = (flags & 0x0080) != 0;

        switch (flags & 0x000F) {
            case 0: m.rcode = ResponseCode::NoError;  break;
            case 1: m.rcode = ResponseCode::FormErr;  break;
            case 2: m.rcode = ResponseCode::ServFail; break;
            case 3: m.rcode = ResponseCode::NxDomain; break;
            case 4: m.rcode = ResponseCode::NotImp;   break;
            case 5: m.rcode = ResponseCode::Refused;  break;
            default: m.rcode = ResponseCode::Unknown; break;
        }

        // A truncated response may legitimately stop mid-section; parse what is
        // there and report `truncated`. The caller decides whether a partial
        // answer is usable -- the parser does not silently pretend it is whole.
        const size_t total_expected =
            static_cast<size_t>(qd) + an + ns + ar;
        if (total_expected > limits.max_records_total) {
            return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                         string("DNS message declares more records than allowed")};
        }

        // ---- Question ----
        if (qd > 0) {
            if (!read_name(r, m.question_name, limits.max_pointer_hops,
                           limits.max_name_length)) {
                return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                             string("DNS question name is malformed")};
            }
            if (!r.u16(m.question_type) || !r.u16(m.question_class)) {
                return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                             string("DNS question is truncated")};
            }
            // Remaining questions are skipped (the library only asks one).
            for (uint16_t i = 1; i < qd; ++i) {
                string ignored;
                if (!read_name(r, ignored, limits.max_pointer_hops,
                               limits.max_name_length)) {
                    return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                                 string("DNS extra question name is malformed")};
                }
                if (!r.skip(4)) {
                    return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                                 string("DNS extra question is truncated")};
                }
            }
        }

        auto parse_section = [&](uint16_t count, std::vector<Record>& out,
                                 size_t cap) -> VoidResult {
            for (uint16_t i = 0; i < count; ++i) {
                if (out.size() >= cap) {
                    return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                                 string("DNS record count exceeds the limit")};
                }
                Record rec;
                if (!read_name(r, rec.name, limits.max_pointer_hops,
                               limits.max_name_length)) {
                    if (m.truncated) return VoidResult{};   // partial is allowed
                    return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                                 string("DNS record name is malformed")};
                }
                uint16_t raw_class = 0;
                if (!r.u16(rec.raw_type) || !r.u16(raw_class) || !r.u32(rec.ttl)) {
                    if (m.truncated) return VoidResult{};
                    return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                                 string("DNS record header is truncated")};
                }
                rec.klass = (raw_class == 1) ? RecordClass::IN
                                             : (raw_class == 255 ? RecordClass::Any
                                                                 : RecordClass::IN);
                uint16_t rdlen = 0;
                if (!r.u16(rdlen)) {
                    if (m.truncated) return VoidResult{};
                    return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                                 string("DNS record length is truncated")};
                }
                if (!r.has(rdlen)) {
                    if (m.truncated) return VoidResult{};
                    return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                                 string("DNS record data is truncated")};
                }

                const size_t rdata_pos = r.pos();
                switch (rec.raw_type) {
                    case 1:  rec.type = RecordType::A; break;
                    case 5:  rec.type = RecordType::CNAME; break;
                    case 6:  rec.type = RecordType::SOA; break;
                    case 28: rec.type = RecordType::AAAA; break;
                    case 41: rec.type = RecordType::OPT; break;
                    default: rec.type = RecordType::Raw; break;
                }

                if (rec.type == RecordType::CNAME) {
                    // The target name may itself be compressed, so it has to be
                    // decoded from the message start, not copied as raw bytes.
                    Reader sub(data, size);
                    if (!sub.seek(rdata_pos)) return Error{
                        ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                        string("DNS CNAME target offset is out of range")};
                    if (!read_name(sub, rec.cname_target, limits.max_pointer_hops,
                                   limits.max_name_length)) {
                        return Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                                     string("DNS CNAME target is malformed")};
                    }
                    if (!r.skip(rdlen)) return Error{
                        ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                        string("DNS record data overruns the message")};
                } else {
                    if (!r.bytes(rdlen, rec.data)) return Error{
                        ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                        string("DNS record data overruns the message")};
                }
                out.push_back(std::move(rec));
            }
            return VoidResult{};
        };

        auto a = parse_section(an, m.answers, limits.max_records);
        if (!a) return a.error();
        auto n = parse_section(ns, m.authorities, limits.max_records);
        if (!n) return n.error();
        auto d = parse_section(ar, m.additionals, limits.max_records);
        if (!d) return d.error();

        // Negative-cache TTL (RFC 2308 5): SOA MINIMUM, capped by the SOA's TTL.
        for (const auto& rec : m.authorities) {
            if (rec.type != RecordType::SOA) continue;
            if (rec.data.size() < 20) break;   // 2 names (>=2 bytes) + 20 bytes fields
            // MINIMUM is the LAST 4 bytes of the SOA RDATA.
            const size_t k = rec.data.size();
            const uint32_t minimum =
                (static_cast<uint32_t>(rec.data[k - 4]) << 24) |
                (static_cast<uint32_t>(rec.data[k - 3]) << 16) |
                (static_cast<uint32_t>(rec.data[k - 2]) << 8) |
                static_cast<uint32_t>(rec.data[k - 1]);
            m.negative_ttl = (minimum < rec.ttl) ? minimum : rec.ttl;
            break;
        }

        return m;
    }

    inline Result<Message> parse_message(const byte_buffer& data, ParseLimits limits) {
        return parse_message(data.data(), data.size(), limits);
    }

    // -----------------------------------------------------------------------
    // Answer extraction
    // -----------------------------------------------------------------------

    inline Result<AddressAnswer> extract_addresses(const Message& msg,
                                                   RecordType want,
                                                   size_t max_cname_hops) {
        AddressAnswer out;

        if (want != RecordType::A && want != RecordType::AAAA) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::Resolve,
                         string("extract_addresses only handles A and AAAA")};
        }
        const size_t want_size = (want == RecordType::A) ? 4 : 16;

        // Names still worth following. A server may answer with the address
        // records directly, or with a CNAME chain ending in them.
        std::vector<string> pending;
        pending.push_back(msg.question_name);

        std::vector<string> visited;

        for (size_t hop = 0; hop <= max_cname_hops; ++hop) {
            bool progressed = false;

            for (const auto& rec : msg.answers) {
                if (rec.type != want) continue;
                if (rec.data.size() != want_size) continue;

                // Only take records whose owner is one of the names we follow.
                bool reachable = false;
                for (const auto& p : pending) {
                    if (detail::ascii_iequals(to_view(rec.name), to_view(p))) {
                        reachable = true;
                        break;
                    }
                }
                if (!reachable) continue;

                out.addresses.push_back(rec.data);
                out.ttls.push_back(rec.ttl);
                progressed = true;
            }
            if (!out.addresses.empty()) return out;

            // No address at this depth: walk one CNAME hop outward.
            std::vector<string> next;
            for (const auto& p : pending) {
                for (const auto& rec : msg.answers) {
                    if (rec.type != RecordType::CNAME) continue;
                    if (!detail::ascii_iequals(to_view(rec.name), to_view(p))) continue;

                    bool seen = false;
                    for (const auto& v : visited) {
                        if (detail::ascii_iequals(to_view(v), to_view(rec.cname_target))) {
                            seen = true;
                            break;
                        }
                    }
                    if (seen) {
                        out.loop_detected = true;
                        return out;
                    }
                    visited.push_back(rec.cname_target);
                    next.push_back(rec.cname_target);
                    progressed = true;
                }
            }
            if (next.empty()) break;
            out.cname_hops += 1;
            pending.swap(next);

            if (!progressed) break;
        }

        return out;
    }

    inline std::optional<uint32_t> min_ttl(const std::vector<Record>& records) {
        if (records.empty()) return std::nullopt;
        uint32_t m = records.front().ttl;
        for (const auto& r : records) {
            if (r.ttl < m) m = r.ttl;
        }
        return m;
    }

    inline std::optional<uint32_t> negative_cache_ttl(const Message& msg) {
        return msg.negative_ttl;
    }

} // namespace dns
} // namespace megohttp

#endif // MEGOHTTP_DNS_WIRE_IMPL_HPP_INCLUDED

#ifndef MEGOHTTP_DNS_WIRE_HPP_INCLUDED
#define MEGOHTTP_DNS_WIRE_HPP_INCLUDED

// ---------------------------------------------------------------------------
// DNS wire-format codec (task book section 9-A.5, phase 5A).
//
// Everything DoT and DoH need to speak DNS: build a query, parse a response,
// and validate every byte on the way in. This file has NO sockets and NO TLS --
// it is a pure codec, which is what makes every malformed-input rule testable
// byte by byte and gives the fuzzer something to chew on without a network.
//
// What the parser is strict about, and why each rule exists:
//   - Every read is bounds-checked. A DNS message is attacker-controlled input
//     arriving over a path the library chose to trust; an out-of-bounds read
//     here is a remote crash.
//   - Compression pointers may only point BACKWARDS and only once per offset
//     budget. A forward or self-referential pointer is a loop, and a loop in a
//     name parser is an infinite loop waiting for a timeout.
//   - Label length (<= 63) and total name length (<= 255) are enforced, because
//     the wire format cannot represent more and a parser that accepts it would
//     disagree with every server.
//   - Record types the library does not understand are SKIPPED by their RDLENGTH,
//     never guessed at.
//   - A truncated message is an error, not a partial success: handing back half
//     an answer set would make a resolver report a wrong address list.
//
// RCODEs are kept distinct (NXDOMAIN / NOERROR-no-data / SERVFAIL / REFUSED)
// because they drive different resolver behaviour: only NXDOMAIN is cacheable
// as "this name does not exist".
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <optional>
#include <vector>

namespace megohttp {

    namespace dns {

        // Record types this library can produce or consume. Anything else is
        // carried as Raw so a caller can inspect it without the parser guessing.
        enum class RecordType : uint16_t {
            A     = 1,
            CNAME = 5,
            SOA   = 6,
            AAAA  = 28,
            Opt   = 41,
            Raw   = 0xFFFF,   // not a wire value: internal marker
        };

        enum class RecordClass : uint16_t {
            In  = 1,
            Any = 255,
        };

        // RCODEs, including the two that are NOT errors in the resolver sense.
        enum class ResponseCode : int {
            NoError  = 0,   // answer present, or NOERROR/NODATA when empty
            FormErr  = 1,
            ServFail = 2,
            NxDomain = 3,
            NotImp   = 4,
            Refused  = 5,
            Unknown  = -1,
        };

        // One resource record. `data` holds the RDATA verbatim: for A/AAAA it is
        // the address bytes, for CNAME it is the DECODED target name (not the
        // compressed wire form), for anything else the raw bytes.
        struct Record {
            string name;                    // owner name, lowercased, no trailing dot
            RecordType type{RecordType::Raw};
            uint16_t raw_type{0};           // wire value, always set
            RecordClass klass{RecordClass::In};
            uint32_t ttl{0};
            byte_buffer data;               // A: 4 bytes, AAAA: 16, CNAME: decoded name
            string cname_target;            // filled only for type == CNAME
        };

        // A parsed response.
        struct Message {
            uint16_t id{0};
            bool is_response{false};
            bool truncated{false};          // TC bit: the answer set is incomplete
            bool recursion_available{false};
            bool recursion_desired{false};
            ResponseCode rcode{ResponseCode::NoError};

            // Question section (echoed back by the server).
            string question_name;
            uint16_t question_type{0};
            uint16_t question_class{0};

            std::vector<Record> answers;
            std::vector<Record> authorities;   // SOA here carries negative-cache TTL
            std::vector<Record> additionals;

            // TTL of the SOA in the authority section, when the response carried
            // one. This is what RFC 2308 negative caching keys off.
            std::optional<uint32_t> negative_ttl;
        };

        // -------------------------------------------------------------------
        // Building a query
        // -------------------------------------------------------------------

        // Encodes `name` as a sequence of length-prefixed labels. Rejects an
        // empty label, a label over 63 bytes and a total over 255 -- all three
        // are unrepresentable on the wire rather than merely unusual.
        Result<byte_buffer> encode_name(string_view name);

        // A single A or AAAA query with RD set. `id` is caller-chosen so a DoT
        // client can match responses to the query that produced them.
        Result<byte_buffer> build_query(uint16_t id, string_view name,
                                        RecordType type,
                                        RecordClass klass = RecordClass::In);

        // -------------------------------------------------------------------
        // Parsing a response
        // -------------------------------------------------------------------

        struct ParseLimits {
            // A name's compression pointer chain may not exceed this depth. Each
            // hop is a pointer; a chain longer than this is treated as a loop.
            size_t max_pointer_hops{32};
            // Upper bound on decoded name length (the wire limit is 255).
            size_t max_name_length{255};
            // Caps on section sizes so a hostile response cannot force unbounded
            // allocation before it fails.
            size_t max_records{512};
            // CNAME chain depth the caller cares about; the parser itself only
            // reports what is in the message.
            size_t max_records_total{1536};
        };

        // Parses a complete DNS message. Returns an error for anything that is
        // not a well-formed message: truncation, a pointer loop, an out-of-range
        // label, a section count that does not match the bytes present.
        //
        // A response whose RCODE is NXDOMAIN/SERVFAIL/REFUSED parses SUCCESSFULLY
        // -- it is a valid message that says "no" -- and the caller inspects
        // `rcode` to decide what to do. Conflating "malformed" with "server said
        // no" is how a NXDOMAIN ends up cached as a network error.
        Result<Message> parse_message(const uint8_t* data, size_t size,
                                      ParseLimits limits = {});

        // Convenience over a byte_buffer.
        Result<Message> parse_message(const byte_buffer& data,
                                      ParseLimits limits = {});

        // -------------------------------------------------------------------
        // Answer extraction
        // -------------------------------------------------------------------

        // Addresses of the requested type from the answer section, following a
        // CNAME chain. `chain_depth_out` reports how many CNAMEs were walked so
        // the caller can detect a chain that hit its own limit.
        //
        // Returns an empty list when the message is valid but carries no address
        // (NODATA) -- distinct from an error, which means the message was
        // unreadable.
        struct AddressAnswer {
            std::vector<byte_buffer> addresses;   // 4 or 16 bytes each
            std::vector<uint32_t> ttls;           // parallel to `addresses`
            size_t cname_hops{0};
            bool loop_detected{false};
        };

        Result<AddressAnswer> extract_addresses(const Message& msg,
                                                RecordType want,
                                                size_t max_cname_hops = 8);

        // Lowest TTL across a record set, for caching. nullopt when empty.
        std::optional<uint32_t> min_ttl(const std::vector<Record>& records);

        // Negative-cache TTL per RFC 2308: SOA's MINIMUM field, capped by the
        // SOA record's own TTL. nullopt when the message carried no SOA.
        std::optional<uint32_t> negative_cache_ttl(const Message& msg);

    } // namespace dns

} // namespace megohttp

#include <megohttp/dns_wire_impl.hpp>

#endif // MEGOHTTP_DNS_WIRE_HPP_INCLUDED

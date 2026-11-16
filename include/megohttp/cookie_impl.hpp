#ifndef MEGOHTTP_COOKIE_IMPL_HPP_INCLUDED
#define MEGOHTTP_COOKIE_IMPL_HPP_INCLUDED

// Implementation of include/megohttp/cookie.hpp. Included at the bottom of
// that header; not meant to be included directly.

#include <megohttp/string_adapter.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <ctime>
#include <mutex>
#include <unordered_map>
#include <utility>

#if MEGOHTTP_HAS_MEMESTRING
// std::hash<memepp::string> lives in its own header and is NOT pulled in by
// string.hpp. Without it, unordered_map<string, ...> fails to instantiate.
#  include <memepp/hash/std/hash.hpp>
#endif

namespace megohttp {
namespace cookie_detail {

    // ------------------------------------------------------------------
    // Built-in Public Suffix List snapshot
    //
    // This is a COMPRESSED SNAPSHOT, not the complete PSL: the full list is
    // ~230 KB and changes weekly, which does not belong in a header. It covers
    // the ICANN section's shape -- every single-label TLD is a suffix, and the
    // multi-label entries below are the ones that actually appear in practice.
    //
    // What this means in practice:
    //   - Domain=com, Domain=co.uk, Domain=example.github.io are all rejected.
    //   - An obscure multi-label suffix missing here would be treated as
    //     registrable, which is the permissive direction of that error.
    //
    // A caller that needs the real list installs it with
    // set_public_suffix_data(loaded_file). Version is reported so a deployment
    // can tell which snapshot it is running against.
    // ------------------------------------------------------------------

    inline string_view builtin_public_suffix_version() noexcept {
        return string_view("embedded-2026.1");
    }

    inline string_view builtin_public_suffix_data() noexcept {
        // Single-label TLDs are handled structurally (any host with one label is
        // a suffix), so only multi-label suffixes are listed. Wildcards use the
        // PSL "*.x" form; exceptions use "!y.x".
        static const char kData[] =
            // United Kingdom
            "co.uk\norg.uk\nme.uk\nac.uk\ngov.uk\nnet.uk\nltd.uk\nplc.uk\n"
            // Australia
            "com.au\nnet.au\norg.au\nedu.au\ngov.au\nid.au\nasn.au\n"
            // New Zealand
            "co.nz\nnet.nz\norg.nz\ngovt.nz\nac.nz\nschool.nz\n"
            // Japan
            "co.jp\nne.jp\nor.jp\nac.jp\ngo.jp\ned.jp\ngr.jp\nlg.jp\n"
            // China
            "com.cn\nnet.cn\norg.cn\ngov.cn\nedu.cn\nac.cn\n"
            // Hong Kong
            "com.hk\nnet.hk\norg.hk\ngov.hk\nedu.hk\nidv.hk\n"
            // Taiwan
            "com.tw\nnet.tw\norg.tw\ngov.tw\nedu.tw\nidv.tw\n"
            // Korea
            "co.kr\nne.kr\nor.kr\nre.kr\npe.kr\ngo.kr\nmil.kr\nac.kr\n"
            // Singapore
            "com.sg\nnet.sg\norg.sg\ngov.sg\nedu.sg\nper.sg\n"
            // India
            "co.in\nnet.in\norg.in\nfirm.in\ngen.in\nind.in\nac.in\nedu.in\n"
            "res.in\ngov.in\n"
            // Brazil
            "com.br\nnet.br\norg.br\ngov.br\nedu.br\nart.br\nblog.br\n"
            // Mexico
            "com.mx\nnet.mx\norg.mx\ngob.mx\nedu.mx\n"
            // Argentina
            "com.ar\nnet.ar\norg.ar\ngob.ar\nedu.ar\n"
            // South Africa
            "co.za\nnet.za\norg.za\ngov.za\nac.za\nweb.za\n"
            // Turkey
            "com.tr\nnet.tr\norg.tr\ngov.tr\nedu.tr\n"
            // Russia
            "com.ru\nnet.ru\norg.ru\npp.ru\nmsk.ru\nspb.ru\n"
            // Ukraine
            "com.ua\nnet.ua\norg.ua\nkiev.ua\n"
            // Poland
            "com.pl\nnet.pl\norg.pl\ngov.pl\ninfo.pl\n"
            // Germany / Austria / Switzerland use single-label ccTLDs only.
            // Netherlands
            "co.nl\n"
            // Israel
            "co.il\nnet.il\norg.il\nac.il\ngov.il\n"
            // Indonesia
            "co.id\nnet.id\nor.id\nweb.id\nac.id\ngo.id\n"
            // Malaysia
            "com.my\nnet.my\norg.my\ngov.my\nedu.my\n"
            // Thailand
            "co.th\nin.th\nor.th\nac.th\ngo.th\n"
            // Vietnam
            "com.vn\nnet.vn\norg.vn\ngov.vn\nedu.vn\n"
            // Philippines
            "com.ph\nnet.ph\norg.ph\ngov.ph\nedu.ph\n"
            // Pakistan
            "com.pk\nnet.pk\norg.pk\ngov.pk\nedu.pk\n"
            // Egypt / Saudi / UAE
            "com.eg\nnet.eg\norg.eg\ngov.eg\nedu.eg\n"
            "com.sa\nnet.sa\norg.sa\ngov.sa\nedu.sa\nmed.sa\npub.sa\n"
            "co.ae\nnet.ae\norg.ae\nac.ae\ngov.ae\n"
            // GitHub Pages and the hosting suffixes that matter most in practice
            "github.io\ngithubusercontent.com\n"
            "herokuapp.com\nnetlify.app\nvercel.app\n"
            "pages.dev\nworkers.dev\nblogspot.com\n"
            "cloudfront.net\nazurewebsites.net\nappspot.com\n"
            "s3.amazonaws.com\nelasticbeanstalk.com\n"
            // Wildcard + exception example, kept because RFC 6265 tests use it
            "*.ck\n!www.ck\n";
        return string_view(kData, sizeof kData - 1);
    }

    // Rule set. Rebuilt wholesale on set_public_suffix_data(), read under the
    // same mutex the jar uses, so no lock is needed here: the functions below
    // are called from the jar while it already holds its own lock, and the
    // install path swaps the whole table atomically.
    struct PslRules {
        std::vector<string> rules;      // lowercased, no leading dot
        std::vector<string> wildcards;  // "ck" from "*.ck"
        std::vector<string> exceptions; // "www.ck" from "!www.ck"
        string version;
    };

    inline std::unique_ptr<PslRules>& psl_slot() {
        static std::unique_ptr<PslRules> slot = [] {
            auto r = std::make_unique<PslRules>();
            r->version = "embedded";
            return r;
        }();
        return slot;
    }

    // Loads the built-in snapshot on first use. is_public_suffix() /
    // registrable_domain() are public entry points that a caller can reach
    // without constructing a CookieJar, so they cannot rely on the jar to have
    // triggered the load. Defined below, after reset_public_suffix_data().
    void load_builtin_psl_once();

    inline std::mutex& psl_mutex() {
        static std::mutex m;
        return m;
    }

    inline void load_psl_into(PslRules& out, string_view data) {
        out.rules.clear();
        out.wildcards.clear();
        out.exceptions.clear();

        string_view rest = data;
        while (!rest.empty()) {
            const size_t nl = rest.find('\n');
            string_view line = (nl == string_view::npos)
                                   ? rest
                                   : string_view(rest.data(), nl);
            rest = (nl == string_view::npos)
                       ? string_view()
                       : string_view(rest.data() + nl + 1, rest.size() - nl - 1);

            // Trim CR and surrounding whitespace, skip blanks and // comments.
            while (!line.empty() &&
                   (line.data()[0] == ' ' || line.data()[0] == '\t')) {
                line = string_view(line.data() + 1, line.size() - 1);
            }
            while (!line.empty()) {
                const char c = line.data()[line.size() - 1];
                if (c == '\r' || c == ' ' || c == '\t') {
                    line = string_view(line.data(), line.size() - 1);
                } else {
                    break;
                }
            }
            if (line.empty() || line.data()[0] == '/') continue;

            string entry;
            {
                string_builder b;
                for (size_t i = 0; i < static_cast<size_t>(line.size()); ++i) {
                    char c = line.data()[i];
                    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                    detail::sb_append(b, c);
                }
                entry = b.release();
            }

            if (entry.empty()) continue;
            if (entry.data()[0] == '!') {
                out.exceptions.push_back(to_string(entry.data() + 1, entry.size() - 1));
            } else if (entry.size() >= 2 && entry.data()[0] == '*' &&
                       entry.data()[1] == '.') {
                out.wildcards.push_back(to_string(entry.data() + 2, entry.size() - 2));
            } else {
                out.rules.push_back(std::move(entry));
            }
        }
    }

    inline void set_public_suffix_data(string_view data) {
        if (data.empty()) return;
        auto fresh = std::make_unique<PslRules>();
        fresh->version = "custom";
        load_psl_into(*fresh, data);
        if (fresh->rules.empty() && fresh->wildcards.empty() &&
            fresh->exceptions.empty()) {
            // Unparsable input: leave what is already installed alone rather
            // than silently disabling the protection.
            return;
        }
        std::lock_guard<std::mutex> g(psl_mutex());
        psl_slot() = std::move(fresh);
    }

    inline void reset_public_suffix_data() {
        auto fresh = std::make_unique<PslRules>();
        fresh->version = to_string(builtin_public_suffix_version());
        load_psl_into(*fresh, builtin_public_suffix_data());
        std::lock_guard<std::mutex> g(psl_mutex());
        psl_slot() = std::move(fresh);
    }

    // One-time install of the built-in snapshot. Called by the public query
    // functions so a caller that never constructs a CookieJar still gets the
    // protection. std::call_once makes the cost a single atomic load.
    inline void load_builtin_psl_once() {
        static std::once_flag once;
        std::call_once(once, [] { reset_public_suffix_data(); });
    }

    inline string public_suffix_version() {
        load_builtin_psl_once();
        std::lock_guard<std::mutex> g(psl_mutex());
        return psl_slot()->version;
    }

    // Counts labels: "a.b.c" -> 3.
    inline size_t label_count(string_view host) noexcept {
        if (host.empty()) return 0;
        size_t n = 1;
        for (size_t i = 0; i < static_cast<size_t>(host.size()); ++i) {
            if (host.data()[i] == '.') ++n;
        }
        return n;
    }

    inline bool psl_contains(const std::vector<string>& v, string_view needle) {
        for (const auto& e : v) {
            if (detail::ascii_iequals(to_view(e), needle)) return true;
        }
        return false;
    }

    // True when `domain` may not be used as a cookie Domain.
    inline bool is_public_suffix(string_view domain) {
        load_builtin_psl_once();

        if (domain.empty()) return true;

        // Normalize a leading dot away: ".example.com" is the same name.
        string_view d = domain;
        if (d.data()[0] == '.') {
            d = string_view(d.data() + 1, d.size() - 1);
        }
        if (d.empty()) return true;

        // A single label is always a suffix (every TLD is).
        if (label_count(d) <= 1) return true;

        std::lock_guard<std::mutex> g(psl_mutex());
        const PslRules& r = *psl_slot();

        // Exception rules win: "!www.ck" means www.ck is registrable.
        if (psl_contains(r.exceptions, d)) return false;

        if (psl_contains(r.rules, d)) return true;

        // A wildcard "*.ck" makes every "<label>.ck" a suffix. Comparing the
        // part after the first label is what implements that.
        for (const auto& w : r.wildcards) {
            if (d.size() > w.size() + 1) {
                const string_view tail(d.data() + (d.size() - w.size()),
                                       w.size());
                if (detail::ascii_iequals(tail, to_view(w)) &&
                    d.data()[d.size() - w.size() - 1] == '.') {
                    // "<x>.ck" is a suffix, but a longer name is not.
                    if (label_count(d) == label_count(to_view(w)) + 1) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    inline string registrable_domain(string_view host) {
        string_view h = host;
        if (!h.empty() && h.data()[0] == '.') {
            h = string_view(h.data() + 1, h.size() - 1);
        }
        const size_t labels = label_count(h);
        if (labels == 0) return string();

        // The public suffix is the LONGEST suffix of the host that is on the
        // list; the registrable domain is that suffix plus one more label.
        // Walk from the full name inward until the candidate stops being a
        // suffix, then keep the last candidate that WAS a suffix.
        size_t suffix_labels = 0;
        for (size_t keep = labels; keep >= 1; --keep) {
            // The candidate is the last `keep` labels of h.
            size_t pos = 0;
            size_t seen_dots = 0;
            while (pos < static_cast<size_t>(h.size()) &&
                   seen_dots < labels - keep) {
                if (h.data()[pos] == '.') ++seen_dots;
                ++pos;
            }
            const string_view candidate(h.data() + pos, h.size() - pos);
            if (is_public_suffix(candidate)) {
                suffix_labels = keep;
                break;
            }
        }

        // A host that IS a suffix has no registrable domain.
        if (suffix_labels == 0 || suffix_labels >= labels) return string();

        // Return the suffix plus the label immediately to its left.
        const size_t want = suffix_labels + 1;
        size_t pos = 0;
        size_t seen_dots = 0;
        while (pos < static_cast<size_t>(h.size()) && seen_dots < labels - want) {
            if (h.data()[pos] == '.') ++seen_dots;
            ++pos;
        }
        return to_string(string_view(h.data() + pos, h.size() - pos));
    }

    // ------------------------------------------------------------------
    // Matching
    // ------------------------------------------------------------------

    inline bool domain_matches(string_view host, string_view domain) noexcept {
        if (domain.empty()) return false;

        string_view h = host;
        string_view d = domain;
        if (!d.empty() && d.data()[0] == '.') {
            d = string_view(d.data() + 1, d.size() - 1);
        }
        if (d.empty()) return false;

        if (detail::ascii_iequals(h, d)) return true;

        // The dot is part of the comparison: "xample.com" must not match
        // "example.com", which is what a bare ends_with would allow.
        if (h.size() <= d.size()) return false;
        const size_t off = static_cast<size_t>(h.size()) - static_cast<size_t>(d.size());
        if (h.data()[off - 1] != '.') return false;
        return detail::ascii_iequals(string_view(h.data() + off, d.size()), d);
    }

    inline bool path_matches(string_view path, string_view cookie_path) noexcept {
        if (cookie_path.empty()) return false;
        if (path.empty()) return false;

        // Identical, or the request path starts with the cookie path AND the
        // next character is a separator. "/a" must not match "/ab".
        if (path.size() >= cookie_path.size()) {
            const string_view head(path.data(), cookie_path.size());
            if (detail::ascii_iequals(head, cookie_path)) {
                if (path.size() == cookie_path.size()) return true;
                if (cookie_path.data()[cookie_path.size() - 1] == '/') return true;
                if (path.data()[cookie_path.size()] == '/') return true;
            }
        }
        return false;
    }

    inline string default_cookie_path(string_view path) {
        if (path.empty() || path.data()[0] != '/') {
            return string("/");
        }
        // Everything up to, but excluding, the rightmost '/'.
        size_t last = static_cast<size_t>(path.size());
        while (last > 0 && path.data()[last - 1] != '/') --last;
        if (last <= 1) return string("/");
        return to_string(string_view(path.data(), last - 1));
    }

    // ------------------------------------------------------------------
    // Cookie date parsing (RFC 6265 5.1.1)
    //
    // The grammar accepts day-of-month, month name, year in any order, which in
    // practice means three formats:
    //   Sun, 06 Nov 1994 08:49:37 GMT     (IMF-fixdate)
    //   Sunday, 06-Nov-94 08:49:37 GMT    (RFC 850, two-digit year)
    //   Sun Nov  6 08:49:37 1994          (asctime)
    // ------------------------------------------------------------------

    namespace date_detail {

        inline bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
        inline bool is_alpha(char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        // Month names, first three letters, case-insensitive.
        inline int month_from(string_view tok) noexcept {
            if (tok.size() < 3) return -1;
            char a = tok.data()[0];
            char b = tok.data()[1];
            char c = tok.data()[2];
            auto lo = [](char x) {
                return static_cast<char>((x >= 'A' && x <= 'Z') ? x - 'A' + 'a' : x);
            };
            a = lo(a); b = lo(b); c = lo(c);
            if (a == 'j' && b == 'a' && c == 'n') return 1;
            if (a == 'f' && b == 'e' && c == 'b') return 2;
            if (a == 'm' && b == 'a' && c == 'r') return 3;
            if (a == 'a' && b == 'p' && c == 'r') return 4;
            if (a == 'm' && b == 'a' && c == 'y') return 5;
            if (a == 'j' && b == 'u' && c == 'n') return 6;
            if (a == 'j' && b == 'u' && c == 'l') return 7;
            if (a == 'a' && b == 'u' && c == 'g') return 8;
            if (a == 's' && b == 'e' && c == 'p') return 9;
            if (a == 'o' && b == 'c' && c == 't') return 10;
            if (a == 'n' && b == 'o' && c == 'v') return 11;
            if (a == 'd' && b == 'e' && c == 'c') return 12;
            return -1;
        }

        // Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
        // Integer-only, no tables, valid for the whole proleptic Gregorian range
        // a cookie can express.
        inline int64_t days_from_civil(int64_t y, int m, int d) noexcept {
            y -= (m <= 2) ? 1 : 0;
            const int64_t era = (y >= 0 ? y : y - 399) / 400;
            const int64_t yoe = y - era * 400;                       // [0, 399]
            const int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
            const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            return era * 146097 + doe - 719468;
        }

        inline bool leap(int64_t y) noexcept {
            return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        }

        inline int days_in_month(int64_t y, int m) noexcept {
            static const int k[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
            if (m < 1 || m > 12) return 0;
            if (m == 2 && leap(y)) return 29;
            return k[m - 1];
        }

    } // namespace date_detail

    inline std::optional<int64_t> parse_cookie_date(string_view text) noexcept {
        using namespace date_detail;

        const size_t n = static_cast<size_t>(text.size());
        if (n == 0 || n > 256) return std::nullopt;

        // 1. Pull out the time as "HH:MM:SS". It is the one element whose shape
        //    is unambiguous, so finding it first removes the need to guess which
        //    bare number is the day and which is a two-digit year.
        int hh = -1, mm = -1, ss = -1;
        size_t time_at = string_view::npos;
        for (size_t i = 0; i + 7 < n; ++i) {
            if (is_digit(text.data()[i]) && is_digit(text.data()[i + 1]) &&
                text.data()[i + 2] == ':' &&
                is_digit(text.data()[i + 3]) && is_digit(text.data()[i + 4]) &&
                text.data()[i + 5] == ':' &&
                is_digit(text.data()[i + 6]) && is_digit(text.data()[i + 7])) {
                hh = (text.data()[i] - '0') * 10 + (text.data()[i + 1] - '0');
                mm = (text.data()[i + 3] - '0') * 10 + (text.data()[i + 4] - '0');
                ss = (text.data()[i + 6] - '0') * 10 + (text.data()[i + 7] - '0');
                time_at = i;
                break;
            }
        }
        if (time_at == string_view::npos) return std::nullopt;
        if (hh > 23 || mm > 59 || ss > 60) return std::nullopt;

        // 2. Scan the rest as tokens, treating the time group as consumed.
        int day = -1, month = -1;
        int64_t year = -1;
        std::vector<int64_t> bare_numbers;   // 1-2 digit numbers outside the time

        size_t i = 0;
        while (i < n) {
            if (i == time_at) { i += 8; continue; }
            const char c = text.data()[i];
            if (c == ' ' || c == '\t' || c == ',' || c == '-' || c == ':' ||
                c == '(' || c == ')') {
                ++i;
                continue;
            }
            const size_t start = i;
            const bool numeric = is_digit(c);
            while (i < n) {
                if (i == time_at) break;
                const char x = text.data()[i];
                if (x == ' ' || x == '\t' || x == ',' || x == '-' || x == ':' ||
                    x == '(' || x == ')') {
                    break;
                }
                if (numeric != is_digit(x)) break;
                ++i;
            }
            if (i == start) { ++i; continue; }
            const string_view tok(text.data() + start, i - start);

            if (numeric) {
                int64_t v = 0;
                bool ok = true;
                for (size_t k = 0; k < static_cast<size_t>(tok.size()); ++k) {
                    if (!is_digit(tok.data()[k])) { ok = false; break; }
                    v = v * 10 + (tok.data()[k] - '0');
                    if (v > 999999) { ok = false; break; }
                }
                if (!ok) continue;
                if (tok.size() >= 3) {
                    // A 4-digit (or longer) run is the year.
                    year = v;
                } else {
                    bare_numbers.push_back(v);
                }
            } else {
                const int m = month_from(tok);
                if (m > 0 && month < 0) month = m;
                // Weekday names and "GMT" fall through and are ignored.
            }
        }

        // 3. A 4-digit year was found above. Otherwise the smallest 1-2 digit
        //    number that is larger than 31 is the year: "94" in RFC 850. If
        //    nothing qualifies, the numbers are (day, year-with-no-space) and the
        //    last one is the year.
        if (year < 0 && !bare_numbers.empty()) {
            for (size_t k = 0; k < bare_numbers.size(); ++k) {
                if (bare_numbers[k] > 31) {
                    year = bare_numbers[k] < 100
                               ? (bare_numbers[k] <= 69 ? 2000 + bare_numbers[k]
                                                        : 1900 + bare_numbers[k])
                               : -1;
                    if (year > 0) {
                        bare_numbers.erase(bare_numbers.begin() +
                                           static_cast<std::ptrdiff_t>(k));
                    }
                    break;
                }
            }
        }
        if (day < 0) {
            for (size_t k = 0; k < bare_numbers.size(); ++k) {
                if (bare_numbers[k] >= 1 && bare_numbers[k] <= 31) {
                    day = static_cast<int>(bare_numbers[k]);
                    break;
                }
            }
        }

        if (day < 1 || day > 31) return std::nullopt;
        if (month < 1 || month > 12) return std::nullopt;
        if (year < 1601) return std::nullopt;
        if (day > days_in_month(year, month)) return std::nullopt;

        const int64_t days = days_from_civil(year, month, day);
        return days * 86400 + hh * 3600 + mm * 60 + ss;
    }

    // Runs the built-in snapshot once, at first use.
    inline void ensure_psl_loaded() {
        load_builtin_psl_once();
    }

} // namespace cookie_detail

// ---------------------------------------------------------------------------
// SetCookie / parsing
// ---------------------------------------------------------------------------

inline VoidResult SetCookie::validate() const {
    if (name.empty()) {
        return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                     string("cookie name is empty")};
    }
    // A name or value with a control character would corrupt the Cookie header
    // and could smuggle a CRLF into the next request (RFC 6265 4.1.1).
    for (size_t i = 0; i < static_cast<size_t>(name.size()); ++i) {
        const unsigned char c = static_cast<unsigned char>(name.data()[i]);
        if (c <= 0x20 || c == 0x7F || c == ';' || c == ',') {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("cookie name contains an illegal character")};
        }
    }
    for (size_t i = 0; i < static_cast<size_t>(value.size()); ++i) {
        const unsigned char c = static_cast<unsigned char>(value.data()[i]);
        if (c < 0x20 || c == 0x7F) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("cookie value contains a control character")};
        }
    }
    return VoidResult{};
}

namespace cookie_detail {

    inline bool is_ows(char c) noexcept { return c == ' ' || c == '\t'; }

    inline string_view trim_ows(string_view s) noexcept {
        size_t b = 0;
        size_t e = static_cast<size_t>(s.size());
        while (b < e && is_ows(s.data()[b])) ++b;
        while (e > b && is_ows(s.data()[e - 1])) --e;
        return string_view(s.data() + b, e - b);
    }

    inline string lower_copy(string_view s) {
        string_builder b;
        for (size_t i = 0; i < static_cast<size_t>(s.size()); ++i) {
            char c = s.data()[i];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            detail::sb_append(b, c);
        }
        return b.release();
    }

} // namespace cookie_detail

inline Result<SetCookie> parse_set_cookie(string_view header_value) {
    using namespace cookie_detail;

    const string_view whole = trim_ows(header_value);
    if (whole.empty()) {
        return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                     string("Set-Cookie header is empty")};
    }

    // First ';' ends the name=value pair; the rest are attributes.
    const size_t semi = whole.find(';');
    const string_view pair = (semi == string_view::npos)
                                 ? whole
                                 : trim_ows(string_view(whole.data(), semi));

    const size_t eq = pair.find('=');
    if (eq == string_view::npos) {
        return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                     string("Set-Cookie has no name=value pair")};
    }

    SetCookie c;
    c.name = to_string(trim_ows(string_view(pair.data(), eq)));
    c.value = to_string(trim_ows(string_view(pair.data() + eq + 1,
                                             pair.size() - eq - 1)));

    // Attributes.
    string_view rest = (semi == string_view::npos)
                           ? string_view()
                           : string_view(whole.data() + semi + 1,
                                         whole.size() - semi - 1);

    while (!rest.empty()) {
        const size_t sep = rest.find(';');
        const string_view attr = (sep == string_view::npos)
                                     ? trim_ows(rest)
                                     : trim_ows(string_view(rest.data(), sep));
        rest = (sep == string_view::npos)
                   ? string_view()
                   : string_view(rest.data() + sep + 1, rest.size() - sep - 1);
        if (attr.empty()) continue;

        const size_t aeq = attr.find('=');
        const string_view aname = (aeq == string_view::npos)
                                      ? attr
                                      : trim_ows(string_view(attr.data(), aeq));
        const string_view aval = (aeq == string_view::npos)
                                     ? string_view()
                                     : trim_ows(string_view(attr.data() + aeq + 1,
                                                            attr.size() - aeq - 1));

        if (detail::ascii_iequals(aname, "domain")) {
            if (!aval.empty()) {
                string_view d = aval;
                if (d.data()[0] == '.') {
                    d = string_view(d.data() + 1, d.size() - 1);
                }
                if (!d.empty()) c.domain = lower_copy(d);
            }
        } else if (detail::ascii_iequals(aname, "path")) {
            if (!aval.empty() && aval.data()[0] == '/') {
                c.path = to_string(aval);
            }
        } else if (detail::ascii_iequals(aname, "expires")) {
            // The value contains a comma and spaces, so it must be taken whole.
            if (const auto t = parse_cookie_date(aval)) {
                c.expires_at = *t;
            }
        } else if (detail::ascii_iequals(aname, "max-age")) {
            // Max-Age wins over Expires when both are present (RFC 6265 5.3).
            // A leading '-' means delete; a non-numeric value is ignored.
            bool negative = false;
            string_view num = aval;
            if (!num.empty() && (num.data()[0] == '-' || num.data()[0] == '+')) {
                negative = (num.data()[0] == '-');
                num = string_view(num.data() + 1, num.size() - 1);
            }
            int64_t v = 0;
            bool ok = !num.empty();
            for (size_t i = 0; i < static_cast<size_t>(num.size()); ++i) {
                const char ch = num.data()[i];
                if (ch < '0' || ch > '9') { ok = false; break; }
                if (v > 100000000) { ok = false; break; }
                v = v * 10 + (ch - '0');
            }
            if (ok) {
                c.has_max_age = true;
                if (negative || v == 0) {
                    // Max-Age <= 0 is a deletion instruction.
                    c.is_deletion = true;
                    c.expires_at = int64_t(0);
                } else {
                    // Relative to now. std::time is used only here, because the
                    // attribute is defined relative to the current time.
                    const int64_t now = static_cast<int64_t>(std::time(nullptr));
                    c.expires_at = now + v;
                }
            }
        } else if (detail::ascii_iequals(aname, "secure")) {
            c.secure = true;
        } else if (detail::ascii_iequals(aname, "httponly")) {
            c.http_only = true;
        } else if (detail::ascii_iequals(aname, "samesite")) {
            if (!aval.empty()) c.same_site = to_string(aval);
        }
        // Unknown attributes are ignored, as RFC 6265 5.2 requires.
    }

    // An Expires in the past is also a deletion (checked only when Max-Age did
    // not already decide, because Max-Age wins).
    if (!c.has_max_age && c.expires_at.has_value()) {
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (*c.expires_at <= now) c.is_deletion = true;
    }

    if (const auto v = c.validate(); !v) return v.error();
    return c;
}

inline string build_cookie_header(const std::vector<SetCookie>& cookies) {
    if (cookies.empty()) return string();
    string_builder b;
    bool first = true;
    for (const auto& c : cookies) {
        if (!first) detail::sb_append(b, "; ");
        first = false;
        detail::sb_append(b, to_view(c.name));
        detail::sb_append(b, '=');
        detail::sb_append(b, to_view(c.value));
    }
    return b.release();
}

// ---------------------------------------------------------------------------
// CookieJar
// ---------------------------------------------------------------------------

struct CookieJar::Impl {
    Limits limits;
    mutable std::mutex mu;

    struct Entry {
        SetCookie cookie;
        string domain;              // normalized, lowercase, no leading dot
        bool host_only{true};
        int64_t created_seq{0};
    };

    // Grouped by normalized domain so the per-domain cap is a size() check and
    // the retrieval path does not scan unrelated domains.
    std::unordered_map<string, std::vector<Entry>> by_domain;
    int64_t next_seq{0};

    Impl() { cookie_detail::ensure_psl_loaded(); }
    explicit Impl(Limits l) : limits(l) { cookie_detail::ensure_psl_loaded(); }

    static size_t total_locked(const std::unordered_map<string, std::vector<Entry>>& m) {
        size_t n = 0;
        for (const auto& kv : m) n += kv.second.size();
        return n;
    }

    static bool same_cookie(const Entry& e, const SetCookie& c,
                            string_view domain, bool host_only) {
        return e.cookie.name == c.name && e.domain == domain &&
               e.host_only == host_only &&
               e.cookie.path.value_or(string()) == c.path.value_or(string());
    }

    void erase_matching_locked(const std::unordered_map<string, std::vector<Entry>>::iterator& it,
                               const SetCookie& c, string_view domain, bool host_only) {
        auto& v = it->second;
        for (auto j = v.begin(); j != v.end(); ++j) {
            if (same_cookie(*j, c, domain, host_only)) {
                v.erase(j);
                return;
            }
        }
        if (v.empty()) by_domain.erase(it);
    }

    // Evicts the soonest-to-expire entry in a domain bucket. Session cookies
    // (no expiry) sort last: they are the ones a caller most likely still wants,
    // and they cannot be reasoned about by deadline.
    void evict_one_locked(std::vector<Entry>& v) {
        if (v.empty()) return;
        size_t best = 0;
        bool best_found = false;
        int64_t best_at = 0;
        for (size_t i = 0; i < v.size(); ++i) {
            if (!v[i].cookie.expires_at.has_value()) continue;
            const int64_t at = *v[i].cookie.expires_at;
            if (!best_found || at < best_at) {
                best = i;
                best_at = at;
                best_found = true;
            }
        }
        if (!best_found) best = 0;   // all session cookies: drop the oldest
        v.erase(v.begin() + static_cast<std::ptrdiff_t>(best));
    }
};

inline CookieJar::CookieJar() : impl_(std::make_unique<Impl>()) {}
inline CookieJar::CookieJar(Limits limits) : impl_(std::make_unique<Impl>(limits)) {}
inline CookieJar::~CookieJar() = default;

inline VoidResult CookieJar::set_from_header(const Url& url, string_view set_cookie_header) {
    auto parsed = parse_set_cookie(set_cookie_header);
    if (!parsed) return parsed.error();
    return set(url, parsed.value());
}

inline VoidResult CookieJar::set(const Url& url, const SetCookie& cookie) {
    using namespace cookie_detail;

    if (const auto v = cookie.validate(); !v) return v.error();

    const string_view host = to_view(url.host);

    // --- Domain decision (RFC 6265 5.3) ---
    string domain;
    bool host_only = true;

    if (cookie.domain.has_value() && !cookie.domain->empty()) {
        const string_view d = to_view(*cookie.domain);

        // A cookie may only be set for a domain the request host belongs to.
        // "evil.com" answering for "example.com" cannot set Domain=example.com.
        if (!domain_matches(host, d)) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("cookie Domain is not the request host or a parent of it")};
        }

        // A public suffix is not a legal Domain: Domain=com would be received
        // by every .com host. This is the PSL's whole purpose here.
        if (is_public_suffix(d)) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("cookie Domain is a public suffix")};
        }

        // An IP literal has no domain hierarchy: Domain= is ignored and the
        // cookie stays host-only.
        if (url.is_ip_literal) {
            domain = to_string(host);
            host_only = true;
        } else {
            domain = to_string(d);
            host_only = false;
        }
    } else {
        domain = to_string(host);
        host_only = true;
    }

    // --- Secure decision ---
    // A Secure cookie from an insecure response is refused outright (RFC 6265
    // 5.3 step 10): the response could have been tampered with on the way.
    if (cookie.secure && !url.is_secure()) {
        return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                     string("Secure cookie received over an insecure connection")};
    }

    SetCookie stored = cookie;
    if (!stored.path.has_value() || stored.path->empty() ||
        stored.path->data()[0] != '/') {
        stored.path = default_cookie_path(to_view(url.path));
    }
    // A stored entry is never a deletion marker, even when the call came in as
    // one: the deletion branch below reads `cookie.is_deletion` (the caller's
    // value) and only stores non-deletions. This line makes that explicit so the
    // entry that goes into the bucket cannot carry a stale flag.
    stored.is_deletion = false;

    if (static_cast<size_t>(stored.name.size() + stored.value.size()) >
        impl_->limits.max_cookie_bytes) {
        return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                     string("cookie exceeds the configured size limit")};
    }

    std::lock_guard<std::mutex> g(impl_->mu);

    auto it = impl_->by_domain.find(domain);
    if (it == impl_->by_domain.end()) {
        it = impl_->by_domain.emplace(domain, std::vector<Impl::Entry>{}).first;
    }
    auto& bucket = it->second;

    // A deletion removes the matching cookie and stores nothing.
    if (cookie.is_deletion) {
        impl_->erase_matching_locked(it, stored, to_view(domain), host_only);
        return VoidResult{};
    }

    // Replace an existing cookie with the same (name, domain, path, host_only).
    for (auto& e : bucket) {
        if (Impl::same_cookie(e, stored, to_view(domain), host_only)) {
            e.cookie = stored;
            e.cookie.is_deletion = false;
            return VoidResult{};
        }
    }

    // Enforce the per-domain cap by eviction, not rejection: a site that sets
    // many cookies must not be able to break its own later cookies.
    while (bucket.size() >= impl_->limits.max_cookies_per_domain) {
        impl_->evict_one_locked(bucket);
    }

    // Enforce the global cap the same way.
    while (Impl::total_locked(impl_->by_domain) >= impl_->limits.max_cookies_total) {
        bool evicted = false;
        for (auto& kv : impl_->by_domain) {
            if (!kv.second.empty()) {
                impl_->evict_one_locked(kv.second);
                evicted = true;
                break;
            }
        }
        if (!evicted) break;
    }

    Impl::Entry e;
    e.cookie = std::move(stored);
    e.domain = domain;
    e.host_only = host_only;
    e.created_seq = impl_->next_seq++;
    bucket.push_back(std::move(e));
    return VoidResult{};
}

inline std::vector<SetCookie> CookieJar::get(const Url& url) const {
    using namespace cookie_detail;

    const string_view host = to_view(url.host);
    const string_view path = to_view(url.path);
    const bool secure = url.is_secure();

    std::vector<Impl::Entry> entries;
    {
        std::lock_guard<std::mutex> g(impl_->mu);
        for (const auto& kv : impl_->by_domain) {
            for (const auto& e : kv.second) {
                // Host-only cookies go to exactly that host; Domain cookies go
                // to the domain and its subdomains.
                if (e.host_only) {
                    if (!detail::ascii_iequals(host, to_view(e.domain))) continue;
                } else {
                    if (!domain_matches(host, to_view(e.domain))) continue;
                }

                if (!path_matches(path, to_view(e.cookie.path.value_or(string("/"))))) {
                    continue;
                }

                // Secure is decided by the TARGET url ONLY. An HTTPS proxy in
                // front of an http:// target leaves the target hop in cleartext,
                // so its Secure cookies must not be sent (task book 10.3).
                if (e.cookie.secure && !secure) continue;

                entries.push_back(e);
            }
        }
    }

    // More specific paths first; ties broken by creation order, oldest first,
    // so a stable order exists for tests and for servers that care.
    std::sort(entries.begin(), entries.end(),
              [](const Impl::Entry& a, const Impl::Entry& b) {
                  const size_t la = a.cookie.path ? a.cookie.path->size() : 0;
                  const size_t lb = b.cookie.path ? b.cookie.path->size() : 0;
                  if (la != lb) return la > lb;
                  return a.created_seq < b.created_seq;
              });

    std::vector<SetCookie> out;
    out.reserve(entries.size());
    for (auto& e : entries) out.push_back(std::move(e.cookie));
    return out;
}

inline string CookieJar::cookie_header(const Url& url) const {
    return build_cookie_header(get(url));
}

inline size_t CookieJar::clear_expired() {
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    size_t removed = 0;
    std::lock_guard<std::mutex> g(impl_->mu);
    for (auto it = impl_->by_domain.begin(); it != impl_->by_domain.end();) {
        auto& v = it->second;
        const size_t before = v.size();
        v.erase(std::remove_if(v.begin(), v.end(), [now](const Impl::Entry& e) {
                    return e.cookie.expires_at.has_value() && *e.cookie.expires_at <= now;
                }),
                v.end());
        removed += before - v.size();
        if (v.empty()) it = impl_->by_domain.erase(it);
        else ++it;
    }
    return removed;
}

inline void CookieJar::clear() {
    std::lock_guard<std::mutex> g(impl_->mu);
    impl_->by_domain.clear();
}

inline size_t CookieJar::size() const {
    std::lock_guard<std::mutex> g(impl_->mu);
    return Impl::total_locked(impl_->by_domain);
}

inline std::vector<string> CookieJar::export_all() const {
    std::vector<string> out;
    std::lock_guard<std::mutex> g(impl_->mu);
    for (const auto& kv : impl_->by_domain) {
        for (const auto& e : kv.second) {
            string_builder b;
            detail::sb_append(b, to_view(e.cookie.name));
            detail::sb_append(b, '=');
            detail::sb_append(b, to_view(e.cookie.value));
            // Domain is written even for a host-only cookie. Without it the
            // export would lose the host, and a re-import would have nowhere to
            // put the cookie.
            detail::sb_append(b, "; Domain=");
            detail::sb_append(b, to_view(e.domain));
            // A host-only cookie and a Domain cookie with the same value are
            // NOT interchangeable: the first must never reach a subdomain. The
            // marker is what survives the round trip, since the attribute
            // itself cannot express the difference.
            if (e.host_only) detail::sb_append(b, "; __HostOnly=1");
            if (e.cookie.path.has_value()) {
                detail::sb_append(b, "; Path=");
                detail::sb_append(b, to_view(*e.cookie.path));
            }
            if (e.cookie.expires_at.has_value()) {
                detail::sb_append(b, "; Expires=");
                detail::sb_append(b, format("{}", *e.cookie.expires_at));
            }
            if (e.cookie.secure) detail::sb_append(b, "; Secure");
            if (e.cookie.http_only) detail::sb_append(b, "; HttpOnly");
            out.push_back(b.release());
        }
    }
    return out;
}

inline size_t CookieJar::import_all(const std::vector<string>& lines) {
    size_t applied = 0;
    for (const auto& line : lines) {
        auto parsed = parse_set_cookie(to_view(line));
        if (!parsed) continue;   // one bad line must not abort the import

        // import_all has no origin URL, so the cookie is stored against the
        // domain it names. The __HostOnly marker written by export_all() is
        // what distinguishes a host-only cookie from a Domain cookie that
        // happens to name the same host; without it the import would silently
        // widen the cookie to every subdomain.
        //
        // The marker is always written as "; __HostOnly=1" (a semicolon-space
        // prefix) and is never part of the real Set-Cookie grammar, so matching
        // against "; __HostOnly=1" rather than "__HostOnly=1" alone prevents a
        // cookie whose value coincidentally contains the substring from being
        // misclassified (2026-11-13 code review, defect #4).
        bool host_only = false;
        {
            const string_view line_v = to_view(line);
            const string_view marker = "; __HostOnly=1";
            size_t pos = 0;
            while ((pos = line_v.find(marker, pos)) != string_view::npos) {
                // Must be at the end of the line or followed by another "; "
                // attribute boundary; this avoids matching inside a value that
                // happens to contain the marker text.
                const size_t after = pos + marker.size();
                if (after == line_v.size() ||
                    (after + 2 <= line_v.size() &&
                     line_v[after] == ';' && line_v[after + 1] == ' ')) {
                    host_only = true;
                    break;
                }
                pos = after;
            }
        }

        Url u;
        u.scheme = parsed.value().secure ? Scheme::Https : Scheme::Http;
        u.host = parsed.value().domain.value_or(string());
        if (u.host.empty()) continue;
        u.port = Url::default_port(u.scheme);

        SetCookie c = parsed.value();
        if (host_only) {
            // Clearing Domain makes set() treat it as host-only.
            c.domain.reset();
        }

        if (set(u, c)) ++applied;
    }
    return applied;
}

inline string CookieJar::describe() const {
    std::lock_guard<std::mutex> g(impl_->mu);
    const size_t domains = impl_->by_domain.size();
    const size_t total = Impl::total_locked(impl_->by_domain);
    // Deliberately no names or values: a cookie can be a session token, and a
    // diagnostic string must not become a leak.
    return format("CookieJar({} cookies in {} domains)", total, domains);
}

inline std::shared_ptr<CookieJar> make_cookie_jar() {
    return std::make_shared<CookieJar>();
}

} // namespace megohttp

#endif // MEGOHTTP_COOKIE_IMPL_HPP_INCLUDED

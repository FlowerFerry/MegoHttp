// Multi-TU link test, part A. Every non-template definition in the header-only
// library must be `inline`; if any were not, linking A+B together would fail with
// a duplicate-symbol error. Compiling alone would never catch that.
//
// Build: g++ -std=c++17 ... tu_a.cpp tu_b.cpp -o test_multi_tu
#include <megohttp/url.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/error.hpp>

megohttp::string tu_a_make();
int tu_b_check(const megohttp::string& s);

// Same headers used here, producing values B also constructs.
int run_tu_a() {
    auto r = megohttp::parse_url("http://tu-a.example.com:8080/p?x=1");
    if (!r) return 1;
    if (r.value().port != 8080) return 2;

    megohttp::Headers h;
    h.add("X-TU", "a");
    h.add("X-TU", "b");
    if (h.get_all("x-tu").size() != 2) return 3;

    megohttp::Error e{megohttp::ErrorCode::HttpChunkError};
    if (e.describe().empty()) return 4;

    // Cross-TU: a value built here is consumed by B, and vice versa.
    if (tu_b_check(tu_a_make()) != 0) return 5;
    return 0;
}

megohttp::string tu_a_make() {
    megohttp::string_builder b;
    megohttp::detail::sb_append(b, "from-a");
    return b.release();
}

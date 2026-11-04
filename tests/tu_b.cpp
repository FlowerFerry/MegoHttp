// Multi-TU link test, part B. See tu_a.cpp for the rationale.
#include <megohttp/url.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/error.hpp>

#include <cstdio>
#include <cstring>

int run_tu_a();
MegoHttp::string tu_a_make();

// Called from A with a value A built.
int tu_b_check(const MegoHttp::string& s) {
    if (s.size() != 6) return 10;
    if (std::memcmp(s.data(), "from-a", 6) != 0) return 11;
    return 0;
}

// Called from main; also builds a string A consumes via tu_b_check.
MegoHttp::string tu_b_make() {
    MegoHttp::string_builder b;
    MegoHttp::Detail::sb_append(b, "from-b");
    return b.release();
}

int main() {
    int rc = run_tu_a();
    if (rc != 0) {
        std::printf("FAIL multi-TU: run_tu_a returned %d\n", rc);
        return 1;
    }

    // B's own use of the same inline definitions.
    auto r = MegoHttp::parse_url("https://tu-b.example.com/");
    if (!r || r.value().port != 443) {
        std::printf("FAIL multi-TU: tu_b url parse\n");
        return 2;
    }

    MegoHttp::Headers h;
    h.add("Content-Length", "42");
    auto cl = h.get_uint("content-length");
    if (!cl || *cl != 42) {
        std::printf("FAIL multi-TU: tu_b headers\n");
        return 3;
    }

    MegoHttp::string sb = tu_b_make();
    if (sb.size() != 6 || std::memcmp(sb.data(), "from-b", 6) != 0) {
        std::printf("FAIL multi-TU: tu_b make\n");
        return 4;
    }

    std::printf("[PASS] multi-TU link: two TUs share all inline definitions\n");
    return 0;
}

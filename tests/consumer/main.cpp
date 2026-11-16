// S8.2-02: an out-of-tree project consuming the installed MegoHttp package.
// Exercises the public surface without touching the source tree, so a missing
// install rule or a header that only works from the build tree fails here.
#include <megohttp/client.hpp>
#include <megohttp/request.hpp>
#include <megohttp/response.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/error.hpp>
#include <megohttp/multipart.hpp>
#include <megohttp/multipart_response.hpp>
#include <megohttp/content_range.hpp>

#include <cstdio>

using namespace megohttp;

int main() {
    // Pure offline checks: no network, so this is a real link + run test of the
    // installed package rather than a compile-only probe.
    Request req(Method::Get, "http://example.com/path");
    req.headers().set("x-test", "1");
    if (req.method() != Method::Get) return 1;
    if (!req.is_body_replayable()) return 2;

    req.set_body("abc");
    if (!req.has_body() || req.body_bytes().size() != 3) return 3;

    MultipartBuilder mb;
    if (!mb.add_text_field("k", "v")) return 4;
    if (mb.field_count() != 1) return 5;

    auto cr = parse_content_range("bytes 0-4/10");
    if (!cr) return 6;
    if (cr.value().length().value() != 5) return 7;

    Error e(ErrorCode::Cancelled);
    if (e.code() != ErrorCode::Cancelled) return 8;

    std::printf("consumer OK\n");
    return 0;
}

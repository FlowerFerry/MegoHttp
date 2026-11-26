// Compile-only cross-target check for the public header surface.
//
// The target is a static library, so this file is compiled for the requested
// Android/iOS ABI but not linked into a runnable binary. That is deliberate:
// the task book's matrix distinguishes cross-compile-only from native runtime
// evidence. A build failure here means the headers do not parse for the target
// toolchain; it does not claim the networking stack was executed.

#include <megohttp/client.hpp>
#include <megohttp/file_source.hpp>
#include <megohttp/multipart.hpp>
#include <megohttp/proxy.hpp>
#include <megohttp/retry.hpp>

int megohttp_cross_smoke() {
    megohttp::ClientOptions options;
    options.dns_timeout = std::chrono::seconds(5);
    options.connect_timeout = std::chrono::seconds(5);
    options.recv_timeout = std::chrono::seconds(5);
    options.total_timeout = std::chrono::seconds(15);
    options.max_response_body = 1024 * 1024;

    options.proxy.proxy.type = megohttp::ProxyType::Http;
    options.proxy.proxy.host = megohttp::string("proxy.invalid");
    options.proxy.proxy.port = 3128;

    megohttp::Request request(megohttp::Method::Get,
                              megohttp::string("http://example.invalid/"));
    request.set_head_callback([](const megohttp::ResponseHead&) {});
    request.set_trailers(megohttp::Headers{});

    megohttp::MultipartBuilder builder;
    builder.add_text_field(megohttp::string("field"), megohttp::string("value"));

    // Constructing Client exercises the inline executor/transport facade. The
    // static library is not linked, so no network operation is ever started.
    megohttp::Client client(options);
    (void)client;
    (void)builder;
    return 0;
}

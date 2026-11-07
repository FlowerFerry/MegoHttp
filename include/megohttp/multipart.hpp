#ifndef MEGOHTTP_MULTIPART_HPP_INCLUDED
#define MEGOHTTP_MULTIPART_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/request.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // multipart/form-data request encoding (S3.3)
    //
    // Builds the body from text fields, in-memory file fields and streamed fields.
    // The builder never buffers a whole payload: a streamed field is handed to the
    // request as a BodySource, so a caller can upload a file without reading it
    // into memory first.
    //
    // Usage:
    //   MultipartBuilder b;
    //   b.add_text_field("name", "value");
    //   b.add_file_field("avatar", "photo.jpg", "image/jpeg", bytes);
    //   auto r = b.apply_to(request);   // sets Content-Type and installs the body
    // ---------------------------------------------------------------------------
    class MultipartBuilder {
    public:
        MultipartBuilder();
        ~MultipartBuilder();

        MultipartBuilder(const MultipartBuilder&);
        MultipartBuilder& operator=(const MultipartBuilder&);
        MultipartBuilder(MultipartBuilder&&) noexcept;
        MultipartBuilder& operator=(MultipartBuilder&&) noexcept;

        // --- Fields ---

        // A text field. The value is copied and sent verbatim (binary safe).
        VoidResult add_text_field(string_view name, string_view value);

        // A file field whose bytes are already in memory.
        VoidResult add_file_field(string_view name,
                                  string_view filename,
                                  string_view content_type,
                                  std::vector<uint8_t> data);

        // A file field produced on demand. `size` lets the builder emit an exact
        // Content-Length; leave it nullopt to fall back to chunked transfer.
        VoidResult add_stream_field(string_view name,
                                    string_view filename,
                                    string_view content_type,
                                    Request::BodySource source,
                                    std::optional<uint64_t> size = std::nullopt);

        // --- Inspection ---

        size_t field_count() const noexcept;

        // Total body size, or nullopt when a streamed field has unknown size.
        std::optional<uint64_t> compute_total_size() const;

        // The boundary in use. Generated at construction unless set explicitly.
        string_view boundary() const noexcept;
        VoidResult set_boundary(string_view boundary);

        // Content-Type header value, boundary parameter included.
        string content_type_header() const;

        // --- Applying ---

        // Sets Content-Type and installs the body on `req`. Uses Content-Length when
        // the size is known, chunked otherwise. Any body already on `req` is replaced.
        VoidResult apply_to(Request& req) const;

        // Builds the whole body in memory. For tests and small payloads; a streamed
        // field of unknown size is an error here.
        Result<std::vector<uint8_t>> build_body() const;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

    // ---------------------------------------------------------------------------
    // Header parameter encoding (RFC 7578 section 5.1)
    //
    // Field names and filenames sit inside a quoted string in Content-Disposition,
    // so quote, backslash and CR/LF must be escaped. Non-ASCII bytes pass through:
    // RFC 7578 asks for UTF-8 there, and this library does not implement the RFC
    // 2231 continuation form.
    // ---------------------------------------------------------------------------
    string encode_multipart_field_name(string_view name);
    string encode_multipart_filename(string_view filename);

} // namespace megohttp

#include <megohttp/multipart_impl.hpp>

#endif // MEGOHTTP_MULTIPART_HPP_INCLUDED

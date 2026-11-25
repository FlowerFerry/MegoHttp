#ifndef MEGOHTTP_FILE_SOURCE_HPP_INCLUDED
#define MEGOHTTP_FILE_SOURCE_HPP_INCLUDED

// Non-blocking file body source.
//
// The worker thread performs the blocking std::ifstream reads and puts chunks
// into a bounded queue. BodySource::operator() never performs file I/O; when
// the queue is empty it returns an empty, non-EOF chunk (the Client's normal
// backpressure signal) and the Client asks again shortly.
//
// A FileSource is a shared object because the BodySource returned by
// body_source() captures a shared_ptr to it. That keeps the worker and its
// current chunk alive until the request has finished consuming them.
#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/request.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace megohttp {

    class FileSource final : public std::enable_shared_from_this<FileSource> {
    public:
        struct Options {
            // One read() request and one queued buffer use this many bytes.
            // The worker blocks before exceeding max_queued_chunks buffers.
            size_t chunk_size{64 * 1024};
            size_t max_queued_chunks{4};
        };

        // Opens the file and starts the reader. The open itself is synchronous
        // (it is normally called from the submitting thread); all subsequent
        // reads happen on the worker thread. size() is known for a regular
        // file and nullopt for a non-seekable source such as a device.
        static Result<std::shared_ptr<FileSource>> open(string_view path,
                                                        Options options = {});

        ~FileSource();

        FileSource(const FileSource&) = delete;
        FileSource& operator=(const FileSource&) = delete;

        // A BodySource that pulls chunks from the bounded queue. The returned
        // string_view is valid until the next call on this FileSource.
        Request::BodySource body_source();

        // Attaches the source to a Request. When the size is known this also
        // sets Content-Length, so the upload uses exact-length framing instead
        // of chunked transfer. A caller-supplied Transfer-Encoding is rejected.
        VoidResult attach_to(Request& request);

        // One pull from the queue. Empty + eof=false means "not ready yet";
        // empty + eof=true means the file is exhausted or close() was called.
        // No file I/O is performed here.
        Result<std::pair<string_view, bool>> next();

        std::optional<uint64_t> size() const noexcept;
        bool is_eof() const noexcept;
        bool is_closed() const noexcept;

        // Stops the worker and discards queued chunks. It does not wait for a
        // read that is already in progress; the worker exits after that read.
        void close() noexcept;

    private:
        class Impl;
        explicit FileSource(std::shared_ptr<Impl> impl) noexcept;

        std::shared_ptr<Impl> impl_;
    };

} // namespace megohttp

#include <megohttp/file_source_impl.hpp>

#endif // MEGOHTTP_FILE_SOURCE_HPP_INCLUDED

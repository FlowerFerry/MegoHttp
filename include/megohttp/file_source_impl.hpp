#ifndef MEGOHTTP_FILE_SOURCE_IMPL_HPP_INCLUDED
#define MEGOHTTP_FILE_SOURCE_IMPL_HPP_INCLUDED

// Included at the end of file_source.hpp. Header-only: every definition is
// inline, and the reader thread owns a shared_ptr to Impl so the state cannot
// be destroyed while a blocking read is still in flight.
#include <megohttp/format.hpp>

#include <condition_variable>
#include <deque>
#include <exception>
#include <fstream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace megohttp {
namespace file_source_detail {

    inline string error_message(const char* what, string_view path) {
        string_builder b;
        detail::sb_append(b, what);
        detail::sb_append(b, path);
        return b.release();
    }

} // namespace file_source_detail

    class FileSource::Impl {
    public:
        Impl(std::ifstream file, string path, Options options,
             std::optional<uint64_t> file_size)
            : file_(std::move(file)),
              path_(std::move(path)),
              options_(options),
              size_(file_size) {}

        void start(std::shared_ptr<Impl> self) {
            std::thread worker([self = std::move(self)]() mutable {
                self->run();
            });
            // Detaching is deliberate: a close() from the I/O thread must not
            // block on a read that the operating system has not completed.
            // The worker owns a shared_ptr to this Impl, so its state survives
            // until the read returns and the loop exits.
            try {
                worker.detach();
            } catch (...) {
                worker.join();
                throw;
            }
        }

        Result<std::pair<string_view, bool>> next() {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!queue_.empty()) {
                current_ = std::move(queue_.front());
                queue_.pop_front();
                const bool last = eof_ && queue_.empty();
                space_.notify_one();
                return std::make_pair(
                    string_view(reinterpret_cast<const char*>(current_.data()),
                                current_.size()),
                    last);
            }
            if (failed_) return error_;
            if (eof_ || closed_) return std::make_pair(string_view{}, true);
            return std::make_pair(string_view{}, false);
        }

        std::optional<uint64_t> size() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return size_;
        }

        bool is_eof() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return eof_;
        }

        bool is_closed() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return closed_;
        }

        void close() noexcept {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                closed_ = true;
                stopped_ = true;
                queue_.clear();
            }
            space_.notify_all();
            data_.notify_all();
        }

    private:
        void fail(Error error) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!stopped_) {
                    failed_ = true;
                    error_ = std::move(error);
                }
            }
            data_.notify_all();
        }

        void run() {
            struct CloseFile {
                std::ifstream& file;
                ~CloseFile() { file.close(); }
            } close_file{file_};
            try {
                for (;;) {
                    {
                        std::unique_lock<std::mutex> lock(mutex_);
                        space_.wait(lock, [this] {
                            return stopped_ ||
                                   queue_.size() < options_.max_queued_chunks;
                        });
                        if (stopped_) return;
                    }

                    std::vector<uint8_t> chunk(options_.chunk_size);
                    file_.read(reinterpret_cast<char*>(chunk.data()),
                               static_cast<std::streamsize>(chunk.size()));
                    const std::streamsize got = file_.gcount();
                    const bool eof = file_.eof();
                    const bool bad = file_.bad();

                    if (got > 0) {
                        chunk.resize(static_cast<size_t>(got));
                        std::lock_guard<std::mutex> lock(mutex_);
                        if (stopped_) return;
                        queue_.push_back(std::move(chunk));
                        data_.notify_one();
                    }

                    if (bad) {
                        fail(Error{ErrorCode::Unknown, ErrorPhase::Send,
                                   file_source_detail::error_message(
                                       "file read failed: ", to_view(path_))});
                        return;
                    }
                    if (eof) {
                        {
                            std::lock_guard<std::mutex> lock(mutex_);
                            if (stopped_) return;
                            eof_ = true;
                        }
                        data_.notify_all();
                        return;
                    }
                    if (got == 0) {
                        // A non-EOF read that made no progress would spin the
                        // worker forever; report it instead of busy-looping.
                        fail(Error{ErrorCode::Unknown, ErrorPhase::Send,
                                   file_source_detail::error_message(
                                       "file read made no progress: ",
                                       to_view(path_))});
                        return;
                    }
                }
            } catch (const std::exception& e) {
                string_builder b;
                detail::sb_append(b, "file read failed: ");
                detail::sb_append(b, to_view(path_));
                detail::sb_append(b, " (");
                detail::sb_append(b, e.what());
                detail::sb_append(b, ")");
                fail(Error{ErrorCode::Unknown, ErrorPhase::Send, b.release()});
            } catch (...) {
                fail(Error{ErrorCode::Unknown, ErrorPhase::Send,
                           file_source_detail::error_message(
                               "file read failed: ", to_view(path_))});
            }
        }

        std::ifstream file_;
        const string path_;
        const Options options_;
        const std::optional<uint64_t> size_;

        mutable std::mutex mutex_;
        std::condition_variable space_;
        std::condition_variable data_;
        std::deque<std::vector<uint8_t>> queue_;
        std::vector<uint8_t> current_;
        Error error_;
        bool eof_{false};
        bool failed_{false};
        bool closed_{false};
        bool stopped_{false};
    };

    inline FileSource::FileSource(std::shared_ptr<Impl> impl) noexcept
        : impl_(std::move(impl)) {}

    inline FileSource::~FileSource() {
        if (impl_) impl_->close();
    }

    inline Result<std::shared_ptr<FileSource>> FileSource::open(string_view path) {
        return FileSource::open(path, Options{});
    }

    inline Result<std::shared_ptr<FileSource>> FileSource::open(
        string_view path, Options options) {
        if (path.empty()) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("file source path is empty")};
        }
        if (options.chunk_size == 0) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("file source chunk_size must be non-zero")};
        }
        if (options.max_queued_chunks == 0) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("file source max_queued_chunks must be non-zero")};
        }
        if (options.chunk_size >
            static_cast<size_t>(
                (std::numeric_limits<std::streamsize>::max)())) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("file source chunk_size is too large")};
        }

        const string path_owned = to_string(path);
        std::ifstream file(path_owned.c_str(), std::ios::binary);
        if (!file) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         file_source_detail::error_message(
                             "cannot open file: ", to_view(path_owned))};
        }

        std::optional<uint64_t> file_size;
        file.seekg(0, std::ios::end);
        if (file) {
            const std::streampos end = file.tellg();
            if (end != std::streampos(-1)) {
                file_size = static_cast<uint64_t>(end);
            }
        }
        file.clear();
        file.seekg(0, std::ios::beg);
        // Non-seekable inputs (pipes/devices) are allowed: leave the stream at
        // its current position and report an unknown length. The worker still
        // reads to EOF; it just cannot advertise Content-Length.
        if (!file) file.clear();

        auto impl = std::make_shared<Impl>(std::move(file), path_owned, options,
                                           file_size);
        auto self = std::shared_ptr<FileSource>(new FileSource(impl));
        try {
            impl->start(impl);
        } catch (const std::exception& e) {
            string_builder b;
            detail::sb_append(b, "cannot start file reader: ");
            detail::sb_append(b, to_view(path_owned));
            detail::sb_append(b, " (");
            detail::sb_append(b, e.what());
            detail::sb_append(b, ")");
            return Error{ErrorCode::Unknown, ErrorPhase::Send, b.release()};
        } catch (...) {
            return Error{ErrorCode::Unknown, ErrorPhase::Send,
                         file_source_detail::error_message(
                             "cannot start file reader: ", to_view(path_owned))};
        }
        return self;
    }

    inline Request::BodySource FileSource::body_source() {
        auto self = shared_from_this();
        return [self]() { return self->next(); };
    }

    inline VoidResult FileSource::attach_to(Request& request) {
        if (request.headers().contains("transfer-encoding")) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("file source cannot be combined with a "
                                "caller-supplied Transfer-Encoding")};
        }
        if (const auto known_size = size()) {
            // Keep the formatted string alive while Headers copies the view.
            const string length_text = format("{}", known_size.value());
            request.headers().set("content-length", to_view(length_text));
        }
        request.set_body_source(body_source());
        return VoidResult{};
    }

    inline Result<std::pair<string_view, bool>> FileSource::next() {
        return impl_->next();
    }

    inline std::optional<uint64_t> FileSource::size() const noexcept {
        return impl_->size();
    }

    inline bool FileSource::is_eof() const noexcept {
        return impl_->is_eof();
    }

    inline bool FileSource::is_closed() const noexcept {
        return impl_->is_closed();
    }

    inline void FileSource::close() noexcept {
        impl_->close();
    }

} // namespace megohttp

#endif // MEGOHTTP_FILE_SOURCE_IMPL_HPP_INCLUDED

#ifndef MEGOHTTP_REQUEST_IMPL_HPP_INCLUDED
#define MEGOHTTP_REQUEST_IMPL_HPP_INCLUDED

// Included at the end of request.hpp. Header-only: every definition is inline.

namespace megohttp {

    class Request::Impl {
    public:
        Method method{Method::Get};
        string custom_method;
        string url_text;
        std::optional<Url> parsed;
        Headers headers;
        std::vector<uint8_t> body;
        bool has_body{false};
        // S3.2-01: BodySource for streaming upload
        std::optional<Request::BodySource> body_source;
        // S3.2-02: BodySink for streaming download
        std::optional<Request::BodySink> body_sink;
        std::optional<Request::BodySinkComplete> body_sink_complete;
        std::shared_ptr<Request::BodySinkFlow> body_sink_flow;
    };

    // Shared pause/resume flag for a streaming download. Deliberately tiny: an
    // atomic plus the client's wake-up callback, installed when the exchange
    // starts. A caller only ever has to pause() and resume().
    struct BodySinkFlowState {
        std::atomic<bool> paused{false};
        // Installed by the client once the exchange exists; invoked on resume so
        // a paused read actually restarts. Guarded because it is written on the
        // I/O thread and read from the caller's thread.
        std::mutex mu;
        std::function<void()> on_resume;
    };

    inline Request::BodySinkFlow::BodySinkFlow()
        : state_(std::make_shared<BodySinkFlowState>()) {}

    inline void Request::BodySinkFlow::pause() { state_->paused.store(true); }

    inline void Request::BodySinkFlow::resume() {
        // Only wake the client when the flag actually changed, so a redundant
        // resume does not stack read loops.
        if (!state_->paused.exchange(false)) return;
        std::function<void()> cb;
        {
            std::lock_guard<std::mutex> lk(state_->mu);
            cb = state_->on_resume;
        }
        if (cb) cb();
    }

    inline bool Request::BodySinkFlow::is_paused() const noexcept {
        return state_->paused.load();
    }

    inline void Request::BodySinkFlow::set_wake(std::function<void()> wake) {
        std::lock_guard<std::mutex> lk(state_->mu);
        state_->on_resume = std::move(wake);
    }

    inline Request::Request() : impl_(std::make_unique<Impl>()) {}

    inline Request::Request(Method method, string_view url)
        : impl_(std::make_unique<Impl>()) {
        impl_->method = method;
        impl_->url_text = to_string(url);
    }

    inline Request::Request(const Request& other)
        : impl_(std::make_unique<Impl>(*other.impl_)) {}

    inline Request& Request::operator=(const Request& other) {
        if (this != &other) *impl_ = *other.impl_;
        return *this;
    }

    inline Request::Request(Request&&) noexcept = default;
    inline Request& Request::operator=(Request&&) noexcept = default;
    inline Request::~Request() = default;

    inline Method Request::method() const noexcept { return impl_->method; }
    inline void Request::set_method(Method method) { impl_->method = method; }

    inline string_view Request::custom_method() const noexcept {
        return to_view(impl_->custom_method);
    }
    inline void Request::set_custom_method(string_view name) {
        impl_->custom_method = to_string(name);
        impl_->method = Method::Custom;
    }

    inline string_view Request::url() const noexcept { return to_view(impl_->url_text); }

    inline void Request::set_url(string_view url) {
        impl_->url_text = to_string(url);
        // The URL changed, so any previously parsed form is stale.
        impl_->parsed.reset();
    }

    inline const std::optional<Url>& Request::parsed_url() const noexcept {
        return impl_->parsed;
    }

    inline VoidResult Request::set_parsed_url(Url url) {
        if (url.scheme == Scheme::Unknown) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("cannot store a URL with Scheme::Unknown")};
        }
        // Store the URL's own canonical text, scheme included. The previous
        // version stored absolute_form_target(), which is a PROXY request-target
        // form and not a URL: re-submitting or re-reading url() gave back a
        // string that no longer carried the original scheme.
        string_builder b;
        detail::sb_append(b, to_view(url.origin()));
        detail::sb_append(b, to_view(url.request_target()));
        impl_->url_text = b.release();
        impl_->parsed = std::move(url);
        return VoidResult{};
    }

    inline Headers& Request::headers() noexcept { return impl_->headers; }
    inline const Headers& Request::headers() const noexcept { return impl_->headers; }

    inline void Request::set_body(string_view data) {
        impl_->body.assign(data.begin(), data.end());
        impl_->has_body = true;
        // Body modes are mutually exclusive. Leaving a previously-set source in
        // place meant the Client could still pull from it instead of the buffer.
        impl_->body_source.reset();
    }

    inline void Request::set_body(std::vector<uint8_t> data) {
        impl_->body = std::move(data);
        impl_->has_body = true;
        impl_->body_source.reset();   // mutually exclusive with source
    }

    inline void Request::set_body_source(BodySource src) {
        impl_->body_source = std::move(src);
        impl_->has_body = true;
        impl_->body.clear();          // mutually exclusive with buffer
    }

    inline bool Request::has_body() const noexcept { return impl_->has_body; }

    inline void Request::clear_body() {
        impl_->body.clear();
        impl_->has_body = false;
        // Both carriers must go; leaving one behind made "cleared" mean
        // "cleared the buffer and kept streaming".
        impl_->body_source.reset();
    }

    inline bool Request::is_body_replayable() const noexcept {
        // A buffered byte body can always be re-sent. A BodySource has no reset
        // contract yet, so a streamed body must be reported as non-replayable --
        // otherwise redirect/retry would silently re-send it (and send nothing,
        // because the source has already been drained).
        return !impl_->body_source.has_value();
    }

    inline const std::vector<uint8_t>& Request::body_bytes() const noexcept {
        return impl_->body;
    }

    inline const std::optional<Request::BodySource>& Request::body_source() const noexcept {
        return impl_->body_source;
    }

    inline void Request::set_body_sink(BodySink sink, BodySinkComplete complete) {
        impl_->body_sink = std::move(sink);
        impl_->body_sink_complete = std::move(complete);
        impl_->body_sink_flow.reset();
    }

    inline void Request::set_body_sink(BodySink sink, BodySinkComplete complete,
                                       std::shared_ptr<BodySinkFlow> flow) {
        impl_->body_sink = std::move(sink);
        impl_->body_sink_complete = std::move(complete);
        impl_->body_sink_flow = std::move(flow);
    }

    inline const std::shared_ptr<Request::BodySinkFlow>& Request::body_sink_flow() const noexcept {
        return impl_->body_sink_flow;
    }

    inline const std::optional<Request::BodySink>& Request::body_sink() const noexcept {
        return impl_->body_sink;
    }

    inline const std::optional<Request::BodySinkComplete>& Request::body_sink_complete() const noexcept {
        return impl_->body_sink_complete;
    }

} // namespace megohttp

#endif // MEGOHTTP_REQUEST_IMPL_HPP_INCLUDED

#ifndef MEGOHTTP_RESPONSE_IMPL_HPP_INCLUDED
#define MEGOHTTP_RESPONSE_IMPL_HPP_INCLUDED

// Included at the end of response.hpp. Header-only: every definition is inline.

namespace MegoHttp {

    class Response::Impl {
    public:
        ResponseHead head;
        std::vector<uint8_t> body;
        bool buffered{true};
        bool decoded{false};
        std::optional<uint64_t> wire_length;
    };

    inline Response::Response() : impl_(std::make_unique<Impl>()) {}

    inline Response::Response(ResponseHead head, std::vector<uint8_t> body)
        : impl_(std::make_unique<Impl>()) {
        impl_->head = std::move(head);
        impl_->body = std::move(body);
    }

    inline Response::Response(const Response& other)
        : impl_(std::make_unique<Impl>(*other.impl_)) {}

    inline Response& Response::operator=(const Response& other) {
        if (this != &other) *impl_ = *other.impl_;
        return *this;
    }

    inline Response::Response(Response&&) noexcept = default;
    inline Response& Response::operator=(Response&&) noexcept = default;
    inline Response::~Response() = default;

    inline const ResponseHead& Response::head() const noexcept { return impl_->head; }

    inline const std::vector<uint8_t>& Response::body_bytes() const noexcept {
        return impl_->body;
    }

    inline string_view Response::body_text() const noexcept {
        return string_view(reinterpret_cast<const char*>(impl_->body.data()),
                           impl_->body.size());
    }

    inline bool Response::body_is_buffered() const noexcept { return impl_->buffered; }

    inline bool Response::body_decoded() const noexcept { return impl_->decoded; }

    inline std::optional<uint64_t> Response::wire_body_length() const noexcept {
        return impl_->wire_length;
    }

    inline uint64_t Response::decoded_body_length() const noexcept {
        return static_cast<uint64_t>(impl_->body.size());
    }

    inline void Response::set_encoding_facts(bool decoded,
                                             std::optional<uint64_t> wire_length) noexcept {
        impl_->decoded = decoded;
        impl_->wire_length = wire_length;
    }

} // namespace MegoHttp

#endif // MEGOHTTP_RESPONSE_IMPL_HPP_INCLUDED

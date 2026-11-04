#ifndef MEGOHTTP_ERROR_HPP_INCLUDED
#define MEGOHTTP_ERROR_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/string_adapter.hpp>

// The error carrier is MemeString's mgpp::err and the code space is
// mego/err/ec.h. Using them instead of a hand-rolled error class means this
// library's errors compose with the rest of the ecosystem: the same err_cat /
// err_cond machinery, the same message/solution/funcinfo payload, the same
// chaining via set_next().
#include <megopp/err/err.hpp>
#include <mego/err/ec.h>

#include <optional>
#include <variant>
#include <utility>

namespace MegoHttp {

    namespace detail {
        // mgpp::err always speaks memepp::string, regardless of which string type
        // this library is configured to use. Convert at the boundary only.
        inline memepp::string to_memepp(const string& s) {
#if MEGOHTTP_HAS_MEMESTRING
            return s;
#else
            return memepp::string(s.data(), static_cast<memepp::string::size_type>(s.size()));
#endif
        }

        // And back, for the payload mgpp::err hands out.
        inline string from_memepp(const memepp::string& s) {
#if MEGOHTTP_HAS_MEMESTRING
            return s;
#else
            return string(s.data(), static_cast<size_t>(s.size()));
#endif
        }
    } // namespace detail

    // MegoHttp-specific codes live in their own numeric band so they can never
    // collide with the POSIX band (-100000..) or the two bands mego/err/ec.h
    // already uses (-200000.. Windows, -300000.. SQLite). -400000.. is free.
    //
    // Expressed as offsets from a BEGIN macro (the same shape ec.h uses) so the
    // band is obvious and inserting a code in the middle stays cheap.
#define MGEC__HTTP_BEGIN    (-400000)
#define MGEC__HTTP_END      (-499999)

    enum class ErrorCode : int32_t {
        Success = MGEC__OK,

        Unknown                 = MGEC__HTTP_BEGIN - 1,
        InvalidArgument         = MGEC__HTTP_BEGIN - 2,
        NotImplemented          = MGEC__HTTP_BEGIN - 3,
        OutOfMemory             = MGEC__HTTP_BEGIN - 4,
        ConfigurationError      = MGEC__HTTP_BEGIN - 5,

        // --- DNS ---
        DnsResolveFailed        = MGEC__HTTP_BEGIN - 20,
        DnsTimeout              = MGEC__HTTP_BEGIN - 21,
        DnsCancelled            = MGEC__HTTP_BEGIN - 22,
        DnsInvalidMessage       = MGEC__HTTP_BEGIN - 23,
        DnsServerFailure        = MGEC__HTTP_BEGIN - 24,  // SERVFAIL / REFUSED
        DnsNameNotFound         = MGEC__HTTP_BEGIN - 25,  // NXDOMAIN
        DnsNoData               = MGEC__HTTP_BEGIN - 26,  // NOERROR, no answer

        // --- Connection ---
        ConnectFailed           = MGEC__HTTP_BEGIN - 40,
        ConnectTimeout          = MGEC__HTTP_BEGIN - 41,
        ConnectionReset         = MGEC__HTTP_BEGIN - 42,
        ConnectionClosed        = MGEC__HTTP_BEGIN - 43,

        // --- TLS ---
        TlsHandshakeFailed      = MGEC__HTTP_BEGIN - 60,
        TlsCertificateInvalid   = MGEC__HTTP_BEGIN - 61,
        TlsCertificateExpired   = MGEC__HTTP_BEGIN - 62,
        TlsHostnameMismatch     = MGEC__HTTP_BEGIN - 63,
        TlsNotEnabled           = MGEC__HTTP_BEGIN - 64,  // built with MGHTTP_TLS_NONE
        TlsProtocolVersionUnsupported = MGEC__HTTP_BEGIN - 65,

        // --- HTTP ---
        HttpInvalidResponse     = MGEC__HTTP_BEGIN - 80,
        HttpVersionNotSupported = MGEC__HTTP_BEGIN - 81,
        HttpHeaderTooLarge      = MGEC__HTTP_BEGIN - 82,
        HttpHeaderCountExceeded = MGEC__HTTP_BEGIN - 83,
        HttpBodyTooLarge        = MGEC__HTTP_BEGIN - 84,
        HttpChunkError          = MGEC__HTTP_BEGIN - 85,
        HttpTrailerError        = MGEC__HTTP_BEGIN - 86,
        HttpAmbiguousFraming    = MGEC__HTTP_BEGIN - 87,
        HttpProtocolViolation   = MGEC__HTTP_BEGIN - 88,

        // --- Content encoding ---
        ContentDecodingFailed   = MGEC__HTTP_BEGIN - 100,
        ContentEncodingUnsupported = MGEC__HTTP_BEGIN - 101,
        ContentDecodingResourceExceeded = MGEC__HTTP_BEGIN - 102,

        // --- Timeouts ---
        TimeoutResolve          = MGEC__HTTP_BEGIN - 120,
        TimeoutConnect          = MGEC__HTTP_BEGIN - 121,
        TimeoutSend             = MGEC__HTTP_BEGIN - 122,
        TimeoutRecv             = MGEC__HTTP_BEGIN - 123,
        TimeoutTotal            = MGEC__HTTP_BEGIN - 124,

        // --- Cancellation ---
        Cancelled               = MGEC__HTTP_BEGIN - 140,

        // --- Proxy ---
        ProxyConnectFailed      = MGEC__HTTP_BEGIN - 160,
        ProxyAuthRequired       = MGEC__HTTP_BEGIN - 161,
        ProxyAuthFailed         = MGEC__HTTP_BEGIN - 162,
        ProxyProtocolError      = MGEC__HTTP_BEGIN - 163,
        ProxyTlsRequired        = MGEC__HTTP_BEGIN - 164,

        // --- SOCKS5 ---
        Socks5HandshakeFailed   = MGEC__HTTP_BEGIN - 180,
        Socks5AuthFailed        = MGEC__HTTP_BEGIN - 181,

        // --- WebSocket ---
        WsHandshakeFailed       = MGEC__HTTP_BEGIN - 200,
        WsProtocolError         = MGEC__HTTP_BEGIN - 201,
        WsFrameTooLarge         = MGEC__HTTP_BEGIN - 202,
        WsMessageTooLarge       = MGEC__HTTP_BEGIN - 203,
        WsUtf8Invalid           = MGEC__HTTP_BEGIN - 204,
        WsSendQueueFull         = MGEC__HTTP_BEGIN - 205,
        WsNotOpen               = MGEC__HTTP_BEGIN - 206,
        WsInvalidState          = MGEC__HTTP_BEGIN - 207,

        // --- WebSocket permessage-deflate: five distinct cases, never merged ---
        WsCompressionNotCompiled            = MGEC__HTTP_BEGIN - 220,
        WsCompressionUnsupportedLocalConfig = MGEC__HTTP_BEGIN - 221,
        WsCompressionNegotiationFailed      = MGEC__HTTP_BEGIN - 222,
        WsCompressionMalformedData          = MGEC__HTTP_BEGIN - 223,
        WsCompressionResourceExceeded       = MGEC__HTTP_BEGIN - 224,

        // --- multipart response: five distinct cases, never merged ---
        MultipartMediaTypeInvalid    = MGEC__HTTP_BEGIN - 240,
        MultipartPartHeaderInvalid   = MGEC__HTTP_BEGIN - 241,
        MultipartDelimiterInvalid    = MGEC__HTTP_BEGIN - 242,
        MultipartTruncated           = MGEC__HTTP_BEGIN - 243,
        MultipartContentRangeInvalid = MGEC__HTTP_BEGIN - 244,
        MultipartLimitExceeded       = MGEC__HTTP_BEGIN - 245,

        // --- SSE ---
        SseInvalidContentType   = MGEC__HTTP_BEGIN - 260,
        SseLineTooLong          = MGEC__HTTP_BEGIN - 261,
        SseEventTooLarge        = MGEC__HTTP_BEGIN - 262,
    };

    // Which stage of a multi-stage connection failed. Tells a proxy certificate
    // error apart from a target certificate error. Carried as mgpp::err's
    // user_code, so it travels with the code without widening mgpp::err.
    enum class ErrorPhase : int32_t {
        None = 0,
        Resolve,
        TcpConnect,
        TlsHandshake,
        Send,
        Receive,
        ProxyResolve,
        ProxyConnect,
        ProxyTls,
        ProxyAuth,
        ProxyConnectTunnel,      // the CONNECT request itself
        TargetResolve,
        TargetConnect,
        TargetTls,
        TargetProtocol,
        Compression,
        MultipartParse,
    };

    // err_cat for MegoHttp codes: supplies the name for each code and the category
    // identity used by mgpp::err_cond comparisons.
    class MegoHttpErrCat final : public mgpp::err_cat {
    public:
        const char* name() const noexcept override { return "megohttp"; }
        memepp::string message(int _errval) const noexcept override;
    };

    // Process-wide category instance (function-local static: created on first use,
    // so there is no static-initialization-order problem).
    const mgpp::err_cat* megohttp_err_cat() noexcept;

    // Raw int code from mgpp::err back to the typed enum. An unrecognized value
    // maps to ErrorCode::Unknown rather than asserting: the error may have come
    // from a platform call that used its own numbering.
    ErrorCode error_code_from_int(int32_t code) noexcept;

    // ---------------------------------------------------------------------------
    // Error: a thin adapter over mgpp::err.
    //
    // Keeps mgpp::err's payload (message / solution / funcinfo / chaining) and adds
    // the two things this library needs on top: the typed ErrorCode and the
    // ErrorPhase. Both travel inside the mgpp::err (code and user_code), so an
    // Error can be handed to code that only understands mgpp::err and back.
    // ---------------------------------------------------------------------------
    class Error {
    public:
        Error() noexcept = default;

        Error(ErrorCode code, ErrorPhase phase, string message)
            : err_(static_cast<int32_t>(code), static_cast<int32_t>(phase),
                   detail::to_memepp(message)) {}

        explicit Error(ErrorCode code)
            : err_(static_cast<int32_t>(code)) {}

        Error(ErrorCode code, string message)
            : err_(static_cast<int32_t>(code), detail::to_memepp(message)) {}

        // Wrap an existing mgpp::err (e.g. one surfaced from MemeString or libuv).
        explicit Error(mgpp::err e) : err_(std::move(e)) {}

        ErrorCode code() const noexcept {
            return error_code_from_int(err_.code());
        }

        ErrorPhase phase() const noexcept {
            return static_cast<ErrorPhase>(err_.usercode());
        }

        // Returns this library's string type. The payload lives in a
        // memepp::string (mgpp::err's carrier), so in std mode this copies once.
        string message() const { return detail::from_memepp(err_.message()); }

        // Transport-level detail code (errno / uv_errno / OpenSSL verify result).
        // Deliberately NOT folded into the MegoHttp code space: it is diagnostic
        // only and comes from a foreign numbering scheme.
        int native_code() const noexcept { return native_code_; }
        void set_native_code(int v) noexcept { native_code_ = v; }

        // Access to the underlying carrier, for callers already using mgpp::err.
        const mgpp::err& native() const noexcept { return err_; }
        mgpp::err& native() noexcept { return err_; }

        // Human-readable description, always non-empty for a real error.
        string describe() const;

        explicit operator bool() const noexcept { return err_.code() != MGEC__OK; }

    private:
        mgpp::err err_;
        int native_code_{0};
    };

    // Name of an error code, for logs and test assertions.
    const char* to_string(ErrorCode code) noexcept;
    const char* to_string(ErrorPhase phase) noexcept;

    // ---------------------------------------------------------------------------
    // Result<T>: value-or-error. Shaped like std::expected (a C++20 feature), so
    // the API can offer `if (r)`, r.value(), r.error() in C++17.
    // ---------------------------------------------------------------------------
    template<typename T>
    class Result {
    public:
        Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
        Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}

        bool has_value() const noexcept { return storage_.index() == 0; }
        bool has_error() const noexcept { return storage_.index() == 1; }
        explicit operator bool() const noexcept { return has_value(); }

        T& value() { return std::get<0>(storage_); }
        const T& value() const { return std::get<0>(storage_); }

        // Pointer-style access, like std::optional / std::expected.
        // Precondition: has_value(). Never checked, matching the standard types.
        T* operator->() noexcept { return &std::get<0>(storage_); }
        const T* operator->() const noexcept { return &std::get<0>(storage_); }
        T& operator*() noexcept { return std::get<0>(storage_); }
        const T& operator*() const noexcept { return std::get<0>(storage_); }

        T value_or(T fallback) const {
            return has_value() ? std::get<0>(storage_) : std::move(fallback);
        }

        const Error& error() const { return std::get<1>(storage_); }
        Error& error() { return std::get<1>(storage_); }

    private:
        std::variant<T, Error> storage_;
    };

    // Result<void> replacement for operations with no value.
    class VoidResult {
    public:
        VoidResult() = default;
        VoidResult(Error error) : error_(std::move(error)) {}

        bool has_value() const noexcept { return !error_.has_value(); }
        bool has_error() const noexcept { return error_.has_value(); }
        explicit operator bool() const noexcept { return !error_.has_value(); }

        const Error& error() const { return *error_; }

    private:
        std::optional<Error> error_;
    };

} // namespace MegoHttp

#include <megohttp/error_impl.hpp>

#endif // MEGOHTTP_ERROR_HPP_INCLUDED

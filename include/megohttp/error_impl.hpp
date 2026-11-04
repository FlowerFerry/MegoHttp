#ifndef MEGOHTTP_ERROR_IMPL_HPP_INCLUDED
#define MEGOHTTP_ERROR_IMPL_HPP_INCLUDED

// Included at the end of error.hpp. Header-only, all definitions inline.

#include <megohttp/format.hpp>

#include <string>
#include <system_error>

namespace MegoHttp {

    // One table drives three things: the std::error_category message, the
    // to_string() name, and the reverse lookup used by error_code_from_int().
    // Keeping them in a single array makes it impossible for a name and its
    // message to disagree.
    namespace detail {

        struct ErrorCodeEntry {
            ErrorCode code;
            const char* name;
        };

        // Ordered exactly as the enum; the array is the single source of truth.
        inline constexpr ErrorCodeEntry kErrorCodes[] = {
            { ErrorCode::Success,                 "Success" },
            { ErrorCode::Unknown,                 "Unknown" },
            { ErrorCode::InvalidArgument,         "InvalidArgument" },
            { ErrorCode::NotImplemented,          "NotImplemented" },
            { ErrorCode::OutOfMemory,             "OutOfMemory" },
            { ErrorCode::ConfigurationError,      "ConfigurationError" },

            { ErrorCode::DnsResolveFailed,        "DnsResolveFailed" },
            { ErrorCode::DnsTimeout,              "DnsTimeout" },
            { ErrorCode::DnsCancelled,            "DnsCancelled" },
            { ErrorCode::DnsInvalidMessage,       "DnsInvalidMessage" },
            { ErrorCode::DnsServerFailure,        "DnsServerFailure" },
            { ErrorCode::DnsNameNotFound,         "DnsNameNotFound" },
            { ErrorCode::DnsNoData,               "DnsNoData" },

            { ErrorCode::ConnectFailed,           "ConnectFailed" },
            { ErrorCode::ConnectTimeout,          "ConnectTimeout" },
            { ErrorCode::ConnectionReset,         "ConnectionReset" },
            { ErrorCode::ConnectionClosed,        "ConnectionClosed" },

            { ErrorCode::TlsHandshakeFailed,      "TlsHandshakeFailed" },
            { ErrorCode::TlsCertificateInvalid,   "TlsCertificateInvalid" },
            { ErrorCode::TlsCertificateExpired,   "TlsCertificateExpired" },
            { ErrorCode::TlsHostnameMismatch,     "TlsHostnameMismatch" },
            { ErrorCode::TlsNotEnabled,           "TlsNotEnabled" },
            { ErrorCode::TlsProtocolVersionUnsupported, "TlsProtocolVersionUnsupported" },

            { ErrorCode::HttpInvalidResponse,     "HttpInvalidResponse" },
            { ErrorCode::HttpVersionNotSupported, "HttpVersionNotSupported" },
            { ErrorCode::HttpHeaderTooLarge,      "HttpHeaderTooLarge" },
            { ErrorCode::HttpHeaderCountExceeded, "HttpHeaderCountExceeded" },
            { ErrorCode::HttpBodyTooLarge,        "HttpBodyTooLarge" },
            { ErrorCode::HttpChunkError,          "HttpChunkError" },
            { ErrorCode::HttpTrailerError,        "HttpTrailerError" },
            { ErrorCode::HttpAmbiguousFraming,    "HttpAmbiguousFraming" },
            { ErrorCode::HttpProtocolViolation,   "HttpProtocolViolation" },

            { ErrorCode::ContentDecodingFailed,   "ContentDecodingFailed" },
            { ErrorCode::ContentEncodingUnsupported, "ContentEncodingUnsupported" },
            { ErrorCode::ContentDecodingResourceExceeded, "ContentDecodingResourceExceeded" },

            { ErrorCode::TimeoutResolve,          "TimeoutResolve" },
            { ErrorCode::TimeoutConnect,          "TimeoutConnect" },
            { ErrorCode::TimeoutSend,             "TimeoutSend" },
            { ErrorCode::TimeoutRecv,             "TimeoutRecv" },
            { ErrorCode::TimeoutTotal,            "TimeoutTotal" },

            { ErrorCode::Cancelled,               "Cancelled" },

            { ErrorCode::ProxyConnectFailed,      "ProxyConnectFailed" },
            { ErrorCode::ProxyAuthRequired,       "ProxyAuthRequired" },
            { ErrorCode::ProxyAuthFailed,         "ProxyAuthFailed" },
            { ErrorCode::ProxyProtocolError,      "ProxyProtocolError" },
            { ErrorCode::ProxyTlsRequired,        "ProxyTlsRequired" },

            { ErrorCode::Socks5HandshakeFailed,   "Socks5HandshakeFailed" },
            { ErrorCode::Socks5AuthFailed,        "Socks5AuthFailed" },

            { ErrorCode::WsHandshakeFailed,       "WsHandshakeFailed" },
            { ErrorCode::WsProtocolError,         "WsProtocolError" },
            { ErrorCode::WsFrameTooLarge,         "WsFrameTooLarge" },
            { ErrorCode::WsMessageTooLarge,       "WsMessageTooLarge" },
            { ErrorCode::WsUtf8Invalid,           "WsUtf8Invalid" },
            { ErrorCode::WsSendQueueFull,         "WsSendQueueFull" },
            { ErrorCode::WsNotOpen,               "WsNotOpen" },
            { ErrorCode::WsInvalidState,          "WsInvalidState" },

            { ErrorCode::WsCompressionNotCompiled,            "WsCompressionNotCompiled" },
            { ErrorCode::WsCompressionUnsupportedLocalConfig, "WsCompressionUnsupportedLocalConfig" },
            { ErrorCode::WsCompressionNegotiationFailed,      "WsCompressionNegotiationFailed" },
            { ErrorCode::WsCompressionMalformedData,          "WsCompressionMalformedData" },
            { ErrorCode::WsCompressionResourceExceeded,       "WsCompressionResourceExceeded" },

            { ErrorCode::MultipartMediaTypeInvalid,    "MultipartMediaTypeInvalid" },
            { ErrorCode::MultipartPartHeaderInvalid,   "MultipartPartHeaderInvalid" },
            { ErrorCode::MultipartDelimiterInvalid,    "MultipartDelimiterInvalid" },
            { ErrorCode::MultipartTruncated,           "MultipartTruncated" },
            { ErrorCode::MultipartContentRangeInvalid, "MultipartContentRangeInvalid" },
            { ErrorCode::MultipartLimitExceeded,       "MultipartLimitExceeded" },

            { ErrorCode::SseInvalidContentType,   "SseInvalidContentType" },
            { ErrorCode::SseLineTooLong,          "SseLineTooLong" },
            { ErrorCode::SseEventTooLarge,        "SseEventTooLarge" },
        };

        inline const char* code_name(ErrorCode code) noexcept {
            for (const auto& e : kErrorCodes) {
                if (e.code == code) return e.name;
            }
            return "Unknown";
        }

    } // namespace detail

    inline const char* to_string(ErrorCode code) noexcept {
        return detail::code_name(code);
    }

    inline const char* to_string(ErrorPhase phase) noexcept {
        switch (phase) {
        case ErrorPhase::None:               return "None";
        case ErrorPhase::Resolve:            return "Resolve";
        case ErrorPhase::TcpConnect:         return "TcpConnect";
        case ErrorPhase::TlsHandshake:       return "TlsHandshake";
        case ErrorPhase::Send:               return "Send";
        case ErrorPhase::Receive:            return "Receive";
        case ErrorPhase::ProxyResolve:       return "ProxyResolve";
        case ErrorPhase::ProxyConnect:       return "ProxyConnect";
        case ErrorPhase::ProxyTls:           return "ProxyTls";
        case ErrorPhase::ProxyAuth:          return "ProxyAuth";
        case ErrorPhase::ProxyConnectTunnel: return "ProxyConnectTunnel";
        case ErrorPhase::TargetResolve:      return "TargetResolve";
        case ErrorPhase::TargetConnect:      return "TargetConnect";
        case ErrorPhase::TargetTls:          return "TargetTls";
        case ErrorPhase::TargetProtocol:     return "TargetProtocol";
        case ErrorPhase::Compression:        return "Compression";
        case ErrorPhase::MultipartParse:     return "MultipartParse";
        }
        return "None";
    }

    namespace detail {
        // std::error_category's message() must return std::string, so this is the
        // one place where std::string appears regardless of the configured string
        // type. It is only reached through std::error_code::message().
        class MegoHttpCategory final : public std::error_category {
        public:
            const char* name() const noexcept override { return "megohttp"; }

            std::string message(int ev) const override {
                return std::string(to_string(error_code_from_int(ev)));
            }
        };
    } // namespace detail

    inline const std::error_category& megohttp_category() noexcept {
        // Function-local static: created on first use, so no static-init-order
        // problem, and the address is stable for the life of the program.
        static const detail::MegoHttpCategory cat;
        return cat;
    }

    inline ErrorCode error_code_from_int(int32_t code) noexcept {
        if (code == 0) return ErrorCode::Success;
        // Only our own band is a valid MegoHttp code; anything else is foreign.
        if (code > MGEC__HTTP_BEGIN || code < MGEC__HTTP_END) return ErrorCode::Unknown;
        const auto value = static_cast<ErrorCode>(code);
        for (const auto& e : detail::kErrorCodes) {
            if (e.code == value) return value;
        }
        return ErrorCode::Unknown;
    }

    inline string Error::describe() const {
        // "<Name>" or "<Name> (<phase>): <message>"
        string out(to_string(code()));
        if (phase() != ErrorPhase::None) {
            out = format("{} ({})", to_view(out), to_string(phase()));
        }
        if (!message().empty()) {
            out = format("{}: {}", to_view(out), message());
        }
        return out;
    }

} // namespace MegoHttp

#endif // MEGOHTTP_ERROR_IMPL_HPP_INCLUDED

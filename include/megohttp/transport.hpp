#ifndef MEGOHTTP_TRANSPORT_HPP_INCLUDED
#define MEGOHTTP_TRANSPORT_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/resolver.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#if defined(MGHTTP_BACKEND_LIBUV)
#   include <uv.h>
#elif defined(MGHTTP_BACKEND_ASIO)
#   include <asio/ip/tcp.hpp>
#   include <asio/io_context.hpp>
#endif

namespace megohttp {

    // ---------------------------------------------------------------------------
    // AsyncByteStream: the single abstraction the protocol layer talks to.
    //
    // Everything above this line (HTTP, SSE, WebSocket) sees only "give me bytes,
    // take my bytes". That is what lets one protocol implementation run over plain
    // TCP, TCP+TLS, and TCP+TLS(proxy)+CONNECT+TLS(target) without an if-statement
    // in the HTTP code (spec 5).
    // ---------------------------------------------------------------------------
    class AsyncByteStream {
    public:
        // Bytes are delivered as a view into a buffer the STREAM owns. The view is
        // valid only for the duration of the callback: the stream may reuse the
        // same storage for the next read. Copy anything you need to keep.
        //
        // Owning the buffer inside the stream is what makes the lifetimes safe on
        // both backends. libuv requires the uv_alloc_cb buffer to stay valid until
        // uv_read_cb runs ("each buffer is used only once and the user is
        // responsible for freeing it in the read callback"), and Asio requires
        // "ownership of the underlying memory blocks is retained by the caller,
        // which must guarantee that they remain valid until the completion handler
        // is called". Handing the stream a caller-owned buffer made that guarantee
        // depend on the caller's object staying alive, which it did not.
        using ReadCallback = std::function<void(Result<string_view>)>;  // empty view = EOF
        using WriteCallback = std::function<void(Result<size_t>)>;
        using CloseCallback = std::function<void()>;

        // VoidResult, NOT Result<VoidResult>: a Result whose value is itself a
        // result would report success while carrying the failure inside the value,
        // so `if (!r)` could never see it.
        using ReadyCallback = std::function<void(VoidResult)>;

        virtual ~AsyncByteStream() = default;

        // Fires on the loop thread once the stream is usable.
        virtual void start(ReadyCallback on_ready) = 0;

        // Read whatever arrives next. Only one read may be outstanding. The view
        // in the callback points into stream-owned storage and dies with the call.
        virtual void async_read_some(ReadCallback cb) = 0;

        // Write the whole buffer; partial writes are resumed internally.
        virtual void async_write(const uint8_t* data, size_t size, WriteCallback cb) = 0;

        // Close; `cb` fires exactly once, on the loop thread.
        virtual void async_close(CloseCallback cb) = 0;

        virtual bool is_open() const noexcept = 0;
        virtual string_view tls_protocol() const noexcept { return {}; }
    };

    // ---------------------------------------------------------------------------
    // TcpStream
    //
    // The two backends are mutually exclusive (CMake enforces 2-of-1), so each
    // provides its own TcpStream under the same name. Callers see one type; only
    // one definition is ever compiled.
    // ---------------------------------------------------------------------------
    class TcpStream final : public AsyncByteStream,
                            public std::enable_shared_from_this<TcpStream> {
    public:
        TcpStream(std::shared_ptr<Executor> executor, const ResolvedAddress& address,
                  Duration connect_timeout = std::chrono::seconds(30));
        ~TcpStream() override;

        void start(ReadyCallback on_ready) override;
        void async_read_some(ReadCallback cb) override;
        void async_write(const uint8_t* data, size_t size, WriteCallback cb) override;
        void async_close(CloseCallback cb) override;
        bool is_open() const noexcept override;

        void set_keep_alive(bool enable, Duration idle = std::chrono::seconds(60));
        void set_no_delay(bool enable);

    private:
#if defined(MGHTTP_BACKEND_LIBUV)
        // libuv keeps pointers into the uv_tcp_t handle and into every request
        // (uv_connect_t / uv_write_t / uv_shutdown_t) it is given, and touches
        // them after our calls return:
        //   - uv_close docs: "the memory can only be released in close_cb or
        //     after it has returned";
        //   - uv_close cancels in-progress requests and delivers their callbacks
        //     later with UV_ECANCELED;
        //   - uv_read's alloc buffer is handed back through uv_read_cb.
        // Embedding those structs in TcpStream therefore violated every one of
        // those rules: ~TcpStream freed them while libuv still held them, which
        // is what the loop thread crashed on inside uv__process_tcp_read_req.
        // They now live in a Node that owns itself until on_closed returns.
        struct Node {
            uv_tcp_t      handle{};
            uv_connect_t  connect_req{};
            uv_shutdown_t shutdown_req{};
            uv_write_t    write_req{};
            // libuv fills this buffer inside uv__process_tcp_read_req; it must
            // outlive the read callback, so it belongs to the Node, not to the
            // caller and not to TcpStream.
            uint8_t read_stage[16 * 1024];
            std::weak_ptr<TcpStream> owner;   // non-owning: no reference cycle
            std::shared_ptr<Node>    self;    // released only from on_closed
        };
        std::shared_ptr<Node> node_;

        static void on_connect(uv_connect_t* req, int status);
        static void on_alloc(uv_handle_t* h, size_t suggested, uv_buf_t* buf);
        static void on_read(uv_stream_t* s, ssize_t nread, const uv_buf_t* buf);
        static void on_write(uv_write_t* req, int status);
        static void on_shutdown(uv_shutdown_t* req, int status);
        static void on_closed(uv_handle_t* h);

        // Closes the handle from the loop thread (uv_close is not thread-safe).
        static void close_on_loop(std::shared_ptr<Node> node);
        static void do_close(Node* node);

        ReadCallback read_cb_;   // one outstanding read at a time

        uv_loop_t* loop_{nullptr};
        bool connecting_{false};
#elif defined(MGHTTP_BACKEND_ASIO)
        static void on_connect(std::shared_ptr<TcpStream> self,
                               const asio::error_code& ec);
        static void on_read(std::shared_ptr<TcpStream> self,
                            const asio::error_code& ec, size_t n);
        static void on_write(std::shared_ptr<TcpStream> self,
                             const asio::error_code& ec, size_t n);

        asio::io_context* ioc_{nullptr};
        // Asio 1.38's basic_stream_socket has NO default constructor, so the
        // socket is created when the target endpoint is known.
        std::unique_ptr<asio::ip::tcp::socket> socket_;

        ReadCallback read_cb_;   // one outstanding read at a time
        // Read buffer owned by the stream: Asio requires it to stay valid until
        // the completion handler runs, and this object is kept alive by the
        // handler's captured shared_ptr.
        std::array<uint8_t, 16 * 1024> read_stage_{};
#endif

        // Shared resume for a partially written buffer (both backends).
        void resume_write();

        std::shared_ptr<Executor> executor_;
        ResolvedAddress address_;
        bool open_{false};
        bool closing_{false};
        bool close_notified_{false};
        ReadyCallback ready_cb_;

        struct PendingWrite {
            std::shared_ptr<std::vector<uint8_t>> bytes;
            size_t total{0};
            size_t written{0};
            WriteCallback cb;
#if defined(MGHTTP_BACKEND_LIBUV)
            // The uv_write_t itself lives in Node: libuv keeps it until the write
            // callback fires, which can be after TcpStream is gone.
            uv_buf_t buf{};
#endif
        };
        std::shared_ptr<PendingWrite> write_;
        CloseCallback close_cb_;
    };

#if defined(MGHTTP_BACKEND_ASIO)
    // TcpStream (asio) implementation is in backend/transport_asio_impl.hpp.
#endif

    // ---------------------------------------------------------------------------
    // Happy Eyeballs connection racing (RFC 8305 shape).
    // ---------------------------------------------------------------------------
    struct ConnectOptions {
        Duration connect_timeout{std::chrono::seconds(30)};
        Duration attempt_delay{std::chrono::milliseconds(250)};
        size_t max_concurrent_attempts{2};
        enum class FamilyPreference { Unspecified, PreferIPv4, PreferIPv6 };
        FamilyPreference preference{FamilyPreference::Unspecified};
    };

    void connect_race(
        std::shared_ptr<Executor> executor,
        AddressList addresses,
        const ConnectOptions& options,
        std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> on_done);

} // namespace megohttp

// --- backend implementation -----------------------------------------------
#if defined(MGHTTP_BACKEND_LIBUV)
#   include <megohttp/backend/transport_libuv_impl.hpp>
#elif defined(MGHTTP_BACKEND_ASIO)
#   include <megohttp/backend/transport_asio_impl.hpp>
#endif
#endif // MEGOHTTP_TRANSPORT_HPP_INCLUDED

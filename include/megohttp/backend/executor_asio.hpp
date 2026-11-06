#ifndef MEGOHTTP_BACKEND_EXECUTOR_ASIO_HPP_INCLUDED
#define MEGOHTTP_BACKEND_EXECUTOR_ASIO_HPP_INCLUDED

// standalone Asio backend: Executor + Timer over asio::io_context.
//
// Contract differences from the libuv backend that callers must know:
//   • An external io_context may be driven by SEVERAL threads. All serialized
//     state therefore runs on a strand, not "the loop thread" — there is no
//     single loop thread to check, so is_in_loop_thread() reports false.
//   • The executor holds a work guard while it is alive, so an external loop
//     does not exit while work is outstanding. reset() is called on shutdown.
#include <megohttp/config.hpp>

#if !defined(MGHTTP_BACKEND_ASIO)
#   error "executor_asio.hpp requires MGHTTP_BACKEND_ASIO"
#endif

#include <megohttp/executor.hpp>

#include <asio/io_context.hpp>
#include <asio/strand.hpp>
#include <asio/steady_timer.hpp>

#include <atomic>
#include <memory>
#include <thread>

namespace megohttp {
namespace asio_backend {

    class AsioExecutor final : public Executor {
    public:
        // Internal loop: the executor owns the io_context and one driver thread.
        static std::shared_ptr<AsioExecutor> create_internal();

        // External loop: the caller owns `ioc` and keeps driving it. This class
        // never calls ioc.stop() and never joins anything.
        static std::shared_ptr<AsioExecutor> create_external(asio::io_context& ioc);

        ~AsioExecutor() override;

        void post(std::function<void()> fn) override;
        bool is_in_loop_thread() const noexcept override;
        std::shared_ptr<Timer> schedule_after(Duration d, std::function<void()> fn) override;
        TimePoint now() const noexcept override;

        // Like post(), but reports whether the work item was accepted. post()
        // silently drops it once the executor is shut down, which is fine for
        // best-effort wakeups but not for work that must still happen (closing a
        // socket). Callers that need a fallback use this instead.
        bool try_post(std::function<void()> fn);

        // Release the work guard so a caller-driven loop can drain and return,
        // and (internal mode) stop + join the driver thread. Idempotent.
        void shutdown();

        asio::io_context* context() const noexcept { return &ioc_; }

        // Public so std::make_shared can reach it; the ownership contract lives
        // in create_internal() / create_external().
        AsioExecutor(asio::io_context& ioc,
                     std::unique_ptr<asio::io_context> own_ioc = nullptr);

    private:
        void start_owned_thread();

        // Declared BEFORE ioc_ so it is destroyed AFTER it in internal mode: the
        // io_context must outlive the strand and the work guard.
        std::unique_ptr<asio::io_context> own_ioc_;

        asio::io_context& ioc_;
        asio::strand<asio::io_context::executor_type> strand_;
        std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> guard_;

        std::atomic<bool> stopped_{false};
        std::thread thread_;

    public:
        bool owns_ioc() const noexcept { return own_ioc_ != nullptr; }
    };

} // namespace asio_backend

    // The transport/resolver code is written against these names, exactly as it
    // is for libuv, so the shared layers do not branch on backend.
    using asio_backend::AsioExecutor;

} // namespace megohttp

#include <megohttp/backend/executor_asio_impl.hpp>

#endif

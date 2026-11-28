#ifndef MEGOHTTP_BACKEND_EXECUTOR_ASIO_IMPL_HPP_INCLUDED
#define MEGOHTTP_BACKEND_EXECUTOR_ASIO_IMPL_HPP_INCLUDED

#include <megohttp/backend/executor_asio.hpp>

#include <asio.hpp>

#include <chrono>
#include <thread>

namespace megohttp {
namespace asio_backend {

    // Timer over asio::steady_timer.
    //
    // Self-holding by design: the libuv backend's DeferredTimer taught this
    // lesson — a caller that drops the returned handle must NOT lose its timer.
    // The shared_ptr therefore lives in `self_` until it fires or is cancelled.
    class AsioTimer final : public Timer,
                            public std::enable_shared_from_this<AsioTimer> {
    public:
        AsioTimer(asio::io_context& ioc,
                  const asio::strand<asio::io_context::executor_type>& strand,
                  Duration d,
                  std::function<void()> fn)
            : timer_(ioc, d), fn_(std::move(fn)), strand_(strand) {}

        // Installs the self-hold and starts waiting. Called by the factory, never
        // by the constructor: weak_from_this() is empty until a shared_ptr owns us.
        void arm() {
            self_ = shared_from_this();
            auto self = self_;
            timer_.async_wait(asio::bind_executor(
                strand_, [self](const asio::error_code& ec) { self->on_fire(ec); }));
        }

        ~AsioTimer() override = default;

        void cancel() override {
            cancelled_.store(true);
            // cancel() may be called from any thread; asio's cancel is thread-safe.
            timer_.cancel();
            self_.reset();
        }

        bool is_cancelled() const noexcept override { return cancelled_.load(); }

    private:
        void on_fire(const asio::error_code& ec) {
            self_.reset();   // released before the handler runs
            if (ec == asio::error::operation_aborted || cancelled_.load()) return;
            auto fn = std::move(fn_);
            if (fn) fn();
        }

        asio::steady_timer timer_;
        std::function<void()> fn_;
        asio::strand<asio::io_context::executor_type> strand_;
        std::shared_ptr<AsioTimer> self_;
        std::atomic<bool> cancelled_{false};
    };

    // ---------------------------------------------------------------------------
    inline AsioExecutor::AsioExecutor(asio::io_context& ioc,
                                      std::shared_ptr<asio::io_context> own_ioc)
        : own_ioc_(std::move(own_ioc)),
          ioc_(ioc),
          strand_(asio::make_strand(ioc.get_executor())),
          guard_(std::make_unique<
                 asio::executor_work_guard<asio::io_context::executor_type>>(
                     asio::make_work_guard(ioc.get_executor()))) {}

    inline std::shared_ptr<AsioExecutor> AsioExecutor::create_internal() {
        // shared_ptr, not unique_ptr: the driver thread captures the io_context
        // itself, so it stays valid even when this object is destroyed from
        // inside one of its own handlers (shutdown() can then only detach).
        auto own = std::make_shared<asio::io_context>();
        auto& ref = *own;
        auto ex = std::make_shared<AsioExecutor>(ref, std::move(own));
        ex->start_owned_thread();
        return ex;
    }

    inline std::shared_ptr<AsioExecutor> AsioExecutor::create_external(asio::io_context& ioc) {
        return std::make_shared<AsioExecutor>(ioc, nullptr);
    }

    inline AsioExecutor::~AsioExecutor() {
        shutdown();
    }

    inline void AsioExecutor::shutdown() {
        if (stopped_.exchange(true)) return;
        // Releasing the guard is what lets a caller-driven run() drain and return.
        // We never call ioc_.stop() in external mode: that would be a global stop
        // of somebody else's loop, which the spec forbids.
        guard_.reset();
        if (!own_ioc_ || !thread_.joinable()) return;

        ioc_.stop();

        // The last reference to an internal executor can be released inside a
        // handler running on this very thread: the multi-address connect race
        // hands the winning stream to the caller and then releases the losing
        // attempt's TcpStream (which holds the executor) from the loop thread.
        // ~AsioExecutor therefore has to work on its own loop thread, where
        // join() is impossible and a joinable std::thread would call
        // std::terminate (0xC0000409). The driver thread captures the
        // io_context, never `this`, so detaching here is safe: the loop keeps
        // running until run() returns and then releases the last io_context
        // reference itself.
        if (thread_.get_id() == std::this_thread::get_id()) {
            thread_.detach();
            return;
        }
        thread_.join();
    }

    inline void AsioExecutor::start_owned_thread() {
        // Capture the io_context, NOT `this`: see shutdown().
        auto io = own_ioc_;
        thread_ = std::thread([io]() { io->run(); });
    }

    inline void AsioExecutor::post(std::function<void()> fn) {
        if (!fn || stopped_.load()) return;
        // Always goes through the strand and never runs inline, matching the
        // libuv backend's "no recursion on the loop thread" rule.
        asio::post(strand_, std::move(fn));
    }

    inline bool AsioExecutor::try_post(std::function<void()> fn) {
        if (!fn) return false;
        if (stopped_.load()) return false;
        asio::post(strand_, std::move(fn));
        return true;
    }

    inline bool AsioExecutor::is_in_loop_thread() const noexcept {
        // An external io_context may be driven by several threads through the
        // strand, so there is no single loop thread to compare against. Reporting
        // false is honest; guessing would risk a false "deadlock" diagnosis.
        return false;
    }

    inline std::shared_ptr<Timer> AsioExecutor::schedule_after(
        Duration d, std::function<void()> fn) {
        if (!fn || stopped_.load()) return nullptr;
        auto t = std::make_shared<AsioTimer>(ioc_, strand_, d, std::move(fn));
        t->arm();   // arm() runs after shared ownership exists
        return t;
    }

    inline TimePoint AsioExecutor::now() const noexcept {
        return Clock::now();
    }

} // namespace asio_backend
} // namespace megohttp

#endif

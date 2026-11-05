#ifndef MEGOHTTP_EXECUTOR_HPP_INCLUDED
#define MEGOHTTP_EXECUTOR_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace megohttp {

    // Monotonic clock, used for every timeout and backoff computation.
    // Deliberately not steady_clock directly: tests need to inject a clock.
    using Clock = std::chrono::steady_clock;
    using Duration = Clock::duration;
    using TimePoint = Clock::time_point;

    class Timer;

    // Execution context abstraction. Two implementations (libuv, standalone Asio)
    // provide identical semantics, which is what lets the protocol layer be shared.
    //
    // Threading contract, identical for both backends:
    //   • post() is callable from ANY thread and never blocks on the target loop.
    //   • A posted handler runs on the loop's thread, never inline on the caller's.
    //   • is_in_loop_thread() lets the sync API detect the "would deadlock" case.
    class Executor {
    public:
        virtual ~Executor() = default;

        // Schedule `fn` to run on the loop thread. Thread-safe.
        virtual void post(std::function<void()> fn) = 0;

        // True when called from the thread that drives this loop.
        virtual bool is_in_loop_thread() const noexcept = 0;

        // Schedule `fn` after `d`. Thread-safe. Returns null on failure.
        virtual std::shared_ptr<Timer> schedule_after(
            Duration d, std::function<void()> fn) = 0;

        // Current monotonic time from this executor's clock.
        virtual TimePoint now() const noexcept = 0;
    };

    // A one-shot timer. Cancelling is idempotent and safe from any thread;
    // cancellation is asynchronous with respect to the firing handler, so a
    // handler may still run if it had already been queued.
    class Timer {
    public:
        virtual ~Timer() = default;
        virtual void cancel() = 0;
        virtual bool is_cancelled() const noexcept = 0;
    };

    // ---------------------------------------------------------------------------
    // Cancellation token shared across threads.
    // ---------------------------------------------------------------------------
    class CancelState {
    public:
        explicit CancelState(std::shared_ptr<Executor> ex = nullptr)
            : executor_(std::move(ex)) {}

        void cancel() {
            bool expected = false;
            if (!cancelled_.compare_exchange_strong(expected, true)) return;
            std::vector<std::function<void()>> handlers;
            {
                std::lock_guard<std::mutex> lk(m_);
                handlers.swap(handlers_);
            }
            for (auto& h : handlers) {
                if (h) h();
            }
        }

        bool is_cancelled() const noexcept { return cancelled_.load(); }

        // Register a handler fired on cancel. If already cancelled, `fn` runs
        // immediately (on the calling thread) so callers do not need a check plus
        // a registration.
        void on_cancel(std::function<void()> fn) {
            if (is_cancelled()) { if (fn) fn(); return; }
            {
                std::lock_guard<std::mutex> lk(m_);
                if (!cancelled_.load()) { handlers_.push_back(std::move(fn)); return; }
            }
            if (fn) fn();
        }

    private:
        std::atomic<bool> cancelled_{false};
        mutable std::mutex m_;
        std::vector<std::function<void()>> handlers_;
        std::shared_ptr<Executor> executor_;
    };

    // Public, copyable, thread-safe handle. Holding one does not keep the request
    // alive; it only lets another thread ask it to stop.
    class CancelHandle {
    public:
        CancelHandle() = default;
        explicit CancelHandle(std::shared_ptr<CancelState> s) : state_(std::move(s)) {}

        void cancel() const { if (state_) state_->cancel(); }
        bool is_cancelled() const noexcept { return state_ ? state_->is_cancelled() : false; }
        bool valid() const noexcept { return static_cast<bool>(state_); }
        std::shared_ptr<CancelState> state() const noexcept { return state_; }

    private:
        std::shared_ptr<CancelState> state_;
    };

} // namespace megohttp

#endif // MEGOHTTP_EXECUTOR_HPP_INCLUDED

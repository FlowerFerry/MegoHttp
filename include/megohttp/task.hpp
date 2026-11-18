#ifndef MEGOHTTP_TASK_HPP_INCLUDED
#define MEGOHTTP_TASK_HPP_INCLUDED

// C++20 coroutine support for MegoHttp (stage 7).
//
// Eager: the coroutine body starts running immediately on construction, up to
// the first real suspension. A coroutine that returns without suspending is
// already done by the time the caller receives the Task.
//
// Single-consumer: await_resume() moves the result out and must be called at
// most once. Destroying a suspended Task destroys its frame without resuming
// it -- the work that would have resumed it is dropped, not deferred.
//
// No blocking: co_await suspends the coroutine and resumes it from the
// completion callback (executor thread). Nothing calls future::get(), blocks a
// thread, or polls.
//
// Thread safety: a Task object must not be awaited or destroyed concurrently
// from two threads. The coroutine's producer (the completion callback) runs on
// the Client's executor.

#include <megohttp/config.hpp>

#if MEGOHTTP_HAS_COROUTINES

#include <megohttp/executor.hpp>

#include <coroutine>
#include <exception>
#include <functional>
#include <optional>
#include <stdexcept>
#include <utility>

namespace megohttp {

    template<typename T>
    class Task {
    public:
        struct promise_type;
        using handle_type = std::coroutine_handle<promise_type>;

        // Lets a coroutine body reach its own promise, so it can publish the
        // CancelHandle of the operation it is about to suspend on.
        struct GetPromise {
            using promise_t = promise_type;
        };

        struct PromisePtr {
            promise_type* p{nullptr};
            bool await_ready() const noexcept { return true; }
            void await_suspend(std::coroutine_handle<>) const noexcept {}
            promise_type* await_resume() const noexcept { return p; }
        };

        struct promise_type {
            std::optional<T> value_;
            std::exception_ptr ex_;
            // Shared so Task::cancel() can copy it safely while the coroutine
            // body publishes the handle on another thread.
            std::shared_ptr<CancelHandle> cancel_ = std::make_shared<CancelHandle>();
            std::coroutine_handle<> outer_{nullptr};
            bool consumed_{false};

            Task get_return_object() { return Task{handle_type::from_promise(*this)}; }

            // Eager: begin executing the body right away.
            std::suspend_never initial_suspend() noexcept { return {}; }

            // Suspend at the end so the Task object stays alive until the
            // caller consumes (or destroys) it. Resuming the awaiting coroutine
            // HERE would run it on whatever thread finished the operation,
            // which is the executor -- exactly the documented continuation.
            struct FinalAwaiter {
                bool await_ready() const noexcept { return false; }
                void await_suspend(std::coroutine_handle<promise_type> self) noexcept {
                    auto outer = self.promise().outer_;
                    if (outer) {
                        self.promise().outer_ = nullptr;
                        outer.resume();
                    }
                }
                void await_resume() const noexcept {}
            };
            FinalAwaiter final_suspend() noexcept { return {}; }

            void return_value(T v) { value_.emplace(std::move(v)); }
            void unhandled_exception() { ex_ = std::current_exception(); }

            // Injected so the body can do: auto* p = co_await Task<T>::GetPromise{};
            PromisePtr await_transform(GetPromise) noexcept { return PromisePtr{this}; }

            // Everything else passes through untouched. Without this overload
            // the presence of any await_transform hides the identity one and
            // every ordinary co_await in the body fails to compile.
            template<typename Awaiter>
            Awaiter&& await_transform(Awaiter&& a) noexcept {
                return std::forward<Awaiter>(a);
            }
        };

        // --- Lifetime -------------------------------------------------------
        explicit Task(handle_type h) noexcept : handle_(h) {}
        Task(Task&& o) noexcept : handle_(std::exchange(o.handle_, nullptr)) {}
        Task& operator=(Task&& o) noexcept {
            if (this != &o) {
                if (handle_) handle_.destroy();
                handle_ = std::exchange(o.handle_, nullptr);
            }
            return *this;
        }
        Task(const Task&) = delete;
        Task& operator=(const Task&) = delete;
        ~Task() { if (handle_) handle_.destroy(); }

        // --- Awaitable ------------------------------------------------------
        bool await_ready() const noexcept { return !handle_ || handle_.done(); }

        void await_suspend(std::coroutine_handle<> awaiting) {
            if (!handle_ || handle_.done()) { awaiting.resume(); return; }
            handle_.promise().outer_ = awaiting;
        }

        T await_resume() {
            if (!handle_) throw std::logic_error("Task::await_resume on a moved-from Task");
            auto& p = handle_.promise();
            if (p.ex_) std::rethrow_exception(p.ex_);
            if (!p.value_) throw std::logic_error("Task::await_resume with no value");
            return std::move(*p.value_);
        }

        // --- Control --------------------------------------------------------
        // Cancels the operation the coroutine is suspended on, if any. Safe to
        // call before the body has published its handle (no-op then) and after
        // completion (no-op).
        void cancel() {
            if (!handle_) return;
            auto c = handle_.promise().cancel_;   // shared_ptr copy is atomic
            if (c) c->cancel();
        }

        bool done() const noexcept { return !handle_ || handle_.done(); }
        CancelHandle cancel_handle() const {
            if (!handle_) return CancelHandle{};
            auto c = handle_.promise().cancel_;
            return c ? *c : CancelHandle{};
        }

    private:
        handle_type handle_;
    };

    // -----------------------------------------------------------------------
    // SuspendedOperation: await a callback-driven operation without blocking.
    //
    // `start(done)` runs once from await_suspend. The operation calls
    // done(T) at most once from any thread; a second call is dropped. The state
    // lives in a shared_ptr so a completion that arrives after the awaiting
    // coroutine frame is gone writes into that shared block and finds no waiter
    // -- no dangling `this`, no crash, no resume of a destroyed frame.
    // -----------------------------------------------------------------------
    template<typename T>
    class SuspendedOperation {
        struct State {
            std::optional<T> result;
            std::coroutine_handle<> waiter;
            bool completed{false};
        };

    public:
        SuspendedOperation() : state_(std::make_shared<State>()) {}

        // Awaiter interface
        bool await_ready() const noexcept {
            // Only "already have a result" means ready. An unset waiter is the
            // normal state before the first await, not a completion signal.
            return state_->completed;
        }

        void await_suspend(std::coroutine_handle<> awaiting) {
            auto st = state_;
            if (st->completed) { awaiting.resume(); return; }
            st->waiter = awaiting;
            if (start) start([st](T v) {
                if (st->completed) return;          // exactly-once
                st->completed = true;
                st->result.emplace(std::move(v));
                auto w = st->waiter;
                st->waiter = nullptr;
                if (w) w.resume();                  // null when the frame is gone
            });
        }

        T await_resume() {
            if (!state_->completed || !state_->result) {
                throw std::logic_error("SuspendedOperation resumed without a result");
            }
            return std::move(*state_->result);
        }

        // Set before awaiting. Missing start = already-complete operation.
        std::function<void(std::function<void(T)>)> start;

        // The awaiter object must outlive the suspension; keep it on the
        // coroutine frame by value.
        std::shared_ptr<State> state_;
    };

} // namespace megohttp

#endif // MEGOHTTP_HAS_COROUTINES

#endif // MEGOHTTP_TASK_HPP_INCLUDED

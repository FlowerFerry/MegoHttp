#ifndef MEGOHTTP_EXECUTOR_LIBUV_HPP_INCLUDED
#define MEGOHTTP_EXECUTOR_LIBUV_HPP_INCLUDED

#include <megohttp/executor.hpp>

#if !MGHTTP_BACKEND_LIBUV
#   error "executor_libuv.hpp requires MGHTTP_BACKEND_LIBUV"
#endif

#include <uv.h>

#include <atomic>
#include <deque>
#include <mutex>
#include <thread>

namespace megohttp {
namespace libuv_backend {

    // libuv-based executor.
    //
    // Ownership model (spec 5.2):
    //   • Internal mode: the executor creates and owns the loop AND its thread.
    //   • External mode: the executor borrows a caller-owned uv_loop_t. It never
    //     runs or stops that loop and never destroys it.
    //
    // In external mode the caller must keep driving the loop until close() has
    // completed; there is no way to guarantee progress otherwise, and pretending
    // otherwise is what the spec forbids.
    class UvExecutor final : public Executor,
                             public std::enable_shared_from_this<UvExecutor> {
    public:
        // Internal loop + own thread.
        static std::shared_ptr<UvExecutor> create_internal();

        // Borrow a caller-owned loop. The caller keeps it alive AND drives it.
        //
        // Contract (spec 5.2): the caller must keep driving the loop until close
        // completes. This executor never runs, stops or destroys that loop, and
        // never creates a thread for it.
        //
        // Because uv_async_init may only be called from the loop's thread, the
        // wake handle is initialized lazily by whichever thread first calls
        // post() while running the loop; work posted before that is retained and
        // drained on the first opportunity.
        static std::shared_ptr<UvExecutor> create_external(uv_loop_t* loop);

        ~UvExecutor() override;

        // --- Executor ---
        void post(std::function<void()> fn) override;
        bool is_in_loop_thread() const noexcept override;
        std::shared_ptr<Timer> schedule_after(Duration d, std::function<void()> fn) override;
        TimePoint now() const noexcept override;

        // --- Internal-mode lifecycle ---
        // Stops the owned loop and joins the thread. No-op in external mode
        // (the executor never stops someone else's loop). Blocks; must not be
        // called from the loop thread.
        void shutdown();

        uv_loop_t* loop() const noexcept { return loop_; }
        bool owns_loop() const noexcept { return owns_loop_; }

        // External mode only: call once from the thread that drives the loop to
        // install the wake handle immediately. Optional -- the first post() from
        // that thread does the same thing -- but it removes any ambiguity.
        void initialize_external_wake_handle();

    // The constructor is public so std::make_shared can reach it; use
    // create_internal()/create_external() -- the ownership contract (who closes
    // and destroys the loop) lives there, not in the constructor.
    public:
        UvExecutor(uv_loop_t* loop, bool owns);

    private:

        void start_owned_thread();
        void drain_pending();
        void attach_wake_handle_if_on_loop_thread();
        static void on_async(uv_async_t* h);
        static void on_wake_timer(uv_timer_t* h);

        uv_loop_t* loop_{nullptr};
        bool owns_loop_{false};

        // Cross-thread post queue. libuv's uv_async_t wakes the loop; the queue
        // itself is protected by this mutex, and the loop drains it on wake.
        std::mutex q_m_;
        std::deque<std::function<void()>> q_;
        uv_async_t async_{};
        bool async_initialized_{false};

        std::thread thread_;
        std::atomic<bool> stopping_{false};
        std::atomic<std::thread::id> loop_thread_id_{};
        bool started_{false};
    };

    // A timer handle returned before the underlying uv_timer_t exists.
    //
    // schedule_after() may be called from any thread, but libuv demands the
    // handle be created on the loop thread. So the caller receives this proxy
    // immediately and the real timer is attached from the loop thread. cancel()
    // before attachment is remembered and honoured, which is what keeps a
    // cancel-versus-arm race deterministic.
    class DeferredTimer final : public Timer,
                                public std::enable_shared_from_this<DeferredTimer> {
    public:
        void cancel() override;
        bool is_cancelled() const noexcept override { return cancelled_.load(); }

        // Attach the real timer. If this proxy was already cancelled, the real one
        // is cancelled immediately and never fires.
        void attach(std::shared_ptr<Timer> real);

        // A timer keeps ITSELF alive until it fires or is cancelled, so a caller
        // that drops the handle immediately is not silently cancelling the timer.
        // (Firing only after the caller released the handle is the common case:
        // `exec->schedule_after(100ms, f);` must run f.)
        void keep_alive();

    private:
        std::atomic<bool> cancelled_{false};
        std::mutex m_;
        std::shared_ptr<Timer> real_;
        // Self-reference held while the timer is armed; cleared on fire or cancel.
        std::shared_ptr<DeferredTimer> self_;
    };

    // libuv timer.
    //
    // uv_close() is asynchronous, so the uv_timer_t must outlive the UvTimer
    // object. The handle therefore lives in a separately owned Node that keeps
    // ITSELF alive until libuv delivers the close callback. The Node holds a
    // weak_ptr back to the UvTimer, so the pair cannot form a reference cycle.
    class UvTimer final : public Timer,
                          public std::enable_shared_from_this<UvTimer> {
    public:
        UvTimer(uv_loop_t* loop, Duration d, std::function<void()> fn);
        ~UvTimer() override;

        void cancel() override;
        bool is_cancelled() const noexcept override { return cancelled_.load(); }

        // Install the self-reference the timer callback needs. Must be called
        // through the owning shared_ptr, immediately after construction:
        // weak_from_this() is empty while the constructor is still running.
        void arm();

        // Install the loop-thread dispatch and the "am I on the loop thread"
        // probe. Both are required for safe cross-thread cancel/destruction:
        // uv_timer_stop and uv_close are handle operations and libuv forbids
        // calling them off the loop thread.
        void set_dispatch(std::function<void(std::function<void()>)> post,
                          std::function<bool()> on_loop_thread);

        // Invoked after the handler runs, so the owner can release its self-hold.
        void set_on_fired(std::function<void()> fn) { on_fired_ = std::move(fn); }

    private:
        struct Node {
            uv_timer_t handle{};
            std::weak_ptr<UvTimer> owner;  // non-owning back-reference
            // Self-hold: keeps the Node (and its embedded uv handle) alive until
            // the asynchronous close callback runs. Cleared there.
            std::shared_ptr<Node> self;
        };

        static void on_timeout(uv_timer_t* h);
        static void on_closed(uv_handle_t* h);

        // Stops and closes the handle. ONLY on the loop thread.
        void stop_and_close_locked();

        std::shared_ptr<Node> node_;
        std::function<void()> fn_;
        std::function<void()> on_fired_;
        std::function<void(std::function<void()>)> post_;
        std::function<bool()> on_loop_thread_;
        std::atomic<bool> cancelled_{false};
    };

} // namespace libuv_backend
} // namespace megohttp

#include <megohttp/backend/executor_libuv_impl.hpp>

#endif // MEGOHTTP_EXECUTOR_LIBUV_HPP_INCLUDED

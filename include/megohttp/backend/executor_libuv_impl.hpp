#ifndef MEGOHTTP_EXECUTOR_LIBUV_IMPL_HPP_INCLUDED
#define MEGOHTTP_EXECUTOR_LIBUV_IMPL_HPP_INCLUDED

// Header-only, all definitions inline. Linked against libuv.

namespace megohttp {
namespace libuv_backend {

    // --- UvTimer ---------------------------------------------------------------

    inline UvTimer::UvTimer(uv_loop_t* loop, Duration d, std::function<void()> fn)
        : fn_(std::move(fn)) {
        // Node owns the uv handle and holds a weak_ptr back to UvTimer, so the two
        // cannot form a reference cycle. The Node also self-holds (see .self) so
        // that libuv's asynchronous close callback always has live storage to work
        // with, even after the UvTimer is long gone.
        node_ = std::make_shared<Node>();
        node_->self = node_;
        // NOTE: weak_from_this() is EMPTY inside the constructor -- the
        // enable_shared_from_this base is wired up only once the owning shared_ptr
        // exists. arm() installs the back-reference right after construction.
        uv_timer_init(loop, &node_->handle);
        node_->handle.data = node_.get();

        const uint64_t ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(d).count());
        uv_timer_start(&node_->handle, &UvTimer::on_timeout, ms, 0);
    }

    inline void UvTimer::arm() {
        // Called through the owning shared_ptr, at which point weak_from_this() is
        // valid.
        if (node_) node_->owner = weak_from_this();
    }

    inline UvTimer::~UvTimer() {
        cancelled_.store(true);
        if (!node_) return;

        // Drop the back-reference so a late timeout callback cannot resurrect us.
        node_->owner.reset();
        // The Node keeps itself alive from here on: `self` is only cleared by
        // on_closed, i.e. after libuv has finished with the handle.
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&node_->handle))) {
            uv_timer_stop(&node_->handle);
            uv_close(reinterpret_cast<uv_handle_t*>(&node_->handle), &UvTimer::on_closed);
        }
    }

    inline void UvTimer::cancel() {
        if (cancelled_.exchange(true)) return;
        if (node_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(&node_->handle))) {
            uv_timer_stop(&node_->handle);
        }
    }

    inline void UvTimer::on_timeout(uv_timer_t* h) {
        auto* node = static_cast<Node*>(h->data);
        if (node == nullptr) return;
        // Lock: if the UvTimer is already gone, the weak_ptr yields null and the
        // callback does nothing instead of touching freed memory.
        auto self = node->owner.lock();
        if (!self) return;
        if (self->cancelled_.load()) return;
        auto fn = std::move(self->fn_);
        self->fn_ = nullptr;
        // Release the owner's self-hold BEFORE running the handler, so a handler
        // that drops the last handle does not resurrect the timer.
        auto on_fired = std::move(self->on_fired_);
        self->on_fired_ = nullptr;
        if (on_fired) on_fired();
        if (fn) fn();
    }

    inline void UvTimer::on_closed(uv_handle_t* h) {
        auto* node = static_cast<Node*>(h->data);
        if (node == nullptr) return;
        h->data = nullptr;
        // Break the self-hold; the Node (and the embedded uv handle) is destroyed
        // as soon as this function returns and no other owner remains.
        node->self.reset();
    }

    // --- DeferredTimer ---------------------------------------------------------

    inline void DeferredTimer::cancel() {
        cancelled_.store(true);
        std::lock_guard<std::mutex> lk(m_);
        if (real_) real_->cancel();
        self_.reset();
    }

    inline void DeferredTimer::keep_alive() {
        // Capture self; released when the timer fires or is cancelled.
        self_ = shared_from_this();
    }

    inline void DeferredTimer::attach(std::shared_ptr<Timer> real) {
        std::lock_guard<std::mutex> lk(m_);
        real_ = real;
        if (cancelled_.load() && real_) { real_->cancel(); self_.reset(); return; }

        auto self = shared_from_this();
        if (auto* uv_t = dynamic_cast<UvTimer*>(real.get())) {
            uv_t->set_on_fired([self]() mutable {
                std::lock_guard<std::mutex> lk2(self->m_);
                self->self_.reset();
            });
        }
    }

    // --- UvExecutor ------------------------------------------------------------

    inline std::shared_ptr<UvExecutor> UvExecutor::create_internal() {
        // uv_loop_init needs storage that outlives the loop. A unique_ptr with the
        // uv_loop_close deleter states that ownership explicitly; no manual
        // new/delete anywhere.
        auto loop = std::make_unique<uv_loop_t>();
        if (uv_loop_init(loop.get()) != 0) {
            return nullptr;   // loop memory freed when `loop` leaves scope
        }
        // The executor takes ownership of the initialized loop; hand it over.
        auto ex = std::make_shared<UvExecutor>(loop.release(), true);
        ex->start_owned_thread();
        return ex;
    }

    inline std::shared_ptr<UvExecutor> UvExecutor::create_external(uv_loop_t* loop) {
        if (loop == nullptr) return nullptr;
        auto ex = std::make_shared<UvExecutor>(loop, false);

        // The wake handle must be created on the loop's thread, which we cannot
        // know from here. The caller calls initialize_external_wake_handle() once
        // from its driver thread; until then posts are queued (never dropped).
        return ex;
    }

    inline UvExecutor::UvExecutor(uv_loop_t* loop, bool owns)
        : loop_(loop), owns_loop_(owns) {}

    inline UvExecutor::~UvExecutor() {
        shutdown();
    }

    inline void UvExecutor::start_owned_thread() {
        // uv_async_t is used to wake the loop when another thread posts work.
        // Initialize it here (before the thread starts) so a post() that races
        // construction still has a live handle to signal.
        uv_async_init(loop_, &async_, &UvExecutor::on_async);
        async_.data = this;
        async_initialized_ = true;

        started_ = true;
        thread_ = std::thread([this] {
            loop_thread_id_.store(std::this_thread::get_id());
            // Drain anything queued before the loop started.
            drain_pending();
            uv_run(loop_, UV_RUN_DEFAULT);
            // Drain anything still queued so posted handlers are not silently lost.
            drain_pending();
        });
    }

    inline void UvExecutor::shutdown() {
        if (stopping_.exchange(true)) return;

        if (!owns_loop_) {
            // External loop: handles we created are still OUR resources, so they
            // must be closed -- but uv_close is asynchronous and only the caller's
            // loop can complete it. Mark it closing and let that loop finish. The
            // loop itself is never stopped, run, or destroyed.
            if (async_initialized_) {
                async_.data = nullptr;
                uv_close(reinterpret_cast<uv_handle_t*>(&async_), nullptr);
                async_initialized_ = false;
            }
            return;
        }

        if (started_) {
            // Stop the owned loop and join our thread.
            uv_stop(loop_);
            if (async_initialized_) uv_async_send(&async_);
            if (thread_.joinable() && thread_.get_id() != std::this_thread::get_id()) {
                thread_.join();
            }
            started_ = false;
        }

        if (loop_ != nullptr) {
            // Close every remaining handle (including our async handle), let the
            // close callbacks run, then destroy the loop.
            uv_walk(loop_, [](uv_handle_t* h, void*) {
                if (!uv_is_closing(h)) uv_close(h, nullptr);
            }, nullptr);
            uv_run(loop_, UV_RUN_DEFAULT);
            uv_loop_close(loop_);
            // Adopt the loop memory so it is freed on scope exit, without a manual
            // delete. Ownership came from make_unique in create_internal().
            std::unique_ptr<uv_loop_t> owned(loop_);
            loop_ = nullptr;
        }
        async_initialized_ = false;
    }

    inline void UvExecutor::post(std::function<void()> fn) {
        if (!fn) return;
        {
            std::lock_guard<std::mutex> lk(q_m_);
            q_.push_back(std::move(fn));
        }
        if (async_initialized_) {
            // Wake the loop; it drains from the async callback. A handler that
            // posts again is deferred rather than recursing on the stack.
            uv_async_send(&async_);
        }
        // Without a wake handle (external mode before initialize_external_wake_handle
        // was called) the work stays queued. The caller is driving the loop and is
        // expected to call initialize_external_wake_handle() once, after which every
        // post is signalled properly. Nothing is lost; it is just not yet woken.
    }

    inline bool UvExecutor::is_in_loop_thread() const noexcept {
        // Internal mode: we started the thread, so its id is authoritative.
        // External mode: we never started the loop and cannot know which thread
        // drives it. Adopting the first poster's id would be a guess, and a wrong
        // guess silently breaks the sync-API deadlock check. So external mode
        // reports false and the documented contract applies instead: the caller
        // supplies a thread that keeps driving the loop, and the sync API must be
        // called from another thread.
        if (!owns_loop_) return false;
        const auto id = loop_thread_id_.load();
        return id != std::thread::id{} && id == std::this_thread::get_id();
    }

    inline void UvExecutor::initialize_external_wake_handle() {
        if (owns_loop_ || async_initialized_ || stopping_.load()) return;
        uv_async_init(loop_, &async_, &UvExecutor::on_async);
        async_.data = this;
        async_initialized_ = true;
    }

    inline void UvExecutor::drain_pending() {
        for (;;) {
            std::function<void()> fn;
            {
                std::lock_guard<std::mutex> lk(q_m_);
                if (q_.empty()) return;
                fn = std::move(q_.front());
                q_.pop_front();
            }
            if (fn) fn();
        }
    }

    inline void UvExecutor::on_async(uv_async_t* h) {
        auto* self = static_cast<UvExecutor*>(h->data);
        if (self == nullptr) return;
        self->drain_pending();
    }

    inline void UvExecutor::on_wake_timer(uv_timer_t*) {}

    inline std::shared_ptr<Timer> UvExecutor::schedule_after(
        Duration d, std::function<void()> fn) {
        if (!fn || loop_ == nullptr) return nullptr;

        // Creating the uv_timer_t must happen on the loop thread (libuv rule), so
        // this call is marshalled through post() rather than blocking the caller
        // with a handshake. The returned timer is usable immediately: cancel()
        // before it is armed flips the flag the arming code checks, so a cancel
        // racing the post still wins.
        auto timer = std::make_shared<DeferredTimer>();
        timer->keep_alive();       // survives a caller that drops the handle
        post([this, d, fn = std::move(fn), timer]() mutable {
            if (timer->is_cancelled()) return;
            auto real = std::make_shared<UvTimer>(loop_, d, std::move(fn));
            // arm() must run through the shared_ptr: weak_from_this() is still
            // empty inside the constructor.
            real->arm();
            timer->attach(real);
        });
        return timer;
    }

    inline TimePoint UvExecutor::now() const noexcept {
        return std::chrono::steady_clock::now();
    }

} // namespace libuv_backend
} // namespace megohttp

#endif // MEGOHTTP_EXECUTOR_LIBUV_IMPL_HPP_INCLUDED

// mpmc_lockfree_no_new.hpp
#pragma once

#include <atomic>
#include <boost/lockfree/queue.hpp>
#include <cassert>
#include <condition_variable>
#include <mutex>
#include <thread>

template <typename T>
class MPMCQueue
{
public:
    // capacity must be > 0 (power-of-two recommended but not required).
    // The underlying boost::lockfree::queue will use this capacity.
    explicit MPMCQueue(std::size_t capacity = 1024)
        : q_(capacity), capacity_(capacity)
    {
        assert(capacity_ > 0 && "capacity must be > 0");
    }

    ~MPMCQueue()
    {
        // drain queue (best-effort) to leave no pending objects.
        T tmp;
        while (q_.pop(tmp))
        {
            // if T has non-trivial destructor, it will be called here.
            // nothing else to do.
        }
    }

    // Non-copyable
    MPMCQueue(const MPMCQueue &) = delete;
    MPMCQueue &operator=(const MPMCQueue &) = delete;

    // Try push (non-blocking). Returns true if pushed, false if full.
    bool try_push(const T &value)
    {
        bool ok = q_.push(value);
        if (ok)
            notify_one_not_empty();
        return ok;
    }

    bool try_push(T &&value)
    {
        bool ok = q_.push(std::move(value));
        if (ok)
            notify_one_not_empty();
        return ok;
    }

    // Blocking push: wait until there is space then push.
    // Returns true when pushed.
    void push(const T &value)
    {
        // Fast-path try
        if (q_.push(value))
        {
            notify_one_not_empty();
            return;
        }

        // Otherwise wait until notified by a pop (not_full)
        std::unique_lock<std::mutex> lk(cv_mtx_);
        not_full_cv_.wait(lk, [&]
                          { return q_.push(value); });
        // pushed, now notify consumer(s)
        notify_one_not_empty();
    }

    void push(T &&value)
    {
        if (q_.push(std::move(value)))
        {
            notify_one_not_empty();
            return;
        }

        std::unique_lock<std::mutex> lk(cv_mtx_);
        not_full_cv_.wait(lk, [&]
                          { return q_.push(std::move(value)); });
        notify_one_not_empty();
    }

    // Try pop (non-blocking). Returns true and sets out if successful.
    bool try_pop(T &out)
    {
        if (q_.pop(out))
        {
            notify_one_not_full();
            return true;
        }
        return false;
    }

    // Blocking pop: wait until an element is available and pop into out.
    void pop(T &out)
    {
        // Fast-path try
        if (q_.pop(out))
        {
            notify_one_not_full();
            return;
        }

        std::unique_lock<std::mutex> lk(cv_mtx_);
        not_empty_cv_.wait(lk, [&]
                           { return !q_.empty(); });
        // After wakeup, we try to pop until success (handle spurious wakeups and races)
        while (!q_.pop(out))
        {
            // yield briefly
            std::this_thread::yield();
        }
        notify_one_not_full();
    }

    // Approximate size (backed by boost method if available).
    std::size_t approx_size() const
    {
#if defined(BOOST_LOCKFREE_QUEUE_HAS_UNSAFE_SIZE)
        return q_.unsafe_size();
#else
        // fallback: no direct size API -> cannot cheaply provide exact size; return 0 as unknown.
        return 0;
#endif
    }

    bool empty() const noexcept { return q_.empty(); }

private:
    // notify helpers: we use a single mutex for condition variables.
    void notify_one_not_empty()
    {
        // notify consumers that an item exists
        not_empty_cv_.notify_one();
    }

    void notify_one_not_full()
    {
        // notify producers that space may exist
        not_full_cv_.notify_one();
    }

    boost::lockfree::queue<T> q_;
    const std::size_t capacity_;

    // condition variables + one mutex for blocking semantics only
    mutable std::mutex cv_mtx_;
    std::condition_variable not_empty_cv_;
    std::condition_variable not_full_cv_;
};

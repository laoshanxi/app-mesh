// test/queue/mpmc_lockfree_queue.hpp
#pragma once

#include <atomic>
#include <boost/lockfree/queue.hpp>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

template <typename T>
class LockFreeQueue
{
public:
    // capacity == 0 -> let boost choose internal default (implementation detail),
    // or pass a power-of-two size to preallocate internal buffer for lower alloc churn.
    explicit LockFreeQueue(std::size_t capacity = 0)
        : q_(capacity)
    {
    }

    ~LockFreeQueue()
    {
        // Drain and delete any remaining pointers to avoid leaks
        T *p = nullptr;
        while (q_.pop(p))
        {
            delete p;
        }
    }

    // Non-copyable
    LockFreeQueue(const LockFreeQueue &) = delete;
    LockFreeQueue &operator=(const LockFreeQueue &) = delete;

    // Enqueue by copy
    void enqueue(const T &v)
    {
        T *p = new T(v);
        push_ptr_blocking(p);
    }

    // Enqueue by move
    void enqueue(T &&v)
    {
        T *p = new T(std::move(v));
        push_ptr_blocking(p);
    }

    // In-place construct
    template <typename... Args>
    void emplace(Args &&...args)
    {
        T *p = new T(std::forward<Args>(args)...);
        push_ptr_blocking(p);
    }

    // Non-blocking pop: returns unique_ptr (null if empty)
    std::unique_ptr<T> try_pop()
    {
        T *p = nullptr;
        if (q_.pop(p))
            return std::unique_ptr<T>(p);
        return nullptr;
    }

    // Blocking pop: waits until an element is available and returns it
    std::unique_ptr<T> pop()
    {
        T *p = nullptr;
        // Fast-path: try immediately
        if (q_.pop(p))
            return std::unique_ptr<T>(p);

        // Otherwise wait for notification. Use loop to handle spurious wakeups.
        std::unique_lock<std::mutex> lk(mtx_);
        cv_.wait(lk, [&]
                 { return !q_.empty(); });
        // After wakeup, try to pop (loop in case multiple consumers)
        while (!q_.pop(p))
        {
            // small backoff to avoid tight-spin on rare races
            std::this_thread::yield();
        }
        return std::unique_ptr<T>(p);
    }

    // Returns approximate size (may be costly or inaccurate depending on implementation)
    std::size_t approx_size() const
    {
        return q_.unsafe_size();
    }

    bool empty() const
    {
        return q_.empty();
    }

private:
    // push pointer into lockfree queue; spin until successful then notify one waiting consumer.
    void push_ptr_blocking(T *p)
    {
        // try pushing; if queue is bounded and full, spin until space
        while (!q_.push(p))
        {
            // backoff
            std::this_thread::yield();
        }
        // notify one waiting consumer
        {
            std::lock_guard<std::mutex> lk(mtx_);
            // no state to change; notify only
        }
        cv_.notify_one();
    }

    // Underlying MPMC lockfree queue stores pointers to T
    boost::lockfree::queue<T *> q_;

    // Wait/notify for blocking pop() only — does not affect lock-free properties.
    mutable std::mutex mtx_;
    std::condition_variable cv_;
};

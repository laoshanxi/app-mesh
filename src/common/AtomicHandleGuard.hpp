// src/common/AtomicHandleGuard.hpp
#pragma once

#include <ace/OS_NS_unistd.h>
#include <atomic>

class AtomicHandleGuard final
{
public:
    explicit AtomicHandleGuard(ACE_HANDLE handle = ACE_INVALID_HANDLE) noexcept
        : m_handle(handle) {}

    ~AtomicHandleGuard() noexcept
    {
        reset();
    }

    // Non-copyable, non-movable
    AtomicHandleGuard(const AtomicHandleGuard &) = delete;
    AtomicHandleGuard &operator=(const AtomicHandleGuard &) = delete;
    AtomicHandleGuard(AtomicHandleGuard &&) = delete;
    AtomicHandleGuard &operator=(AtomicHandleGuard &&) = delete;

    void reset(ACE_HANDLE newHandle = ACE_INVALID_HANDLE) noexcept
    {
        ACE_HANDLE old = m_handle.exchange(newHandle, std::memory_order_acq_rel);
        if (old != ACE_INVALID_HANDLE)
        {
            ACE_OS::close(old);
        }
    }

    ACE_HANDLE get() const noexcept
    {
        return m_handle.load(std::memory_order_relaxed);
    }

    bool valid() const noexcept
    {
        return get() != ACE_INVALID_HANDLE;
    }

private:
    std::atomic<ACE_HANDLE> m_handle;
};

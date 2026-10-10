// src/common/AtomicHandleGuard.hpp
#pragma once

#include <atomic>

#if defined(_WIN32)
#include <windows.h>
using native_fd = void *;
constexpr native_fd INVALID_FD = nullptr;
#else
#include <unistd.h>
using native_fd = int;
constexpr native_fd INVALID_FD = -1;
#endif

class AtomicHandleGuard final
{
public:
    explicit AtomicHandleGuard(native_fd handle = INVALID_FD) noexcept
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

    void reset(native_fd newHandle = INVALID_FD) noexcept
    {
        native_fd old = m_handle.exchange(newHandle, std::memory_order_acq_rel);
        if (old != INVALID_FD)
        {
#if defined(_WIN32)
            ::CloseHandle(reinterpret_cast<HANDLE>(old));
#else
            ::close(old);
#endif
        }
    }

    native_fd get() const noexcept
    {
        return m_handle.load(std::memory_order_relaxed);
    }

    bool valid() const noexcept
    {
        return get() != INVALID_FD;
    }

private:
    std::atomic<native_fd> m_handle;
};

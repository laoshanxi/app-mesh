// src/common/os/handler.hpp
#pragma once

#if defined(_WIN32)
#include <windows.h>

namespace os
{
    // RAII wrapper for Windows HANDLE
    class HandleRAII
    {
    private:
        HANDLE handle_;

    public:
        explicit HandleRAII(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}

        ~HandleRAII()
        {
            if (handle_ != INVALID_HANDLE_VALUE && handle_ != NULL)
            {
                CloseHandle(handle_);
            }
        }

        // Non-copyable
        HandleRAII(const HandleRAII &) = delete;
        HandleRAII &operator=(const HandleRAII &) = delete;

        // Movable
        HandleRAII(HandleRAII &&other) noexcept : handle_(other.handle_)
        {
            other.handle_ = INVALID_HANDLE_VALUE;
        }

        HandleRAII &operator=(HandleRAII &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                handle_ = other.handle_;
                other.handle_ = INVALID_HANDLE_VALUE;
            }
            return *this;
        }

        HANDLE get() const { return handle_; }
        HANDLE release()
        {
            HANDLE temp = handle_;
            handle_ = INVALID_HANDLE_VALUE;
            return temp;
        }

        void reset(HANDLE newHandle = INVALID_HANDLE_VALUE)
        {
            if (handle_ != INVALID_HANDLE_VALUE && handle_ != NULL)
            {
                CloseHandle(handle_);
            }
            handle_ = newHandle;
        }

        bool valid() const
        {
            return handle_ != INVALID_HANDLE_VALUE && handle_ != NULL;
        }

        // Allow implicit conversion to HANDLE for API calls
        operator HANDLE() const { return handle_; }
    };
}
#endif
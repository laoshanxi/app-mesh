// src/common/os/malloc.hpp
#pragma once

namespace os
{

    // RAII wrapper for malloc'd memory
    template <typename T>
    class MallocRAII
    {
    private:
        T *ptr_;

    public:
        explicit MallocRAII(T *ptr = nullptr) : ptr_(ptr) {}

        ~MallocRAII()
        {
            if (ptr_)
            {
                free(ptr_);
            }
        }

        // Non-copyable
        MallocRAII(const MallocRAII &) = delete;
        MallocRAII &operator=(const MallocRAII &) = delete;

        // Movable
        MallocRAII(MallocRAII &&other) noexcept : ptr_(other.ptr_)
        {
            other.ptr_ = nullptr;
        }

        MallocRAII &operator=(MallocRAII &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                ptr_ = other.ptr_;
                other.ptr_ = nullptr;
            }
            return *this;
        }

        T *get() const { return ptr_; }
        T *release()
        {
            T *temp = ptr_;
            ptr_ = nullptr;
            return temp;
        }

        void reset(T *newPtr = nullptr)
        {
            if (ptr_)
            {
                free(ptr_);
            }
            ptr_ = newPtr;
        }

        bool valid() const { return ptr_ != nullptr; }

        // Allow pointer-like operations
        T &operator*() const { return *ptr_; }
        T *operator->() const { return ptr_; }
        operator T *() const { return ptr_; }
    };
}
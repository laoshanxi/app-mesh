// src/common/os/malloc.hpp
#pragma once

namespace os
{

	// RAII wrapper for malloc'd memory
	template <typename T> class MallocRAII
	{
	private:
		T *m_ptr;

	public:
		explicit MallocRAII(T *ptr = nullptr) : m_ptr(ptr) {}

		~MallocRAII()
		{
			if (m_ptr)
			{
				free(m_ptr);
			}
		}

		// Non-copyable
		MallocRAII(const MallocRAII &) = delete;
		MallocRAII &operator=(const MallocRAII &) = delete;

		// Movable
		MallocRAII(MallocRAII &&other) noexcept : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }

		MallocRAII &operator=(MallocRAII &&other) noexcept
		{
			if (this != &other)
			{
				reset();
				m_ptr = other.m_ptr;
				other.m_ptr = nullptr;
			}
			return *this;
		}

		T *get() const { return m_ptr; }
		T *release()
		{
			T *temp = m_ptr;
			m_ptr = nullptr;
			return temp;
		}

		void reset(T *newPtr = nullptr)
		{
			if (m_ptr)
			{
				free(m_ptr);
			}
			m_ptr = newPtr;
		}

		bool valid() const { return m_ptr != nullptr; }

		// Allow pointer-like operations
		T &operator*() const { return *m_ptr; }
		T *operator->() const { return m_ptr; }
		operator T *() const { return m_ptr; }
	};
}

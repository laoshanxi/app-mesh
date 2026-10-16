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
		HANDLE m_handle;

	public:
		explicit HandleRAII(HANDLE handle = INVALID_HANDLE_VALUE) : m_handle(handle) {}

		~HandleRAII()
		{
			if (m_handle != INVALID_HANDLE_VALUE && m_handle != NULL)
			{
				CloseHandle(m_handle);
			}
		}

		// Non-copyable
		HandleRAII(const HandleRAII &) = delete;
		HandleRAII &operator=(const HandleRAII &) = delete;

		// Movable
		HandleRAII(HandleRAII &&other) noexcept : m_handle(other.m_handle) { other.m_handle = INVALID_HANDLE_VALUE; }

		HandleRAII &operator=(HandleRAII &&other) noexcept
		{
			if (this != &other)
			{
				reset();
				m_handle = other.m_handle;
				other.m_handle = INVALID_HANDLE_VALUE;
			}
			return *this;
		}

		HANDLE get() const { return m_handle; }
		HANDLE release()
		{
			HANDLE temp = m_handle;
			m_handle = INVALID_HANDLE_VALUE;
			return temp;
		}

		void reset(HANDLE newHandle = INVALID_HANDLE_VALUE)
		{
			if (m_handle != INVALID_HANDLE_VALUE && m_handle != NULL)
			{
				CloseHandle(m_handle);
			}
			m_handle = newHandle;
		}

		bool valid() const { return m_handle != INVALID_HANDLE_VALUE && m_handle != NULL; }

		// Allow implicit conversion to HANDLE for API calls
		operator HANDLE() const { return m_handle; }
	};
}
#endif

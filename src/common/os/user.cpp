// src/common/os/user.cpp
// Platform-agnostic user utilities.

#include "user.h"

#include <cstdint>
#include <string>

namespace os
{

	unsigned int hashSidToUid(const std::string &sidString)
	{
		constexpr uint32_t FNV_OFFSET_BASIS = 2166136261U;
		constexpr uint32_t FNV_PRIME = 16777619U;

		uint32_t hash = FNV_OFFSET_BASIS;
		for (char c : sidString)
		{
			hash ^= static_cast<uint32_t>(c);
			hash *= FNV_PRIME;
		}

		return (hash & 0x7FFFFFFF) % 1000000 + 1000;
	}

} // namespace os

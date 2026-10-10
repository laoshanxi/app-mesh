// src/common/os/user_windows.cpp
// Windows-specific user utilities.

#include "user.h"

#include <memory>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <lmcons.h>
#include <sddl.h>
#include <windows.h>

#pragma comment(lib, "advapi32.lib")

#include "../Utility.h"
#include "handler.hpp"

namespace os
{

	std::optional<std::pair<unsigned int, unsigned int>> getUidByName(const std::string &userName)
	{
		const static char fname[] = "os::getUidByName() ";

		if (userName.empty())
		{
			LOG_ERR << fname << "Empty username provided";
			return std::nullopt;
		}

		PSID userSid = nullptr;
		DWORD sidSize = 0;
		DWORD domainSize = 0;
		SID_NAME_USE sidType;

		if (!LookupAccountNameA(nullptr, userName.c_str(), nullptr, &sidSize, nullptr, &domainSize, &sidType))
		{
			DWORD error = GetLastError();
			if (error != ERROR_INSUFFICIENT_BUFFER)
			{
				LOG_ERR << fname << "User does not exist: " << userName << " Error: " << error;
				return std::nullopt;
			}
		}

		std::vector<BYTE> sidBuffer(sidSize);
		std::vector<char> domainBuffer(domainSize);
		userSid = reinterpret_cast<PSID>(sidBuffer.data());

		if (!LookupAccountNameA(nullptr, userName.c_str(), userSid, &sidSize, domainBuffer.data(), &domainSize, &sidType))
		{
			LOG_ERR << fname << "Failed to lookup account: " << userName << " Error: " << GetLastError();
			return std::nullopt;
		}

		LPSTR sidString = nullptr;
		if (!ConvertSidToStringSidA(userSid, &sidString))
		{
			LOG_ERR << fname << "Failed to convert SID to string for user: " << userName;
			return std::nullopt;
		}

		std::unique_ptr<void, decltype(&LocalFree)> sidStringPtr(sidString, LocalFree);

		const auto uid = hashSidToUid(std::string(sidString));
		constexpr unsigned int groupid = 1000;

		LOG_DBG << fname << "Windows user " << userName << " mapped to UID: " << uid << " GID: " << groupid;
		return std::make_pair(uid, groupid);
	}

	uid_t get_uid()
	{
		HandleRAII hToken;
		HANDLE tempToken = nullptr;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tempToken))
		{
			return static_cast<uid_t>(-1);
		}
		hToken.reset(tempToken);

		DWORD size = 0;
		if (!GetTokenInformation(hToken.get(), TokenUser, nullptr, 0, &size))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				return static_cast<uid_t>(-1);
			}
		}

		std::vector<BYTE> buffer(size);
		TOKEN_USER *user = reinterpret_cast<TOKEN_USER *>(buffer.data());
		if (!GetTokenInformation(hToken.get(), TokenUser, user, size, &size))
		{
			return static_cast<uid_t>(-1);
		}

		LPSTR sidString = nullptr;
		if (!ConvertSidToStringSidA(user->User.Sid, &sidString))
		{
			return static_cast<uid_t>(-1);
		}

		std::unique_ptr<void, decltype(&LocalFree)> sidStringPtr(sidString, LocalFree);

		return hashSidToUid(std::string(sidString));
	}

	std::string getUsernameByUid(uid_t uid /* = get_uid() */)
	{
		const static char fname[] = "os::getUsernameByUid() ";

		if (uid == static_cast<uid_t>(-1))
		{
			LOG_WAR << fname << "Invalid UID provided";
			return "";
		}

		uid_t currentUid = get_uid();
		if (uid == currentUid)
		{
			DWORD bufferSize = UNLEN + 1;
			std::vector<char> username(bufferSize);

			if (GetUserNameA(username.data(), &bufferSize))
			{
				std::string result(username.data());

				if (auto ids = getUidByName(result); ids && ids->first == uid)
				{
					return result;
				}
			}
		}

		LOG_WAR << fname << "Cannot resolve UID " << uid << " on Windows (not current user)";
		return "";
	}

} // namespace os

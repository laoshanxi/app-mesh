// src/common/os/user_posix.cpp
// POSIX user utilities shared by Linux and macOS.

#include "user.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <pwd.h>
#include <vector>

#include <ace/OS.h>

#include "../Utility.h"

namespace os
{

	bool getUidByName(const std::string &userName, unsigned int &uid, unsigned int &groupid)
	{
		const static char fname[] = "os::getUidByName() ";

		if (userName.empty())
		{
			LOG_ERR << fname << "Empty username provided";
			return false;
		}

		struct passwd pwd;
		struct passwd *result = nullptr;
		static auto bufsize = ACE_OS::sysconf(_SC_GETPW_R_SIZE_MAX);
		if (bufsize == -1)
			bufsize = 16384;
		std::shared_ptr<char> buff(new char[bufsize], std::default_delete<char[]>());
		ACE_OS::getpwnam_r(userName.c_str(), &pwd, buff.get(), bufsize, &result);
		if (result)
		{
			uid = pwd.pw_uid;
			groupid = pwd.pw_gid;
			return true;
		}

		// Fallback: treat all-digits userName as a numeric UID. The Python SDK's
		// upload path falls back to str(st.st_uid) when pwd.getpwuid() fails on
		// the SDK side (typical in containers where the host UID isn't in the
		// container's passwd db). chown(2) accepts arbitrary numeric UIDs, so
		// honoring the digit-form lets the upload succeed even when no user
		// with that UID is registered locally.
		if (std::all_of(userName.begin(), userName.end(),
						[](char c) { return c >= '0' && c <= '9'; }))
		{
			try
			{
				const unsigned long numeric = std::stoul(userName);
				// Range-check before static_cast<uid_t> so that an oversized
				// value (e.g. "4294967296" on a 32-bit uid_t platform) does
				// not silently truncate to 0 / root.
				if (numeric > std::numeric_limits<uid_t>::max())
				{
					LOG_ERR << fname << "Numeric UID out of range: " << userName;
					return false;
				}
				// Try getpwuid first to also resolve the matching primary group;
				// if that fails too, accept the UID and reuse it as the GID
				// (Linux UPG convention — caller can still override gid via a
				// separate group lookup).
				::getpwuid_r(static_cast<uid_t>(numeric), &pwd, buff.get(), bufsize, &result);
				if (result)
				{
					uid = pwd.pw_uid;
					groupid = pwd.pw_gid;
					return true;
				}
				uid = static_cast<unsigned int>(numeric);
				groupid = uid;
				LOG_DBG << fname << "User name not in passwd db, accepting numeric UID: " << userName;
				return true;
			}
			catch (const std::exception &)
			{
				// fall through to the not-found error
			}
		}

		LOG_ERR << fname << "User does not exist: " << userName;
		return false;
	}

	uid_t get_uid()
	{
		return ACE_OS::getuid();
	}

	std::string getUsernameByUid(uid_t uid /* = get_uid() */)
	{
		const static char fname[] = "os::getUsernameByUid() ";

		if (uid == static_cast<uid_t>(-1))
		{
			LOG_WAR << fname << "Invalid UID provided";
			return "";
		}

		long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
		if (bufsize == -1)
			bufsize = 16384;

		std::vector<char> buffer(bufsize);
		struct passwd pwd;
		struct passwd *result = nullptr;

		int ret = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);

		if (ret == 0 && result != nullptr)
		{
			LOG_DBG << fname << "User name for " << uid << " is " << pwd.pw_name;
			return std::string(pwd.pw_name);
		}

		LOG_WAR << fname << "User not found for UID: " << uid;
		return "";
	}

} // namespace os

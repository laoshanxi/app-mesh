// src/common/os/user_posix.cpp
// POSIX user utilities shared by Linux and macOS.

#include "user.h"

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

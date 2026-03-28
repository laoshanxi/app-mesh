// src/common/os/user.h
#pragma once

#include <string>

#include <ace/OS_NS_unistd.h> // for uid_t

namespace os
{
	/// SID to UID conversion for Windows simulation.
	unsigned int hashSidToUid(const std::string &sidString);

	bool getUidByName(const std::string &userName, unsigned int &uid, unsigned int &groupid);

	/// Get uid for current process.
	uid_t get_uid();

	std::string getUsernameByUid(uid_t uid = get_uid());

} // namespace os

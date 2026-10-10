// src/common/os/user.h
#pragma once

#include <optional>
#include <string>
#include <utility>

#include <ace/OS_NS_unistd.h> // for uid_t

namespace os
{
	/// SID to UID conversion for Windows simulation.
	unsigned int hashSidToUid(const std::string &sidString);

	/// Resolve a user name to its (uid, gid); no value when the user is unknown.
	std::optional<std::pair<unsigned int, unsigned int>> getUidByName(const std::string &userName);

	/// Get uid for current process.
	uid_t get_uid();

	std::string getUsernameByUid(uid_t uid = get_uid());

} // namespace os

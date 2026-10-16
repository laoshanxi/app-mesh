// src/common/os/chown.h
#pragma once

#if !defined(_WIN32)
#include <string>
#include <sys/types.h> // for uid_t, gid_t

namespace os
{
	bool chown(const std::string &path, uid_t uid, gid_t gid, bool recursive = false);
	bool chown(const std::string &path, std::string user, std::string group = "", bool recursive = false);
} // namespace os
#endif

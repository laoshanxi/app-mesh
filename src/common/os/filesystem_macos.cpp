// src/common/os/filesystem_macos.cpp
// macOS-specific filesystem utilities.

#include "filesystem.h"

#include <set>
#include <string>
#include <sys/mount.h>
#include <sys/param.h>

#include "../Utility.h"

namespace os
{

	std::shared_ptr<FilesystemUsage> df(const std::string &path)
	{
		const static char fname[] = "proc::df() ";
		auto df = std::make_shared<FilesystemUsage>();

		struct statfs buf;
		if (::statfs(path.c_str(), &buf) != 0)
		{
			LOG_ERR << fname << "Failed to call statfs for path: " << path << " Error: " << last_error_msg();
			return nullptr;
		}

		if (buf.f_blocks <= 0)
		{
			LOG_ERR << fname << "Invalid block count (f_blocks) returned by statfs for path: " << path;
			return nullptr;
		}

		df->totalSize = static_cast<uint64_t>(buf.f_bsize) * buf.f_blocks;
		df->usedSize = static_cast<uint64_t>(buf.f_bsize) * (buf.f_blocks - buf.f_bfree);
		df->usagePercentage = static_cast<double>(buf.f_blocks - buf.f_bfree) / buf.f_blocks;

		return df;
	}

	std::map<std::string, std::string> getMountPoints()
	{
		const static char fname[] = "proc::getMountPoints() ";
		std::map<std::string, std::string> mountPointsMap;

		struct statfs *mountEntries;
		int totalMounts = getmntinfo(&mountEntries, MNT_NOWAIT);
		if (totalMounts <= 0)
		{
			LOG_ERR << fname << "Failed to retrieve mount points using getmntinfo: " << last_error_msg();
			return mountPointsMap;
		}

		std::set<std::string> ignoredFileSystems = {
			"autofs", "devfs", "volfs", "tmpfs", "vmware_fusion",
			"com.apple.TimeMachine", "synthetics", "com.apple.filesystems.apfs.serviceroot",
			"com.apple.os.update-", "com.apple.system.clock",
			"com.apple.system.background-task", "com.apple.system.ql-cache"};

		for (int i = 0; i < totalMounts; ++i)
		{
			std::string devicePath = mountEntries[i].f_mntfromname;
			std::string mountDir = mountEntries[i].f_mntonname;
			std::string mountFsType = mountEntries[i].f_fstypename;

			if (ignoredFileSystems.find(mountFsType) != ignoredFileSystems.end())
			{
				LOG_DBG << fname << "Skipping ignored filesystem type: " << mountFsType;
				continue;
			}

			if (!devicePath.empty() && devicePath[0] == '/')
			{
				struct statfs fileSystemStats;
				if (statfs(mountDir.c_str(), &fileSystemStats) != 0)
				{
					LOG_WAR << fname << "Failed to get filesystem stats for " << mountDir << ": " << last_error_msg();
					continue;
				}

				if (fileSystemStats.f_blocks <= 0)
				{
					LOG_WAR << fname << "Skipping mount point with no blocks: " << mountDir;
					continue;
				}

				if (fileSystemStats.f_flags & MNT_RDONLY)
				{
					LOG_DBG << fname << "Skipping read-only filesystem: " << mountDir;
					continue;
				}

				LOG_DBG << fname << "device: " << devicePath << " mountDir: " << mountDir << " mountFsType: " << mountFsType;
				mountPointsMap[mountDir] = devicePath;
			}
			else
			{
				LOG_DBG << fname << "Skipping invalid device path: " << devicePath;
			}
		}

		return mountPointsMap;
	}

} // namespace os

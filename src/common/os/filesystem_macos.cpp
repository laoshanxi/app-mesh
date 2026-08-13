// src/common/os/filesystem_macos.cpp
// macOS-specific filesystem utilities.

#include "filesystem.h"

#include <algorithm>
#include <set>
#include <string>
#include <sys/mount.h>
#include <sys/param.h>

#include "../Utility.h"

namespace os
{

	std::shared_ptr<FilesystemUsage> df(const std::string &path)
	{
		const static char fname[] = "os::df() ";
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

		const auto freeBlocks = std::min(buf.f_bfree, buf.f_blocks);
		const auto availableBlocks = std::min(buf.f_bavail, freeBlocks);
		df->totalSize = static_cast<uint64_t>(buf.f_bsize) * buf.f_blocks;
		df->usedSize = static_cast<uint64_t>(buf.f_bsize) * (buf.f_blocks - freeBlocks);
		df->availableSize = static_cast<uint64_t>(buf.f_bsize) * availableBlocks;
		df->usagePercentage = static_cast<double>(buf.f_blocks - freeBlocks) / buf.f_blocks;

		return df;
	}

	std::map<std::string, std::string> getMountPoints()
	{
		const static char fname[] = "os::getMountPoints() ";
		std::map<std::string, std::string> mountPointsMap;

		struct statfs *mountEntries;
		int totalMounts = getmntinfo(&mountEntries, MNT_NOWAIT);
		if (totalMounts <= 0)
		{
			LOG_ERR << fname << "Failed to retrieve mount points using getmntinfo: " << last_error_msg();
			return mountPointsMap;
		}

		static const std::set<std::string> ignoredFileSystems = {
			"autofs", "devfs", "volfs", "tmpfs", "vmware_fusion",
			"com.apple.TimeMachine", "synthetics", "com.apple.filesystems.apfs.serviceroot",
			"com.apple.os.update-", "com.apple.system.clock",
			"com.apple.system.background-task", "com.apple.system.ql-cache"};
		std::set<std::string> seenDevices;

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

			if ((mountEntries[i].f_flags & MNT_LOCAL) == 0)
			{
				LOG_DBG << fname << "Skipping remote filesystem: " << mountFsType << " at " << mountDir;
				continue;
			}
			if (devicePath.empty() || devicePath[0] != '/')
			{
				LOG_DBG << fname << "Skipping invalid device path: " << devicePath;
				continue;
			}
			if (mountDir == "/System/Volumes" || Utility::startWith(mountDir, "/System/Volumes/"))
			{
				LOG_DBG << fname << "Skipping macOS auxiliary system volume: " << mountDir;
				continue;
			}
			if (mountEntries[i].f_blocks <= 0)
				continue;
			if (!seenDevices.insert(devicePath).second)
			{
				LOG_DBG << fname << "Skipping duplicate logical disk device: " << devicePath << " at " << mountDir;
				continue;
			}

			// AsJson performs the single filesystem usage query.
			LOG_DBG << fname << "device: " << devicePath << " mountDir: " << mountDir << " mountFsType: " << mountFsType;
			mountPointsMap[mountDir] = devicePath;
		}

		return mountPointsMap;
	}

} // namespace os

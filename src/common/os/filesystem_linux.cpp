// src/common/os/filesystem_linux.cpp
// Linux-specific filesystem utilities.

#include "filesystem.h"

#include <cstring>
#include <mntent.h>
#include <set>
#include <sys/statvfs.h>

#include "../Utility.h"

namespace os
{

	std::shared_ptr<FilesystemUsage> df(const std::string &path)
	{
		const static char fname[] = "proc::df() ";
		auto df = std::make_shared<FilesystemUsage>();

		struct statvfs buf;
		if (::statvfs(path.c_str(), &buf) != 0)
		{
			LOG_ERR << fname << "Failed to call statvfs for path: " << path << " Error: " << last_error_msg();
			return nullptr;
		}

		if (buf.f_blocks <= 0)
		{
			LOG_ERR << fname << "Invalid block count (f_blocks) returned by statvfs for path: " << path;
			return nullptr;
		}

		df->totalSize = static_cast<uint64_t>(buf.f_frsize) * buf.f_blocks;
		df->usedSize = static_cast<uint64_t>(buf.f_frsize) * (buf.f_blocks - buf.f_bfree);
		df->usagePercentage = static_cast<double>(buf.f_blocks - buf.f_bfree) / buf.f_blocks;

		return df;
	}

	std::map<std::string, std::string> getMountPoints()
	{
		const static char fname[] = "proc::getMountPoints() ";
		std::map<std::string, std::string> mountPointsMap;

		std::unique_ptr<FILE, void (*)(FILE *)> mountsFile(setmntent("/proc/mounts", "r"), [](FILE *fp)
														   { if (fp) endmntent(fp); });
		if (!mountsFile.get())
		{
			std::unique_ptr<FILE, void (*)(FILE *)> fallbackFile(setmntent("/etc/mtab", "r"), [](FILE *fp)
																 { if (fp) endmntent(fp); });
			if (!fallbackFile.get())
			{
				LOG_ERR << fname << "Failed to open both /proc/mounts and /etc/mtab: " << last_error_msg();
				return mountPointsMap;
			}
			LOG_WAR << fname << "Using fallback /etc/mtab";
			mountsFile = std::move(fallbackFile);
		}

		struct mntent *currentMountEntry;
		struct mntent tempMountEntry;
		char entryBuffer[4096];

		std::set<std::string> ignoredFileSystems = {
			"tmpfs", "romfs", "ramfs", "devtmpfs", "overlay", "squashfs",
			"sysfs", "proc", "devpts", "securityfs", "cgroup", "cgroup2",
			"pstore", "debugfs", "hugetlbfs", "mqueue", "fusectl",
			"configfs", "fuse", "binfmt_misc"};

		while ((currentMountEntry = getmntent_r(mountsFile.get(), &tempMountEntry, entryBuffer, sizeof(entryBuffer))) != nullptr)
		{
			const char *devicePath = currentMountEntry->mnt_fsname;
			const char *mountDir = currentMountEntry->mnt_dir;
			const char *fileSystemType = currentMountEntry->mnt_type;

			if (!devicePath || !mountDir || !fileSystemType)
			{
				LOG_WAR << fname << "Skipped an invalid mount entry";
				continue;
			}

			if (ignoredFileSystems.count(fileSystemType) > 0 || devicePath[0] != '/')
			{
				LOG_DBG << fname << "Skipping " << (devicePath[0] != '/' ? "non-device" : "ignored")
						<< " filesystem: " << fileSystemType << " at " << mountDir;
				continue;
			}

			struct statvfs fileSystemStats;
			if (::statvfs(mountDir, &fileSystemStats) != 0)
			{
				LOG_WAR << fname << "Failed to get filesystem stats for " << mountDir << ": " << last_error_msg();
				continue;
			}

			if (fileSystemStats.f_blocks <= 0)
			{
				LOG_WAR << fname << "Skipping mount point with no blocks: " << mountDir;
				continue;
			}

			if (strstr(currentMountEntry->mnt_opts, "bind"))
			{
				LOG_DBG << fname << "Skipping bind mount: " << mountDir;
				continue;
			}

			LOG_DBG << fname << "device: " << devicePath << " mountDir: " << mountDir << " fileSystemType: " << fileSystemType;
			mountPointsMap[mountDir] = devicePath;
		}

		return mountPointsMap;
	}

} // namespace os

// src/common/os/filesystem_linux.cpp
// Linux-specific filesystem utilities.

#include "filesystem.h"

#include <algorithm>
#include <cstring>
#include <mntent.h>
#include <set>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include "../Utility.h"

namespace os
{

	std::shared_ptr<FilesystemUsage> df(const std::string &path)
	{
		const static char fname[] = "os::df() ";
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

		const auto freeBlocks = std::min(buf.f_bfree, buf.f_blocks);
		const auto availableBlocks = std::min(buf.f_bavail, freeBlocks);
		df->totalSize = static_cast<uint64_t>(buf.f_frsize) * buf.f_blocks;
		df->usedSize = static_cast<uint64_t>(buf.f_frsize) * (buf.f_blocks - freeBlocks);
		df->availableSize = static_cast<uint64_t>(buf.f_frsize) * availableBlocks;
		df->usagePercentage = static_cast<double>(buf.f_blocks - freeBlocks) / buf.f_blocks;

		return df;
	}

	std::map<std::string, std::string> getMountPoints()
	{
		const static char fname[] = "os::getMountPoints() ";
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

		static const std::set<std::string> ignoredFileSystems = {
			"tmpfs", "romfs", "ramfs", "devtmpfs", "overlay", "squashfs", "autofs",
			"sysfs", "proc", "devpts", "securityfs", "cgroup", "cgroup2",
			"pstore", "debugfs", "tracefs", "hugetlbfs", "mqueue", "fusectl",
			"configfs", "fuse", "binfmt_misc", "bpf", "nsfs", "rpc_pipefs",
			"efivarfs", "selinuxfs"};
		// Avoid blocking the local collector on unreachable remote mounts.
		static const std::set<std::string> remoteFileSystems = {
			"nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs", "9p",
			"ceph", "glusterfs", "gcsfuse", "s3fs", "afs"};
		// ZFS datasets are logical disks but do not expose a /dev block-device path.
		static const std::set<std::string> logicalFileSystemsWithoutBlockDevice = {"zfs"};
		std::set<dev_t> seenBlockDevices;
		std::set<std::string> seenLogicalDevices;

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

			if (ignoredFileSystems.count(fileSystemType) > 0)
			{
				LOG_DBG << fname << "Skipping ignored filesystem: " << fileSystemType << " at " << mountDir;
				continue;
			}

			if (remoteFileSystems.count(fileSystemType) > 0 || hasmntopt(currentMountEntry, "_netdev"))
			{
				LOG_DBG << fname << "Skipping remote filesystem: " << fileSystemType << " at " << mountDir;
				continue;
			}

			if (strstr(currentMountEntry->mnt_opts, "bind"))
			{
				LOG_DBG << fname << "Skipping bind mount: " << mountDir;
				continue;
			}

			struct stat deviceStats {};
			const bool blockBacked = ::stat(devicePath, &deviceStats) == 0 && S_ISBLK(deviceStats.st_mode);
			const bool logicalWithoutBlockDevice = logicalFileSystemsWithoutBlockDevice.count(fileSystemType) > 0;
			if (!blockBacked && !logicalWithoutBlockDevice)
			{
				LOG_DBG << fname << "Skipping non-logical-disk filesystem: " << fileSystemType
						<< " device: " << devicePath << " at " << mountDir;
				continue;
			}
			if (blockBacked && !seenBlockDevices.insert(deviceStats.st_rdev).second)
			{
				LOG_DBG << fname << "Skipping duplicate logical disk device: " << devicePath << " at " << mountDir;
				continue;
			}
			if (logicalWithoutBlockDevice && !seenLogicalDevices.insert(devicePath).second)
			{
				LOG_DBG << fname << "Skipping duplicate logical disk: " << devicePath << " at " << mountDir;
				continue;
			}
			if (mountPointsMap.count(mountDir) > 0)
			{
				LOG_DBG << fname << "Skipping duplicate mount point: " << mountDir;
				continue;
			}

			LOG_DBG << fname << "device: " << devicePath << " mountDir: " << mountDir << " fileSystemType: " << fileSystemType;
			mountPointsMap[mountDir] = devicePath;
		}

		return mountPointsMap;
	}

} // namespace os

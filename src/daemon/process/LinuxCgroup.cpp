// src/daemon/process/LinuxCgroup.cpp
#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

#if defined(__linux__)
#include <mntent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "../../common/Utility.h"
#include "LinuxCgroup.h"

namespace
{
	constexpr const char *CGROUP_APPMESH_DIR = "appmesh";
	constexpr long long MIN_MEMORY_LIMIT_BYTES = 4 * 1024 * 1024; // 4 MB minimum
	constexpr long long DEFAULT_CPU_SHARES = 1024;
	constexpr long long DEFAULT_CPU_WEIGHT = 100;

	/// Parse CPU set string like "0-3,5,7-9" and count CPUs
	int parseCpuSetString(const std::string &cpuSetStr)
	{
		int cpuCount = 0;
		std::istringstream stream(cpuSetStr);
		std::string token;

		while (std::getline(stream, token, ','))
		{
			// Trim whitespace
			token.erase(0, token.find_first_not_of(" \t\r\n"));
			token.erase(token.find_last_not_of(" \t\r\n") + 1);

			if (token.empty())
				continue;

			size_t dashPos = token.find('-');
			if (dashPos != std::string::npos)
			{
				// Range like "0-3"
				std::string startStr = token.substr(0, dashPos);
				std::string endStr = token.substr(dashPos + 1);

				if (Utility::isNumber(startStr) && Utility::isNumber(endStr))
				{
					int start = std::atoi(startStr.c_str());
					int end = std::atoi(endStr.c_str());
					cpuCount += (end - start + 1);
				}
			}
			else
			{
				// Single CPU like "5"
				if (Utility::isNumber(token))
				{
					cpuCount++;
				}
			}
		}

		return cpuCount;
	}
} // anonymous namespace

//=============================================================================
// LinuxCgroup - Base class static methods
//=============================================================================

CgroupVersion LinuxCgroup::detectCgroupVersion()
{
#if !defined(__linux__)
	return CgroupVersion::None;
#else
	// Simple and reliable detection:
	// 1. Check if /sys/fs/cgroup/cgroup.controllers exists (v2 unified hierarchy)
	// 2. Check if /sys/fs/cgroup/memory exists (v1 memory controller)
	// 3. Otherwise, no cgroup support

	// Check for cgroup v2 (unified hierarchy)
	// The presence of cgroup.controllers in root indicates v2
	if (Utility::isFileExist("/sys/fs/cgroup/cgroup.controllers"))
	{
		return CgroupVersion::V2;
	}

	// Check for cgroup v1 (legacy hierarchy)
	// The presence of /sys/fs/cgroup/memory indicates v1 memory controller
	if (Utility::isDirExist("/sys/fs/cgroup/memory"))
	{
		return CgroupVersion::V1;
	}

	// Fallback: parse /proc/mounts to detect cgroup type
	std::unique_ptr<FILE, void (*)(FILE *)> fp(fopen("/proc/mounts", "r"), [](FILE *f)
											   { if (f) fclose(f); });
	if (!fp)
	{
		return CgroupVersion::None;
	}

	struct mntent *entry = nullptr;
	struct mntent entryBuffer;
	char lineBuffer[4096] = {0};

	while (nullptr != (entry = getmntent_r(fp.get(), &entryBuffer, lineBuffer, sizeof(lineBuffer))))
	{
		if (std::string(entry->mnt_type) == "cgroup2")
		{
			return CgroupVersion::V2;
		}
		if (std::string(entry->mnt_type) == "cgroup")
		{
			return CgroupVersion::V1;
		}
	}

	return CgroupVersion::None;
#endif
}

std::unique_ptr<LinuxCgroup> LinuxCgroup::create(long long memoryLimitBytes, long long memorySwapBytes, long long cpuShares)
{
	const static char fname[] = "LinuxCgroup::create() ";

	// If no limits requested, return null handler
	if (memoryLimitBytes <= 0 && memorySwapBytes <= 0 && cpuShares <= 0)
	{
		LOG_DBG << fname << "No cgroup limits requested, using null handler";
		return std::make_unique<LinuxCgroupNull>();
	}

#if !defined(__linux__)
	LOG_DBG << fname << "Not on Linux, cgroup not supported";
	return std::make_unique<LinuxCgroupNull>();
#else
	CgroupVersion version = detectCgroupVersion();

	switch (version)
	{
	case CgroupVersion::V2:
		LOG_DBG << fname << "Detected cgroup v2, creating V2 handler";
		return std::make_unique<LinuxCgroupV2>(memoryLimitBytes, memorySwapBytes, cpuShares);

	case CgroupVersion::V1:
		LOG_DBG << fname << "Detected cgroup v1, creating V1 handler";
		return std::make_unique<LinuxCgroupV1>(memoryLimitBytes, memorySwapBytes, cpuShares);

	default:
		LOG_WAR << fname << "No cgroup support detected";
		return std::make_unique<LinuxCgroupNull>();
	}
#endif
}

bool LinuxCgroup::writeValueToFile(const std::string &filePath, long long value)
{
	const static char fname[] = "LinuxCgroup::writeValueToFile() ";

	std::unique_ptr<FILE, void (*)(FILE *)> fp(fopen(filePath.c_str(), "w"), [](FILE *f)
											   { if (f) fclose(f); });
	if (!fp)
	{
		LOG_ERR << fname << "Failed to open file <" << filePath << ">: " << std::strerror(errno);
		return false;
	}

	if (fprintf(fp.get(), "%lld", value) < 0)
	{
		LOG_ERR << fname << "Failed to write <" << value << "> to file <" << filePath << ">: " << std::strerror(errno);
		return false;
	}

	LOG_DBG << fname << "Wrote <" << value << "> to file <" << filePath << ">";
	return true;
}

long long LinuxCgroup::readValueFromFile(const std::string &filePath)
{
	const static char fname[] = "LinuxCgroup::readValueFromFile() ";

	std::unique_ptr<FILE, void (*)(FILE *)> fp(fopen(filePath.c_str(), "r"), [](FILE *f)
											   { if (f) fclose(f); });
	if (!fp)
	{
		LOG_ERR << fname << "Failed to open file <" << filePath << ">: " << std::strerror(errno);
		return 0;
	}

	long long value = 0;
	if (fscanf(fp.get(), "%lld", &value) != 1)
	{
		LOG_ERR << fname << "Failed to read from file <" << filePath << ">: " << std::strerror(errno);
		return 0;
	}

	LOG_DBG << fname << "Read <" << value << "> from file <" << filePath << ">";
	return value;
}

bool LinuxCgroup::addProcessToCgroup(const std::string &cgroupPath, int pid, const std::string &procsFileName)
{
	std::string procsFile = cgroupPath + "/" + procsFileName;
	return writeValueToFile(procsFile, pid);
}

//=============================================================================
// LinuxCgroupV1 - Cgroup v1 implementation
//=============================================================================

std::string LinuxCgroupV1::s_memoryRootDir;
std::string LinuxCgroupV1::s_cpuRootDir;
std::string LinuxCgroupV1::s_cpusetRootDir;
bool LinuxCgroupV1::s_mountPointsDiscovered = false;

LinuxCgroupV1::LinuxCgroupV1(long long memoryLimitBytes, long long memorySwapBytes, long long cpuShares)
	: m_memoryLimitBytes(memoryLimitBytes),
	  m_memorySwapBytes(memorySwapBytes),
	  m_cpuShares(cpuShares),
	  m_pid(0),
	  m_enabled(false),
	  m_swapLimitSupported(true)
{
	const static char fname[] = "LinuxCgroupV1::LinuxCgroupV1() ";

#if defined(__linux__)
	// Validate and adjust memory limit
	if (m_memoryLimitBytes > 0 && m_memoryLimitBytes < MIN_MEMORY_LIMIT_BYTES)
	{
		LOG_WAR << fname << "Memory limit increased to minimum " << MIN_MEMORY_LIMIT_BYTES << " bytes";
		m_memoryLimitBytes = MIN_MEMORY_LIMIT_BYTES;
	}

	// In cgroup v1, memory.memsw.limit_in_bytes must be >= memory.limit_in_bytes
	// If only swap is specified, set memory limit to match
	if (m_memoryLimitBytes == 0 && m_memorySwapBytes > 0)
	{
		m_memoryLimitBytes = m_memorySwapBytes;
		LOG_WAR << fname << "Memory limit set to swap limit value";
	}

	// Ensure swap >= memory (cgroup v1 requirement)
	if (m_memorySwapBytes > 0 && m_memorySwapBytes < m_memoryLimitBytes)
	{
		m_memorySwapBytes = m_memoryLimitBytes;
		LOG_WAR << fname << "Swap limit adjusted to match memory limit (v1 requirement)";
	}

	m_enabled = (m_memoryLimitBytes > 0 || m_memorySwapBytes > 0 || m_cpuShares > 0);

	if (m_enabled)
	{
		// Discover mount points (once per process)
		if (!s_mountPointsDiscovered)
		{
			discoverMountPoints();
			s_mountPointsDiscovered = true;
		}

		// Check swap support
		if (!s_memoryRootDir.empty())
		{
			std::string swapLimitFile = s_memoryRootDir + "/memory.memsw.limit_in_bytes";
			if (!Utility::isFileExist(swapLimitFile))
			{
				m_swapLimitSupported = false;
				if (m_memorySwapBytes > 0)
				{
					LOG_WAR << fname << "Kernel does not support swap limit or cgroup not mounted properly";
				}
			}
		}

		if (!m_swapLimitSupported)
		{
			m_memorySwapBytes = 0;
		}
	}
#endif
}

LinuxCgroupV1::~LinuxCgroupV1()
{
	cleanup();
}

void LinuxCgroupV1::cleanup()
{
	if (!m_enabled)
		return;

	const static char fname[] = "LinuxCgroupV1::cleanup() ";

	// Force memory reclaim before removing cgroup
	if (!m_cgroupMemoryPath.empty() && Utility::isDirExist(m_cgroupMemoryPath))
	{
		std::string forceEmptyFile = m_cgroupMemoryPath + "/memory.force_empty";
		writeValueToFile(forceEmptyFile, 0);
		Utility::removeDir(m_cgroupMemoryPath);
		LOG_DBG << fname << "Removed memory cgroup: " << m_cgroupMemoryPath;
	}

	if (!m_cgroupCpuPath.empty() && Utility::isDirExist(m_cgroupCpuPath))
	{
		Utility::removeDir(m_cgroupCpuPath);
		LOG_DBG << fname << "Removed CPU cgroup: " << m_cgroupCpuPath;
	}
}

void LinuxCgroupV1::discoverMountPoints()
{
	const static char fname[] = "LinuxCgroupV1::discoverMountPoints() ";

#if defined(__linux__)
	std::unique_ptr<FILE, void (*)(FILE *)> fp(fopen("/proc/mounts", "r"), [](FILE *f)
											   { if (f) fclose(f); });
	if (!fp)
	{
		LOG_ERR << fname << "Failed to open /proc/mounts: " << std::strerror(errno);
		return;
	}

	struct mntent *entry = nullptr;
	struct mntent entryBuffer;
	char lineBuffer[4096] = {0};

	while (nullptr != (entry = getmntent_r(fp.get(), &entryBuffer, lineBuffer, sizeof(lineBuffer))))
	{
		if (std::string(entry->mnt_type) != "cgroup")
		{
			continue;
		}

		// Check for memory controller
		if (hasmntopt(entry, "memory"))
		{
			s_memoryRootDir = entry->mnt_dir;
			LOG_DBG << fname << "Memory cgroup mount: " << s_memoryRootDir;
		}

		// Check for cpuset controller
		if (hasmntopt(entry, "cpuset"))
		{
			s_cpusetRootDir = entry->mnt_dir;
			LOG_DBG << fname << "Cpuset cgroup mount: " << s_cpusetRootDir;
		}

		// Check for cpu controller
		if (hasmntopt(entry, "cpu"))
		{
			std::string cpuDir = entry->mnt_dir;
			// Handle combined mount like "/sys/fs/cgroup/cpu,cpuacct"
			size_t commaPos = cpuDir.find(',');
			if (commaPos != std::string::npos)
			{
				cpuDir = cpuDir.substr(0, commaPos);
			}
			s_cpuRootDir = cpuDir;
			LOG_DBG << fname << "CPU cgroup mount: " << s_cpuRootDir;
		}
	}
#endif
}

void LinuxCgroupV1::applyLimits(const std::string &appName, int pid, int index)
{
	const static char fname[] = "LinuxCgroupV1::applyLimits() ";

	if (!m_enabled)
		return;

	m_pid = pid;

	// Build cgroup paths
	m_cgroupMemoryPath = (fs::path(s_memoryRootDir) / CGROUP_APPMESH_DIR / appName / std::to_string(index)).string();
	m_cgroupCpuPath = (fs::path(s_cpuRootDir) / CGROUP_APPMESH_DIR / appName / std::to_string(index)).string();

	const auto perm = fs::perms::owner_all | fs::perms::group_exe | fs::perms::others_exe;

	// Apply memory limits
	if (m_memoryLimitBytes > 0 && !s_memoryRootDir.empty())
	{
		if (Utility::createRecursiveDirectory(m_cgroupMemoryPath, perm))
		{
			applyMemoryLimit(m_cgroupMemoryPath);
			if (m_memorySwapBytes > 0 && m_swapLimitSupported)
			{
				applySwapLimit(m_cgroupMemoryPath);
			}
		}
		else
		{
			LOG_ERR << fname << "Failed to create memory cgroup directory: " << m_cgroupMemoryPath;
		}
	}

	// Apply CPU shares
	if (m_cpuShares > 0 && !s_cpuRootDir.empty())
	{
		if (Utility::createRecursiveDirectory(m_cgroupCpuPath, perm))
		{
			applyCpuShares(m_cgroupCpuPath);
		}
		else
		{
			LOG_ERR << fname << "Failed to create CPU cgroup directory: " << m_cgroupCpuPath;
		}
	}

	LOG_DBG << fname << "Applied cgroup v1 limits for app <" << appName << "> pid <" << pid << ">";
}

void LinuxCgroupV1::applyMemoryLimit(const std::string &cgroupPath)
{
	std::string limitFile = cgroupPath + "/memory.limit_in_bytes";
	writeValueToFile(limitFile, m_memoryLimitBytes);
	addProcessToCgroup(cgroupPath, m_pid, "tasks");
}

void LinuxCgroupV1::applySwapLimit(const std::string &cgroupPath)
{
	// In v1, memsw includes memory+swap, so it must be >= memory.limit_in_bytes
	std::string swapLimitFile = cgroupPath + "/memory.memsw.limit_in_bytes";
	writeValueToFile(swapLimitFile, m_memorySwapBytes);
}

void LinuxCgroupV1::applyCpuShares(const std::string &cgroupPath)
{
	std::string sharesFile = cgroupPath + "/cpu.shares";
	writeValueToFile(sharesFile, m_cpuShares);
	addProcessToCgroup(cgroupPath, m_pid, "tasks");
}

long long LinuxCgroupV1::readHostMemoryValue(const std::string &cgroupFileName)
{
	if (s_memoryRootDir.empty())
		return 0;
	return readValueFromFile(s_memoryRootDir + "/" + cgroupFileName);
}

int LinuxCgroupV1::readHostCpuCount()
{
	const static char fname[] = "LinuxCgroupV1::readHostCpuCount() ";

	if (s_cpusetRootDir.empty())
	{
		LOG_WAR << fname << "Cpuset root directory not discovered";
		return 0;
	}

	std::string cpusetFile = s_cpusetRootDir + "/cpuset.cpus";
	std::string cpuSetStr = Utility::readFile(cpusetFile);

	int cpuCount = parseCpuSetString(cpuSetStr);
	LOG_DBG << fname << "CPU count: " << cpuCount;
	return cpuCount;
}

bool LinuxCgroupV1::isSwapLimitSupported() const
{
	return m_swapLimitSupported;
}

bool LinuxCgroupV1::isEnabled() const
{
	return m_enabled;
}

//=============================================================================
// LinuxCgroupV2 - Cgroup v2 (unified) implementation
//=============================================================================

std::string LinuxCgroupV2::s_cgroupRootDir;
bool LinuxCgroupV2::s_mountPointDiscovered = false;

LinuxCgroupV2::LinuxCgroupV2(long long memoryLimitBytes, long long memorySwapBytes, long long cpuShares)
	: m_memoryLimitBytes(memoryLimitBytes),
	  m_memorySwapBytes(memorySwapBytes),
	  m_cpuShares(cpuShares),
	  m_pid(0),
	  m_enabled(false),
	  m_swapLimitSupported(true)
{
	const static char fname[] = "LinuxCgroupV2::LinuxCgroupV2() ";

#if defined(__linux__)
	// Validate and adjust memory limit
	if (m_memoryLimitBytes > 0 && m_memoryLimitBytes < MIN_MEMORY_LIMIT_BYTES)
	{
		LOG_WAR << fname << "Memory limit increased to minimum " << MIN_MEMORY_LIMIT_BYTES << " bytes";
		m_memoryLimitBytes = MIN_MEMORY_LIMIT_BYTES;
	}

	m_enabled = (m_memoryLimitBytes > 0 || m_memorySwapBytes > 0 || m_cpuShares > 0);

	if (m_enabled)
	{
		// Discover mount point (once per process)
		if (!s_mountPointDiscovered)
		{
			discoverMountPoint();
			s_mountPointDiscovered = true;
		}

		// Check swap support in v2
		if (!s_cgroupRootDir.empty())
		{
			// In cgroup v2, check if memory.swap.max is available
			std::string swapFile = s_cgroupRootDir + "/memory.swap.max";
			if (!Utility::isFileExist(swapFile))
			{
				// Try checking in a subdirectory or cgroup.controllers
				std::string controllersFile = s_cgroupRootDir + "/cgroup.controllers";
				std::string controllers = Utility::readFile(controllersFile);
				if (controllers.find("memory") == std::string::npos)
				{
					LOG_WAR << fname << "Memory controller not available in cgroup v2";
				}
			}
		}
	}
#endif
}

LinuxCgroupV2::~LinuxCgroupV2()
{
	cleanup();
}

void LinuxCgroupV2::cleanup()
{
	if (!m_enabled || m_cgroupPath.empty())
		return;

	const static char fname[] = "LinuxCgroupV2::cleanup() ";

	if (Utility::isDirExist(m_cgroupPath))
	{
		Utility::removeDir(m_cgroupPath);
		LOG_DBG << fname << "Removed cgroup: " << m_cgroupPath;
	}
}

void LinuxCgroupV2::discoverMountPoint()
{
	const static char fname[] = "LinuxCgroupV2::discoverMountPoint() ";

#if defined(__linux__)
	// Default location for cgroup v2
	const std::string defaultPath = "/sys/fs/cgroup";

	if (Utility::isFileExist(defaultPath + "/cgroup.controllers"))
	{
		s_cgroupRootDir = defaultPath;
		LOG_DBG << fname << "Cgroup v2 mount: " << s_cgroupRootDir;
		return;
	}

	// Parse /proc/mounts as fallback
	std::unique_ptr<FILE, void (*)(FILE *)> fp(fopen("/proc/mounts", "r"), [](FILE *f)
											   { if (f) fclose(f); });
	if (!fp)
	{
		LOG_ERR << fname << "Failed to open /proc/mounts: " << std::strerror(errno);
		return;
	}

	struct mntent *entry = nullptr;
	struct mntent entryBuffer;
	char lineBuffer[4096] = {0};

	while (nullptr != (entry = getmntent_r(fp.get(), &entryBuffer, lineBuffer, sizeof(lineBuffer))))
	{
		if (std::string(entry->mnt_type) == "cgroup2")
		{
			s_cgroupRootDir = entry->mnt_dir;
			LOG_DBG << fname << "Cgroup v2 mount: " << s_cgroupRootDir;
			return;
		}
	}

	LOG_WAR << fname << "Cgroup v2 mount point not found";
#endif
}

long long LinuxCgroupV2::sharesToWeight(long long shares)
{
	// Convert v1 cpu.shares to v2 cpu.weight
	// V1: shares range 2-262144, default 1024
	// V2: weight range 1-10000, default 100
	// Formula: weight = 1 + ((shares - 2) * 9999) / 262142
	// Simplified: weight ≈ shares * 100 / 1024

	if (shares <= 0)
		return DEFAULT_CPU_WEIGHT;

	long long weight = (shares * DEFAULT_CPU_WEIGHT) / DEFAULT_CPU_SHARES;

	// Clamp to valid range
	if (weight < 1)
		weight = 1;
	if (weight > 10000)
		weight = 10000;

	return weight;
}

bool LinuxCgroupV2::enableControllers(const std::string &cgroupPath)
{
	// In cgroup v2, we need to enable controllers via cgroup.subtree_control
	// in parent directories

	fs::path path(cgroupPath);
	fs::path root(s_cgroupRootDir);

	// Walk from root to our target, enabling controllers at each level
	std::vector<std::string> pathComponents;
	fs::path current = path;
	while (current != root && !current.empty())
	{
		pathComponents.push_back(current.string());
		current = current.parent_path();
	}

	// Enable controllers from root down (reverse order)
	std::reverse(pathComponents.begin(), pathComponents.end());

	for (size_t i = 0; i < pathComponents.size(); ++i)
	{
		fs::path parentPath = fs::path(pathComponents[i]).parent_path();
		std::string subtreeControl = parentPath.string() + "/cgroup.subtree_control";

		if (Utility::isFileExist(subtreeControl))
		{
			// Enable memory and cpu controllers
			std::ofstream ofs(subtreeControl, std::ios::app);
			if (ofs.is_open())
			{
				if (m_memoryLimitBytes > 0 || m_memorySwapBytes > 0)
				{
					ofs << "+memory ";
				}
				if (m_cpuShares > 0)
				{
					ofs << "+cpu ";
				}
				ofs.close();
			}
		}
	}

	return true;
}

void LinuxCgroupV2::applyLimits(const std::string &appName, int pid, int index)
{
	const static char fname[] = "LinuxCgroupV2::applyLimits() ";

	if (!m_enabled)
		return;

	m_pid = pid;

	// Build cgroup path (unified in v2)
	m_cgroupPath = (fs::path(s_cgroupRootDir) / CGROUP_APPMESH_DIR / appName / std::to_string(index)).string();

	const auto perm = fs::perms::owner_all | fs::perms::group_exe | fs::perms::others_exe;

	if (!Utility::createRecursiveDirectory(m_cgroupPath, perm))
	{
		LOG_ERR << fname << "Failed to create cgroup directory: " << m_cgroupPath;
		return;
	}

	// Enable controllers in parent directories
	enableControllers(m_cgroupPath);

	// Apply memory limits
	if (m_memoryLimitBytes > 0 || m_memorySwapBytes > 0)
	{
		applyMemoryLimit(m_cgroupPath);
	}

	// Apply CPU weight (converted from shares)
	if (m_cpuShares > 0)
	{
		applyCpuWeight(m_cgroupPath);
	}

	// Add process to cgroup (v2 uses cgroup.procs)
	addProcessToCgroup(m_cgroupPath, m_pid, "cgroup.procs");

	LOG_DBG << fname << "Applied cgroup v2 limits for app <" << appName << "> pid <" << pid << ">";
}

void LinuxCgroupV2::applyMemoryLimit(const std::string &cgroupPath)
{
	const static char fname[] = "LinuxCgroupV2::applyMemoryLimit() ";

	// In cgroup v2, use memory.max for memory limit
	if (m_memoryLimitBytes > 0)
	{
		std::string memMaxFile = cgroupPath + "/memory.max";
		writeValueToFile(memMaxFile, m_memoryLimitBytes);
	}

	// In cgroup v2, memory.swap.max is separate (not combined like v1)
	if (m_memorySwapBytes > 0)
	{
		std::string swapMaxFile = cgroupPath + "/memory.swap.max";
		if (Utility::isFileExist(swapMaxFile))
		{
			writeValueToFile(swapMaxFile, m_memorySwapBytes);
		}
		else
		{
			m_swapLimitSupported = false;
			LOG_WAR << fname << "Swap limit not supported (memory.swap.max not available)";
		}
	}
}

void LinuxCgroupV2::applyCpuWeight(const std::string &cgroupPath)
{
	// Convert shares to weight
	long long weight = sharesToWeight(m_cpuShares);

	std::string weightFile = cgroupPath + "/cpu.weight";
	writeValueToFile(weightFile, weight);
}

long long LinuxCgroupV2::readHostMemoryValue(const std::string &cgroupFileName)
{
	if (s_cgroupRootDir.empty())
		return 0;

	// Map v1 file names to v2 equivalents
	std::string v2FileName = cgroupFileName;
	if (cgroupFileName == "memory.limit_in_bytes")
	{
		v2FileName = "memory.max";
	}
	else if (cgroupFileName == "memory.memsw.limit_in_bytes")
	{
		v2FileName = "memory.swap.max";
	}
	else if (cgroupFileName == "memory.usage_in_bytes")
	{
		v2FileName = "memory.current";
	}

	return readValueFromFile(s_cgroupRootDir + "/" + v2FileName);
}

int LinuxCgroupV2::readHostCpuCount()
{
	const static char fname[] = "LinuxCgroupV2::readHostCpuCount() ";

	if (s_cgroupRootDir.empty())
	{
		LOG_WAR << fname << "Cgroup root directory not discovered";
		return 0;
	}

	// In cgroup v2, cpuset is unified
	std::string cpusetFile = s_cgroupRootDir + "/cpuset.cpus.effective";
	if (!Utility::isFileExist(cpusetFile))
	{
		cpusetFile = s_cgroupRootDir + "/cpuset.cpus";
	}

	std::string cpuSetStr = Utility::readFile(cpusetFile);
	int cpuCount = parseCpuSetString(cpuSetStr);

	LOG_DBG << fname << "CPU count: " << cpuCount;
	return cpuCount;
}

bool LinuxCgroupV2::isSwapLimitSupported() const
{
	return m_swapLimitSupported;
}

bool LinuxCgroupV2::isEnabled() const
{
	return m_enabled;
}

//=============================================================================
// LinuxCgroupNull - Null implementation
//=============================================================================

void LinuxCgroupNull::applyLimits(const std::string &appName, int pid, int index)
{
	// No-op
	(void)appName;
	(void)pid;
	(void)index;
}

long long LinuxCgroupNull::readHostMemoryValue(const std::string &cgroupFileName)
{
	(void)cgroupFileName;
	return 0;
}

int LinuxCgroupNull::readHostCpuCount()
{
	return 0;
}

bool LinuxCgroupNull::isSwapLimitSupported() const
{
	return false;
}

bool LinuxCgroupNull::isEnabled() const
{
	return false;
}

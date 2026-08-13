// src/daemon/process/LinuxCgroup.cpp
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <vector>

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
	constexpr long long DEFAULT_CPU_WEIGHT = 100;
	constexpr long long CGROUP_V1_UNLIMITED_THRESHOLD = 9223372036854771712LL;
	std::once_flag cgroupV1MountOnce;
	std::once_flag cgroupV2MountOnce;
	std::mutex cgroupV2ManagementMutex;

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
					if (start >= 0 && end >= start)
						cpuCount += (end - start + 1);
				}
			}
			else
			{
				// Single CPU like "5"
				if (Utility::isNumber(token) && std::atoi(token.c_str()) >= 0)
				{
					cpuCount++;
				}
			}
		}

		return cpuCount;
	}

	std::string currentCgroupPath(const std::string &controller)
	{
#if defined(__linux__)
		std::ifstream input("/proc/self/cgroup");
		std::string line;
		while (std::getline(input, line))
		{
			const auto firstColon = line.find(':');
			const auto secondColon = firstColon == std::string::npos ? std::string::npos : line.find(':', firstColon + 1);
			if (secondColon == std::string::npos)
				continue;

			const auto controllers = line.substr(firstColon + 1, secondColon - firstColon - 1);
			if (controller.empty())
			{
				if (controllers.empty())
					return line.substr(secondColon + 1);
				continue;
			}

			std::istringstream controllerList(controllers);
			std::string item;
			while (std::getline(controllerList, item, ','))
			{
				if (item == controller)
					return line.substr(secondColon + 1);
			}
		}
#else
		(void)controller;
#endif
		return {};
	}

	std::string decodeMountInfoPath(const std::string &value)
	{
		std::string decoded;
		for (std::size_t i = 0; i < value.size(); ++i)
		{
			if (value[i] == '\\' && i + 3 < value.size() &&
				value[i + 1] >= '0' && value[i + 1] <= '7' &&
				value[i + 2] >= '0' && value[i + 2] <= '7' &&
				value[i + 3] >= '0' && value[i + 3] <= '7')
			{
				decoded.push_back(static_cast<char>((value[i + 1] - '0') * 64 +
					(value[i + 2] - '0') * 8 + value[i + 3] - '0'));
				i += 3;
			}
			else
			{
				decoded.push_back(value[i]);
			}
		}
		return decoded;
	}

	std::string cgroupMountRoot(const std::string &mountPoint, const std::string &filesystemType)
	{
#if defined(__linux__)
		std::ifstream input("/proc/self/mountinfo");
		std::string line;
		while (std::getline(input, line))
		{
			const auto separator = line.find(" - ");
			if (separator == std::string::npos)
				continue;

			std::istringstream left(line.substr(0, separator));
			std::string mountId, parentId, device, root, mountedAt;
			left >> mountId >> parentId >> device >> root >> mountedAt;
			std::istringstream right(line.substr(separator + 3));
			std::string type;
			right >> type;
			if (type == filesystemType && decodeMountInfoPath(mountedAt) == mountPoint)
				return decodeMountInfoPath(root);
		}
#else
		(void)mountPoint;
		(void)filesystemType;
#endif
		return "/";
	}

	std::string cgroupCandidatePath(const std::string &mountPoint, const std::string &mountRoot,
		const std::string &cgroupPath)
	{
		if (mountPoint.empty() || cgroupPath.empty() || cgroupPath == "/")
			return mountPoint;

		std::string relative = cgroupPath;
		if (!mountRoot.empty() && mountRoot != "/" &&
			(cgroupPath == mountRoot || cgroupPath.find(mountRoot + "/") == 0))
		{
			relative = cgroupPath.substr(mountRoot.size());
		}
		if (relative.empty() || relative == "/")
			return mountPoint;
		return (fs::path(mountPoint) / relative.substr(relative.front() == '/' ? 1 : 0)).string();
	}

	std::vector<std::string> cgroupHierarchy(const std::string &leafPath, const std::string &mountRoot)
	{
		std::vector<std::string> result;
		if (leafPath.empty() || mountRoot.empty())
			return result;

		fs::path current(leafPath);
		const fs::path root(mountRoot);
		const auto rootPrefix = root.string() + "/";
		if (current != root && current.string().find(rootPrefix) != 0)
			return result;

		while (!current.empty())
		{
			result.push_back(current.string());
			if (current == root)
				break;
			const auto parent = current.parent_path();
			if (parent == current)
				return {};
			current = parent;
		}
		return result;
	}

	bool isFiniteV1Limit(long long value)
	{
		return value > 0 && value < CGROUP_V1_UNLIMITED_THRESHOLD;
	}

	bool hasWhitespaceToken(const std::string &value, const std::string &token)
	{
		std::istringstream stream(value);
		std::string item;
		while (stream >> item)
			if (item == token)
				return true;
		return false;
	}

	bool isSafeCgroupComponent(const std::string &value)
	{
		return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
		});
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

void LinuxCgroup::initializeApplicationCgroups()
{
#if defined(__linux__)
	if (detectCgroupVersion() != CgroupVersion::V2)
		return;
	try
	{
		LinuxCgroupV2 bootstrap(MIN_MEMORY_LIMIT_BYTES, 0, 1);
		bootstrap.initializeManagement();
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << "Cgroup v2 application delegation unavailable: " << ex.what();
	}
#endif
}

std::unique_ptr<LinuxCgroup> LinuxCgroup::create(long long memoryLimitBytes, long long memorySwapBytes,
	long long cpuShares, bool swapLimitSpecified)
{
	const static char fname[] = "LinuxCgroup::create() ";

	// If no limits requested, return null handler
	if (memoryLimitBytes <= 0 && !swapLimitSpecified && cpuShares <= 0)
	{
		LOG_DBG << fname << "No cgroup limits requested, using null handler";
		return std::make_unique<LinuxCgroupNull>();
	}

#if !defined(__linux__)
	LOG_DBG << fname << "Not on Linux, cgroup not supported";
	return std::make_unique<LinuxCgroupNull>(true);
#else
	CgroupVersion version = detectCgroupVersion();

	switch (version)
	{
	case CgroupVersion::V2:
		LOG_DBG << fname << "Detected cgroup v2, creating V2 handler";
		return std::make_unique<LinuxCgroupV2>(memoryLimitBytes, memorySwapBytes, cpuShares, swapLimitSpecified);

	case CgroupVersion::V1:
		LOG_DBG << fname << "Detected cgroup v1, creating V1 handler";
		return std::make_unique<LinuxCgroupV1>(memoryLimitBytes, memorySwapBytes, cpuShares, swapLimitSpecified);

	default:
		LOG_WAR << fname << "No cgroup support detected";
		return std::make_unique<LinuxCgroupNull>(true);
	}
#endif
}

bool LinuxCgroup::writeValueToFile(const std::string &filePath, long long value)
{
	const static char fname[] = "LinuxCgroup::writeValueToFile() ";
	FILE *fp = fopen(filePath.c_str(), "w");
	if (!fp)
	{
		LOG_ERR << fname << "Failed to open file <" << filePath << ">: " << std::strerror(errno);
		return false;
	}

	const bool written = fprintf(fp, "%lld", value) >= 0 && fflush(fp) == 0;
	const int closeResult = fclose(fp);
	if (!written || closeResult != 0)
	{
		LOG_ERR << fname << "Failed to write <" << value << "> to file <" << filePath << ">: " << std::strerror(errno);
		return false;
	}

	LOG_DBG << fname << "Wrote <" << value << "> to file <" << filePath << ">";
	return true;
}

boost::optional<long long> LinuxCgroup::readValueFromFile(const std::string &filePath)
{
	const static char fname[] = "LinuxCgroup::readValueFromFile() ";
	std::ifstream input(filePath);
	if (!input.is_open())
	{
		LOG_ERR << fname << "Failed to open file <" << filePath << ">: " << std::strerror(errno);
		return boost::none;
	}

	std::string rawValue;
	input >> rawValue;
	if (rawValue == "max")
	{
		return std::numeric_limits<long long>::max();
	}

	long long value = 0;
	try
	{
		value = std::stoll(rawValue);
	}
	catch (const std::exception &)
	{
		LOG_ERR << fname << "Invalid integer <" << rawValue << "> in file <" << filePath << ">";
		return boost::none;
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
std::string LinuxCgroupV1::s_memoryMountRootDir;
std::string LinuxCgroupV1::s_cpuMountRootDir;
std::string LinuxCgroupV1::s_cpusetMountRootDir;

LinuxCgroupV1::LinuxCgroupV1(long long memoryLimitBytes, long long memorySwapBytes, long long cpuShares, bool swapLimitSpecified)
	: m_memoryLimitBytes(memoryLimitBytes),
	  m_memorySwapBytes(memorySwapBytes),
	  m_swapLimitSpecified(swapLimitSpecified),
	  m_cpuShares(cpuShares),
	  m_pid(0),
	  m_enabled(false),
	  m_swapLimitSupported(true)
{
#if defined(__linux__)
	const static char fname[] = "LinuxCgroupV1::LinuxCgroupV1() ";

	// Validate and adjust memory limit
	if (m_memoryLimitBytes > 0 && m_memoryLimitBytes < MIN_MEMORY_LIMIT_BYTES)
	{
		LOG_WAR << fname << "Memory limit <" << m_memoryLimitBytes << "> below minimum, increased to <" << MIN_MEMORY_LIMIT_BYTES << "> bytes";
		m_memoryLimitBytes = MIN_MEMORY_LIMIT_BYTES;
	}

	// The public value is swap-only; cgroup v1 writes memory+swap to memsw.
	if (m_swapLimitSpecified)
	{
		if (m_memoryLimitBytes <= 0)
			throw std::invalid_argument("cgroup v1 swap limit requires a memory limit");
		if (m_memorySwapBytes > std::numeric_limits<long long>::max() - m_memoryLimitBytes)
			throw std::overflow_error("cgroup v1 memory+swap limit overflow");
		m_memorySwapBytes += m_memoryLimitBytes;
	}

	m_enabled = (m_memoryLimitBytes > 0 || m_swapLimitSpecified || m_cpuShares > 0);

	if (m_enabled)
	{
		std::call_once(cgroupV1MountOnce, [this]() { discoverMountPoints(); });

		// Check swap support
		if (!s_memoryRootDir.empty())
		{
			std::string swapLimitFile = s_memoryRootDir + "/memory.memsw.limit_in_bytes";
			if (!Utility::isFileExist(swapLimitFile))
			{
				m_swapLimitSupported = false;
				if (m_swapLimitSpecified)
				{
					LOG_WAR << fname << "Kernel does not support swap limit or cgroup not mounted properly";
				}
			}
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
		boost::system::error_code ec;
		if (!fs::remove(m_cgroupMemoryPath, ec) && ec)
			LOG_WAR << fname << "Failed to remove memory cgroup <" << m_cgroupMemoryPath << ">: " << ec.message();
	}

	if (!m_cgroupCpuPath.empty() && Utility::isDirExist(m_cgroupCpuPath))
	{
		boost::system::error_code ec;
		if (!fs::remove(m_cgroupCpuPath, ec) && ec)
			LOG_WAR << fname << "Failed to remove CPU cgroup <" << m_cgroupCpuPath << ">: " << ec.message();
	}
}

void LinuxCgroupV1::discoverMountPoints()
{
#if defined(__linux__)
	const static char fname[] = "LinuxCgroupV1::discoverMountPoints() ";

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
			s_memoryRootDir = s_memoryMountRootDir = entry->mnt_dir;
			LOG_DBG << fname << "Memory cgroup mount: " << s_memoryRootDir;
		}

		// Check for cpuset controller
		if (hasmntopt(entry, "cpuset"))
		{
			s_cpusetRootDir = s_cpusetMountRootDir = entry->mnt_dir;
			LOG_DBG << fname << "Cpuset cgroup mount: " << s_cpusetRootDir;
		}

		// Check for cpu controller
		if (hasmntopt(entry, "cpu"))
		{
			// Keep the actual combined-controller mount path.
			s_cpuRootDir = s_cpuMountRootDir = entry->mnt_dir;
			LOG_DBG << fname << "CPU cgroup mount: " << s_cpuRootDir;
		}
	}

	const auto memoryCandidate = cgroupCandidatePath(s_memoryRootDir,
		cgroupMountRoot(s_memoryRootDir, "cgroup"), currentCgroupPath("memory"));
	if (Utility::isFileExist(memoryCandidate + "/memory.limit_in_bytes"))
		s_memoryRootDir = memoryCandidate;
	const auto cpuCandidate = cgroupCandidatePath(s_cpuRootDir,
		cgroupMountRoot(s_cpuRootDir, "cgroup"), currentCgroupPath("cpu"));
	if (Utility::isFileExist(cpuCandidate + "/cpu.shares"))
		s_cpuRootDir = cpuCandidate;
	const auto cpusetCandidate = cgroupCandidatePath(s_cpusetRootDir,
		cgroupMountRoot(s_cpusetRootDir, "cgroup"), currentCgroupPath("cpuset"));
	if (Utility::isFileExist(cpusetCandidate + "/cpuset.cpus"))
		s_cpusetRootDir = cpusetCandidate;
#endif
}

void LinuxCgroupV1::applyLimits(const std::string &appName, int pid, int index)
{
	const static char fname[] = "LinuxCgroupV1::applyLimits() ";

	if (!m_enabled)
		return;
	if (!isSafeCgroupComponent(appName) || index < 0)
		throw std::invalid_argument("unsafe cgroup application component");

	m_pid = pid;
	bool applied = true;

	// Build cgroup paths
	const auto leafName = appName + "-" + std::to_string(index);
	m_cgroupMemoryPath = s_memoryRootDir.empty() ? std::string() :
		(fs::path(s_memoryRootDir) / CGROUP_APPMESH_DIR / leafName).string();
	m_cgroupCpuPath = s_cpuRootDir.empty() ? std::string() :
		(fs::path(s_cpuRootDir) / CGROUP_APPMESH_DIR / leafName).string();

	const auto perm = fs::perms::owner_all | fs::perms::group_exe | fs::perms::others_exe;

	// Apply memory limits
	if (m_memoryLimitBytes > 0)
	{
		if (s_memoryRootDir.empty())
			applied = false;
		else if (Utility::createRecursiveDirectory(m_cgroupMemoryPath, perm))
		{
			applied = applyMemoryLimit(m_cgroupMemoryPath) && applied;
			if (m_swapLimitSpecified)
				applied = m_swapLimitSupported && applySwapLimit(m_cgroupMemoryPath) && applied;
		}
		else
		{
			LOG_ERR << fname << "Failed to create memory cgroup directory: " << m_cgroupMemoryPath;
			applied = false;
		}
	}

	// Apply CPU shares
	if (m_cpuShares > 0)
	{
		if (s_cpuRootDir.empty())
			applied = false;
		else if (Utility::createRecursiveDirectory(m_cgroupCpuPath, perm))
		{
			applied = applyCpuShares(m_cgroupCpuPath) && applied;
		}
		else
		{
			LOG_ERR << fname << "Failed to create CPU cgroup directory: " << m_cgroupCpuPath;
			applied = false;
		}
	}
	if (!applied)
		throw std::runtime_error("failed to apply cgroup v1 limits");

	LOG_DBG << fname << "Applied cgroup v1 limits for app <" << appName << "> pid <" << pid << ">";
}

bool LinuxCgroupV1::applyMemoryLimit(const std::string &cgroupPath)
{
	std::string limitFile = cgroupPath + "/memory.limit_in_bytes";
	return writeValueToFile(limitFile, m_memoryLimitBytes) &&
		addProcessToCgroup(cgroupPath, m_pid, "tasks");
}

bool LinuxCgroupV1::applySwapLimit(const std::string &cgroupPath)
{
	// In v1, memsw includes memory+swap, so it must be >= memory.limit_in_bytes
	std::string swapLimitFile = cgroupPath + "/memory.memsw.limit_in_bytes";
	return writeValueToFile(swapLimitFile, m_memorySwapBytes);
}

bool LinuxCgroupV1::applyCpuShares(const std::string &cgroupPath)
{
	std::string sharesFile = cgroupPath + "/cpu.shares";
	return writeValueToFile(sharesFile, m_cpuShares) &&
		addProcessToCgroup(cgroupPath, m_pid, "tasks");
}

boost::optional<long long> LinuxCgroupV1::readHostMemoryValue(const std::string &cgroupFileName)
{
	if (s_memoryRootDir.empty())
		return boost::none;

	const bool isLimit = cgroupFileName == "memory.limit_in_bytes" || cgroupFileName == "memory.memsw.limit_in_bytes";
	if (!isLimit)
		return readValueFromFile(s_memoryRootDir + "/" + cgroupFileName);

	boost::optional<long long> effective;
	for (const auto &path : cgroupHierarchy(s_memoryRootDir, s_memoryMountRootDir))
	{
		const auto value = readValueFromFile(path + "/" + cgroupFileName);
		if (!value)
			return boost::none;
		if (!effective || *value < *effective)
			effective = *value;
	}
	return effective;
}

boost::optional<long long> LinuxCgroupV1::readHostMemoryAvailableValue(const std::string &limitFileName, const std::string &currentFileName)
{
	boost::optional<long long> available;
	for (const auto &path : cgroupHierarchy(s_memoryRootDir, s_memoryMountRootDir))
	{
		const auto limit = readValueFromFile(path + "/" + limitFileName);
		const auto current = readValueFromFile(path + "/" + currentFileName);
		if (!limit || !current)
			return boost::none;
		if (!isFiniteV1Limit(*limit))
			continue;
		const auto headroom = std::max(0LL, *limit - std::max(0LL, *current));
		if (!available || headroom < *available)
			available = headroom;
	}
	return available ? available : boost::optional<long long>(std::numeric_limits<long long>::max());
}

boost::optional<CgroupSwapStats> LinuxCgroupV1::readHostSwapStats()
{
	CgroupSwapStats stats;
	bool leaf = true;
	for (const auto &path : cgroupHierarchy(s_memoryRootDir, s_memoryMountRootDir))
	{
		const auto memoryLimit = readValueFromFile(path + "/memory.limit_in_bytes");
		const auto memoryCurrent = readValueFromFile(path + "/memory.usage_in_bytes");
		const auto memswLimit = readValueFromFile(path + "/memory.memsw.limit_in_bytes");
		const auto memswCurrent = readValueFromFile(path + "/memory.memsw.usage_in_bytes");
		if (!memoryLimit || !memoryCurrent || !memswLimit || !memswCurrent)
			return boost::none;

		if (leaf)
		{
			stats.currentBytes = std::max(0LL, *memswCurrent - std::max(0LL, *memoryCurrent));
			leaf = false;
		}
		if (isFiniteV1Limit(*memoryLimit) && isFiniteV1Limit(*memswLimit))
		{
			const auto levelLimit = std::max(0LL, *memswLimit - *memoryLimit);
			stats.limitBytes = stats.limitBytes ? std::min(*stats.limitBytes, levelLimit) : levelLimit;
		}
		if (isFiniteV1Limit(*memswLimit))
		{
			const auto levelHeadroom = std::max(0LL, *memswLimit - std::max(0LL, *memswCurrent));
			stats.headroomBytes = stats.headroomBytes ? std::min(*stats.headroomBytes, levelHeadroom) : levelHeadroom;
		}
	}
	return leaf ? boost::none : boost::optional<CgroupSwapStats>(stats);
}

boost::optional<int> LinuxCgroupV1::readHostCpuCount()
{
	const static char fname[] = "LinuxCgroupV1::readHostCpuCount() ";

	int cpuCount = 0;
	if (!s_cpusetRootDir.empty())
	{
		for (const auto &path : cgroupHierarchy(s_cpusetRootDir, s_cpusetMountRootDir))
		{
			std::string cpusetFile = path + "/cpuset.effective_cpus";
			if (!Utility::isFileExist(cpusetFile))
				cpusetFile = path + "/cpuset.cpus";
			const auto pathCpuCount = parseCpuSetString(Utility::readFile(cpusetFile));
			if (pathCpuCount > 0)
				cpuCount = cpuCount > 0 ? std::min(cpuCount, pathCpuCount) : pathCpuCount;
		}
	}
	else
	{
		LOG_WAR << fname << "Cpuset root directory not discovered; using CPU quota if available";
	}
	const auto quotaCores = readHostCpuQuotaCores();
	if (quotaCores && *quotaCores > 0)
	{
		const int quotaCount = static_cast<int>(std::ceil(*quotaCores));
		cpuCount = cpuCount > 0 ? std::min(cpuCount, quotaCount) : quotaCount;
	}
	LOG_DBG << fname << "CPU count: " << cpuCount;
	if (cpuCount == 0 && !quotaCores)
		return boost::none;
	return cpuCount;
}

boost::optional<double> LinuxCgroupV1::readHostCpuQuotaCores()
{
	if (s_cpuRootDir.empty() || s_cpuMountRootDir.empty())
		return boost::none;

	boost::optional<double> effective;
	for (const auto &path : cgroupHierarchy(s_cpuRootDir, s_cpuMountRootDir))
	{
		const auto quota = readValueFromFile(path + "/cpu.cfs_quota_us");
		const auto period = readValueFromFile(path + "/cpu.cfs_period_us");
		if (!quota || !period || *period <= 0)
			return boost::none;
		if (*quota <= 0)
			continue;
		const double cores = static_cast<double>(*quota) / static_cast<double>(*period);
		if (!effective || cores < *effective)
			effective = cores;
	}
	return effective ? effective : boost::optional<double>(0.0);
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
std::string LinuxCgroupV2::s_cgroupMountRootDir;
std::string LinuxCgroupV2::s_cgroupManagementRootDir;

LinuxCgroupV2::LinuxCgroupV2(long long memoryLimitBytes, long long memorySwapBytes, long long cpuShares, bool swapLimitSpecified)
	: m_memoryLimitBytes(memoryLimitBytes),
	  m_memorySwapBytes(memorySwapBytes),
	  m_swapLimitSpecified(swapLimitSpecified),
	  m_cpuShares(cpuShares),
	  m_pid(0),
	  m_enabled(false),
	  m_swapLimitSupported(true)
{
#if defined(__linux__)
	const static char fname[] = "LinuxCgroupV2::LinuxCgroupV2() ";

	// Validate and adjust memory limit
	if (m_memoryLimitBytes > 0 && m_memoryLimitBytes < MIN_MEMORY_LIMIT_BYTES)
	{
		LOG_WAR << fname << "Memory limit <" << m_memoryLimitBytes << "> below minimum, increased to <" << MIN_MEMORY_LIMIT_BYTES << "> bytes";
		m_memoryLimitBytes = MIN_MEMORY_LIMIT_BYTES;
	}

	m_enabled = (m_memoryLimitBytes > 0 || m_swapLimitSpecified || m_cpuShares > 0);

	if (m_enabled)
	{
		std::call_once(cgroupV2MountOnce, [this]() { discoverMountPoint(); });

		// Check swap support in v2
		if (!s_cgroupRootDir.empty())
		{
			// In cgroup v2, check if memory.swap.max is available
			std::string swapFile = s_cgroupRootDir + "/memory.swap.max";
			if (!Utility::isFileExist(swapFile))
			{
				m_swapLimitSupported = false;
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
	std::lock_guard<std::mutex> managementGuard(cgroupV2ManagementMutex);
	if (Utility::isDirExist(m_cgroupPath))
	{
		boost::system::error_code ec;
		if (!fs::remove(m_cgroupPath, ec) && ec)
			LOG_WAR << fname << "Failed to remove cgroup <" << m_cgroupPath << ">: " << ec.message();
	}
}

void LinuxCgroupV2::discoverMountPoint()
{
#if defined(__linux__)
	const static char fname[] = "LinuxCgroupV2::discoverMountPoint() ";

	// Default location for cgroup v2
	const std::string defaultPath = "/sys/fs/cgroup";

	if (Utility::isFileExist(defaultPath + "/cgroup.controllers"))
	{
		s_cgroupRootDir = s_cgroupMountRootDir = defaultPath;
	}
	else
	{
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
				s_cgroupRootDir = s_cgroupMountRootDir = entry->mnt_dir;
				break;
			}
		}
	}

	if (s_cgroupRootDir.empty())
	{
		LOG_WAR << fname << "Cgroup v2 mount point not found";
		return;
	}

	const auto candidate = cgroupCandidatePath(s_cgroupRootDir,
		cgroupMountRoot(s_cgroupRootDir, "cgroup2"), currentCgroupPath(""));
	if (Utility::isFileExist(candidate + "/cgroup.procs"))
		s_cgroupRootDir = candidate;
	LOG_DBG << fname << "Cgroup v2 path: " << s_cgroupRootDir;
#endif
}

long long LinuxCgroupV2::sharesToWeight(long long shares)
{
	// Convert v1 cpu.shares to v2 cpu.weight
	// V1: shares range 2-262144, default 1024
	// V2: weight range 1-10000, default 100
	// Formula: weight = 1 + ((shares - 2) * 9999) / 262142

	if (shares <= 0)
		return DEFAULT_CPU_WEIGHT;

	const auto clamped = std::max(2LL, std::min(262144LL, shares));
	return 1 + ((clamped - 2) * 9999) / 262142;
}

bool LinuxCgroupV2::enableControllers(const std::string &cgroupPath)
{
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
	if (current != root)
		return false;

	// Enable controllers from root down (reverse order)
	std::reverse(pathComponents.begin(), pathComponents.end());

	for (const auto &component : pathComponents)
	{
		const auto parentPath = fs::path(component).parent_path().string();
		const auto controllers = Utility::readFile(parentPath + "/cgroup.controllers");
		std::string requested;
		if (m_memoryLimitBytes > 0 || m_swapLimitSpecified)
		{
			if (!hasWhitespaceToken(controllers, "memory"))
				return false;
			requested += "+memory ";
		}
		if (m_cpuShares > 0)
		{
			if (!hasWhitespaceToken(controllers, "cpu"))
				return false;
			requested += "+cpu ";
		}
		std::ofstream output(parentPath + "/cgroup.subtree_control");
		if (!output.is_open())
			return false;
		output << requested;
		output.flush();
		if (output.fail())
			return false;
		output.close();
		if (output.fail())
			return false;
		const auto enabled = Utility::readFile(parentPath + "/cgroup.subtree_control");
		if ((m_memoryLimitBytes > 0 || m_swapLimitSpecified) && !hasWhitespaceToken(enabled, "memory"))
			return false;
		if (m_cpuShares > 0 && !hasWhitespaceToken(enabled, "cpu"))
			return false;
	}

	return true;
}

void LinuxCgroupV2::initializeManagement(int additionalPid)
{
	const auto perm = fs::perms::owner_all | fs::perms::group_exe | fs::perms::others_exe;
	std::lock_guard<std::mutex> managementGuard(cgroupV2ManagementMutex);
	if (!s_cgroupManagementRootDir.empty())
		return;
	if (s_cgroupRootDir.empty())
		throw std::runtime_error("cgroup v2 resource root is unavailable");
	const auto daemonPid = static_cast<int>(ACE_OS::getpid());
	const auto daemonLeaf = (fs::path(s_cgroupRootDir) / "appmesh-daemon").string();
	const auto applicationsRoot = (fs::path(s_cgroupRootDir) / CGROUP_APPMESH_DIR).string();
	if (!Utility::createRecursiveDirectory(daemonLeaf, perm) ||
		!addProcessToCgroup(daemonLeaf, daemonPid, "cgroup.procs") ||
		(additionalPid > 1 && additionalPid != daemonPid &&
			!addProcessToCgroup(daemonLeaf, additionalPid, "cgroup.procs")))
		throw std::runtime_error("failed to move App Mesh processes into a cgroup v2 leaf");
	if (!Utility::stdStringTrim(Utility::readFile(s_cgroupRootDir + "/cgroup.procs")).empty())
		throw std::runtime_error("cgroup v2 resource root contains unmanaged processes");
	if (!Utility::createRecursiveDirectory(applicationsRoot, perm) || !enableControllers(applicationsRoot))
		throw std::runtime_error("failed to initialize delegated cgroup v2 controllers");
	s_cgroupManagementRootDir = applicationsRoot;
}

void LinuxCgroupV2::applyLimits(const std::string &appName, int pid, int index)
{
	const static char fname[] = "LinuxCgroupV2::applyLimits() ";

	if (!m_enabled)
		return;
	if (!isSafeCgroupComponent(appName) || index < 0)
		throw std::invalid_argument("unsafe cgroup application component");

	m_pid = pid;
	initializeManagement(pid);
	std::lock_guard<std::mutex> managementGuard(cgroupV2ManagementMutex);
	const auto perm = fs::perms::owner_all | fs::perms::group_exe | fs::perms::others_exe;

	m_cgroupPath = (fs::path(s_cgroupManagementRootDir) /
		(appName + "-" + std::to_string(index))).string();

	if (!Utility::createRecursiveDirectory(m_cgroupPath, perm))
	{
		LOG_ERR << fname << "Failed to create cgroup directory: " << m_cgroupPath;
		throw std::runtime_error("failed to create cgroup v2 application directory");
	}

	// Enable controllers in parent directories
	if (!enableControllers(m_cgroupPath))
		throw std::runtime_error("failed to enable cgroup v2 controllers");

	if ((m_memoryLimitBytes > 0 || m_swapLimitSpecified) && !applyMemoryLimit(m_cgroupPath))
		throw std::runtime_error("failed to apply cgroup v2 memory limits");
	if (m_cpuShares > 0 && !applyCpuWeight(m_cgroupPath))
		throw std::runtime_error("failed to apply cgroup v2 CPU weight");
	if (!addProcessToCgroup(m_cgroupPath, m_pid, "cgroup.procs"))
		throw std::runtime_error("failed to attach process to cgroup v2");

	LOG_DBG << fname << "Applied cgroup v2 limits for app <" << appName << "> pid <" << pid << ">";
}

bool LinuxCgroupV2::applyMemoryLimit(const std::string &cgroupPath)
{
	const static char fname[] = "LinuxCgroupV2::applyMemoryLimit() ";

	// In cgroup v2, use memory.max for memory limit
	if (m_memoryLimitBytes > 0)
	{
		std::string memMaxFile = cgroupPath + "/memory.max";
		if (!writeValueToFile(memMaxFile, m_memoryLimitBytes))
			return false;
	}

	// In cgroup v2, memory.swap.max is separate (not combined like v1)
	if (m_swapLimitSpecified)
	{
		std::string swapMaxFile = cgroupPath + "/memory.swap.max";
		if (Utility::isFileExist(swapMaxFile))
		{
			if (!writeValueToFile(swapMaxFile, m_memorySwapBytes))
				return false;
		}
		else
		{
			m_swapLimitSupported = false;
			LOG_WAR << fname << "Swap limit not supported (memory.swap.max not available)";
			return false;
		}
	}
	return true;
}

bool LinuxCgroupV2::applyCpuWeight(const std::string &cgroupPath)
{
	// Convert shares to weight
	long long weight = sharesToWeight(m_cpuShares);

	std::string weightFile = cgroupPath + "/cpu.weight";
	return writeValueToFile(weightFile, weight);
}

boost::optional<long long> LinuxCgroupV2::readHostMemoryValue(const std::string &cgroupFileName)
{
	if (s_cgroupRootDir.empty())
		return boost::none;

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
	else if (cgroupFileName == "memory.memsw.usage_in_bytes")
	{
		v2FileName = "memory.swap.current";
	}

	const bool isLimit = v2FileName == "memory.max" || v2FileName == "memory.swap.max";
	if (!isLimit)
		return readValueFromFile(s_cgroupRootDir + "/" + v2FileName);

	boost::optional<long long> effective;
	for (const auto &path : cgroupHierarchy(s_cgroupRootDir, s_cgroupMountRootDir))
	{
		const auto value = readValueFromFile(path + "/" + v2FileName);
		if (!value)
			return boost::none;
		if (!effective || *value < *effective)
			effective = *value;
	}
	return effective;
}

boost::optional<long long> LinuxCgroupV2::readHostMemoryAvailableValue(const std::string &limitFileName, const std::string &currentFileName)
{
	const auto mapName = [](const std::string &name) {
		if (name == "memory.limit_in_bytes") return std::string("memory.max");
		if (name == "memory.usage_in_bytes") return std::string("memory.current");
		if (name == "memory.memsw.limit_in_bytes") return std::string("memory.swap.max");
		if (name == "memory.memsw.usage_in_bytes") return std::string("memory.swap.current");
		return name;
	};
	const auto limitName = mapName(limitFileName);
	const auto currentName = mapName(currentFileName);
	boost::optional<long long> available;
	for (const auto &path : cgroupHierarchy(s_cgroupRootDir, s_cgroupMountRootDir))
	{
		const auto limit = readValueFromFile(path + "/" + limitName);
		const auto current = readValueFromFile(path + "/" + currentName);
		if (!limit || !current)
			return boost::none;
		if (*limit == std::numeric_limits<long long>::max())
			continue;
		const auto headroom = std::max(0LL, *limit - std::max(0LL, *current));
		if (!available || headroom < *available)
			available = headroom;
	}
	return available ? available : boost::optional<long long>(std::numeric_limits<long long>::max());
}

boost::optional<CgroupSwapStats> LinuxCgroupV2::readHostSwapStats()
{
	CgroupSwapStats stats;
	bool leaf = true;
	for (const auto &path : cgroupHierarchy(s_cgroupRootDir, s_cgroupMountRootDir))
	{
		const auto limit = readValueFromFile(path + "/memory.swap.max");
		const auto current = readValueFromFile(path + "/memory.swap.current");
		if (!limit || !current)
			return boost::none;
		if (leaf)
		{
			stats.currentBytes = std::max(0LL, *current);
			leaf = false;
		}
		if (*limit != std::numeric_limits<long long>::max())
		{
			stats.limitBytes = stats.limitBytes ? std::min(*stats.limitBytes, *limit) : *limit;
			const auto headroom = std::max(0LL, *limit - std::max(0LL, *current));
			stats.headroomBytes = stats.headroomBytes ? std::min(*stats.headroomBytes, headroom) : headroom;
		}
	}
	return leaf ? boost::none : boost::optional<CgroupSwapStats>(stats);
}

boost::optional<int> LinuxCgroupV2::readHostCpuCount()
{
	const static char fname[] = "LinuxCgroupV2::readHostCpuCount() ";

	if (s_cgroupRootDir.empty())
	{
		LOG_WAR << fname << "Cgroup root directory not discovered";
		return boost::none;
	}

	// In cgroup v2, cpuset is unified
	int cpuCount = 0;
	for (const auto &path : cgroupHierarchy(s_cgroupRootDir, s_cgroupMountRootDir))
	{
		std::string cpusetFile = path + "/cpuset.cpus.effective";
		if (!Utility::isFileExist(cpusetFile))
			cpusetFile = path + "/cpuset.cpus";
		const auto pathCpuCount = parseCpuSetString(Utility::readFile(cpusetFile));
		if (pathCpuCount > 0)
			cpuCount = cpuCount > 0 ? std::min(cpuCount, pathCpuCount) : pathCpuCount;
	}
	const auto quotaCores = readHostCpuQuotaCores();
	if (quotaCores && *quotaCores > 0)
	{
		const int quotaCount = static_cast<int>(std::ceil(*quotaCores));
		cpuCount = cpuCount > 0 ? std::min(cpuCount, quotaCount) : quotaCount;
	}

	LOG_DBG << fname << "CPU count: " << cpuCount;
	if (cpuCount == 0 && !quotaCores)
		return boost::none;
	return cpuCount;
}

boost::optional<double> LinuxCgroupV2::readHostCpuQuotaCores()
{
	if (s_cgroupRootDir.empty())
		return boost::none;

	boost::optional<double> effective;
	for (const auto &path : cgroupHierarchy(s_cgroupRootDir, s_cgroupMountRootDir))
	{
		std::istringstream cpuMax(Utility::readFile(path + "/cpu.max"));
		std::string quotaValue;
		long long period = 0;
		cpuMax >> quotaValue >> period;
		if (quotaValue.empty() || period <= 0)
			return boost::none;
		if (quotaValue == "max")
			continue;
		try
		{
			const auto quota = std::stoll(quotaValue);
			if (quota <= 0)
				return boost::none;
			const double cores = static_cast<double>(quota) / static_cast<double>(period);
			if (!effective || cores < *effective)
				effective = cores;
		}
		catch (const std::exception &)
		{
			return boost::none;
		}
	}
	return effective ? effective : boost::optional<double>(0.0);
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
	(void)appName;
	(void)pid;
	(void)index;
	if (m_limitsRequested)
		throw std::runtime_error("resource limits requested but cgroup is unavailable");
}

boost::optional<long long> LinuxCgroupNull::readHostMemoryValue(const std::string &cgroupFileName)
{
	(void)cgroupFileName;
	return boost::none;
}

boost::optional<long long> LinuxCgroupNull::readHostMemoryAvailableValue(const std::string &limitFileName, const std::string &currentFileName)
{
	(void)limitFileName;
	(void)currentFileName;
	return boost::none;
}

boost::optional<CgroupSwapStats> LinuxCgroupNull::readHostSwapStats()
{
	return boost::none;
}

boost::optional<int> LinuxCgroupNull::readHostCpuCount()
{
	return boost::none;
}

boost::optional<double> LinuxCgroupNull::readHostCpuQuotaCores()
{
	return boost::none;
}

bool LinuxCgroupNull::isSwapLimitSupported() const
{
	return false;
}

bool LinuxCgroupNull::isEnabled() const
{
	return false;
}

// src/daemon/process/LinuxCgroup.h
#pragma once

#include <boost/optional.hpp>
#include <memory>
#include <string>

/// Linux Cgroup version enumeration
enum class CgroupVersion
{
	None, // Cgroup not available or not needed
	V1,	  // Cgroup v1 (legacy)
	V2	  // Cgroup v2 (unified)
};

struct CgroupSwapStats
{
	boost::optional<long long> limitBytes; // none means unlimited
	long long currentBytes = 0;
	boost::optional<long long> headroomBytes; // none means unlimited
};

/// Abstract base class for Linux Cgroup operations
class LinuxCgroup
{
public:
	virtual ~LinuxCgroup() = default;

	/// Factory method to create appropriate cgroup implementation
	/// @param memoryLimitBytes Physical memory limit in bytes (0 = no limit)
	/// @param memorySwapBytes Swap-only limit in bytes; explicit zero disables swap
	/// @param cpuShares CPU shares for scheduling priority
	/// @return Unique pointer to cgroup implementation (V1, V2, or null handler)
	static std::unique_ptr<LinuxCgroup> create(long long memoryLimitBytes, long long memorySwapBytes,
		long long cpuShares, bool swapLimitSpecified = false);

	/// Detect which cgroup version is available on the system
	/// @return CgroupVersion enum indicating available version
	static CgroupVersion detectCgroupVersion();
	/// Prepare a delegated cgroup v2 domain before application processes start.
	static void initializeApplicationCgroups();

	/// Apply cgroup limits to a process
	/// @param appName Application name for cgroup naming
	/// @param pid Process ID to add to cgroup
	/// @param index Instance index for unique cgroup path
	virtual void applyLimits(const std::string &appName, int pid, int index) = 0;

	/// Read memory value from host cgroup
	/// @param cgroupFileName Name of the cgroup file to read
	/// @return Value read from the file
	virtual boost::optional<long long> readHostMemoryValue(const std::string &cgroupFileName) = 0;
	/// Effective headroom across the current cgroup and all of its ancestors.
	virtual boost::optional<long long> readHostMemoryAvailableValue(const std::string &limitFileName,
		const std::string &currentFileName) = 0;
	virtual boost::optional<CgroupSwapStats> readHostSwapStats() = 0;

	/// Get the number of CPUs available in the cpuset
	/// and CPU quota. An unlimited quota is ignored.
	/// @return Effective number of logical CPUs available
	virtual boost::optional<int> readHostCpuCount() = 0;

	/// Read the CPU quota as a fractional number of cores.
	/// @return Quota in cores, 0 when unlimited, or no value on failure.
	virtual boost::optional<double> readHostCpuQuotaCores() = 0;

	/// Check if swap limit is supported
	/// @return true if swap limiting is supported
	virtual bool isSwapLimitSupported() const = 0;

	/// Check if cgroup is enabled for this instance
	/// @return true if cgroup limits are active
	virtual bool isEnabled() const = 0;

protected:
	LinuxCgroup() = default;

	/// Write a value to a cgroup file
	/// @param filePath Full path to the cgroup file
	/// @param value Value to write
	/// @return true on success
	static bool writeValueToFile(const std::string &filePath, long long value);

	/// Read a value from a cgroup file
	/// @param filePath Full path to the cgroup file
	/// @return Value read from the file, or no value on I/O/parse failure.
	static boost::optional<long long> readValueFromFile(const std::string &filePath);

	/// Add a process to a cgroup
	/// @param cgroupPath Path to the cgroup directory
	/// @param pid Process ID to add
	/// @param procsFileName Name of the procs/tasks file
	/// @return true on success
	static bool addProcessToCgroup(const std::string &cgroupPath, int pid, const std::string &procsFileName);
};

/// Cgroup V1 implementation
class LinuxCgroupV1 : public LinuxCgroup
{
public:
	LinuxCgroupV1(long long memoryLimitBytes, long long memorySwapBytes, long long cpuShares, bool swapLimitSpecified = false);
	~LinuxCgroupV1() override;

	void applyLimits(const std::string &appName, int pid, int index) override;
	boost::optional<long long> readHostMemoryValue(const std::string &cgroupFileName) override;
	boost::optional<long long> readHostMemoryAvailableValue(const std::string &limitFileName, const std::string &currentFileName) override;
	boost::optional<CgroupSwapStats> readHostSwapStats() override;
	boost::optional<int> readHostCpuCount() override;
	boost::optional<double> readHostCpuQuotaCores() override;
	bool isSwapLimitSupported() const override;
	bool isEnabled() const override;

private:
	/// Discover cgroup v1 mount points from /proc/mounts
	void discoverMountPoints();

	/// Set physical memory limit
	/// @param cgroupPath Path to memory cgroup directory
	bool applyMemoryLimit(const std::string &cgroupPath);

	/// Set swap memory limit
	/// @param cgroupPath Path to memory cgroup directory
	bool applySwapLimit(const std::string &cgroupPath);

	/// Set CPU shares
	/// @param cgroupPath Path to cpu cgroup directory
	bool applyCpuShares(const std::string &cgroupPath);

	/// Clean up cgroup directories
	void cleanup();

private:
	long long m_memoryLimitBytes;
	long long m_memorySwapBytes;
	bool m_swapLimitSpecified;
	long long m_cpuShares;

	int m_pid;
	std::string m_cgroupMemoryPath;
	std::string m_cgroupCpuPath;
	bool m_enabled;
	bool m_swapLimitSupported;

	// Mount points (discovered once, shared across instances)
	static std::string s_memoryRootDir;
	static std::string s_cpuRootDir;
	static std::string s_cpusetRootDir;
	static std::string s_memoryMountRootDir;
	static std::string s_cpuMountRootDir;
	static std::string s_cpusetMountRootDir;
};

/// Cgroup V2 (unified) implementation
class LinuxCgroupV2 : public LinuxCgroup
{
public:
	LinuxCgroupV2(long long memoryLimitBytes, long long memorySwapBytes, long long cpuShares, bool swapLimitSpecified = false);
	~LinuxCgroupV2() override;

	void applyLimits(const std::string &appName, int pid, int index) override;
	boost::optional<long long> readHostMemoryValue(const std::string &cgroupFileName) override;
	boost::optional<long long> readHostMemoryAvailableValue(const std::string &limitFileName, const std::string &currentFileName) override;
	boost::optional<CgroupSwapStats> readHostSwapStats() override;
	boost::optional<int> readHostCpuCount() override;
	boost::optional<double> readHostCpuQuotaCores() override;
	bool isSwapLimitSupported() const override;
	bool isEnabled() const override;
	void initializeManagement(int additionalPid = 0);

private:
	/// Discover cgroup v2 mount point
	void discoverMountPoint();

	/// Enable controllers for a cgroup path
	/// @param cgroupPath Path to cgroup directory
	/// @return true on success
	bool enableControllers(const std::string &cgroupPath);

	/// Set memory limits (memory.max and memory.swap.max)
	/// @param cgroupPath Path to cgroup directory
	bool applyMemoryLimit(const std::string &cgroupPath);

	/// Set CPU weight (replaces cpu.shares in v2)
	/// @param cgroupPath Path to cgroup directory
	bool applyCpuWeight(const std::string &cgroupPath);

	/// Clean up cgroup directory
	void cleanup();

	/// Convert CPU shares (v1) to CPU weight (v2)
	/// V1 shares: 2-262144, default 1024
	/// V2 weight: 1-10000, default 100
	/// @param shares CPU shares value
	/// @return Equivalent CPU weight
	static long long sharesToWeight(long long shares);

private:
	long long m_memoryLimitBytes;
	long long m_memorySwapBytes;
	bool m_swapLimitSpecified;
	long long m_cpuShares;

	int m_pid;
	std::string m_cgroupPath;
	bool m_enabled;
	bool m_swapLimitSupported;

	// Mount point (discovered once, shared across instances)
	static std::string s_cgroupRootDir;
	static std::string s_cgroupMountRootDir;
	static std::string s_cgroupManagementRootDir;
};

/// Null implementation when cgroup is not available or not needed
class LinuxCgroupNull : public LinuxCgroup
{
public:
	explicit LinuxCgroupNull(bool limitsRequested = false) : m_limitsRequested(limitsRequested) {}
	~LinuxCgroupNull() override = default;

	void applyLimits(const std::string &appName, int pid, int index) override;
	boost::optional<long long> readHostMemoryValue(const std::string &cgroupFileName) override;
	boost::optional<long long> readHostMemoryAvailableValue(const std::string &limitFileName, const std::string &currentFileName) override;
	boost::optional<CgroupSwapStats> readHostSwapStats() override;
	boost::optional<int> readHostCpuCount() override;
	boost::optional<double> readHostCpuQuotaCores() override;
	bool isSwapLimitSupported() const override;
	bool isEnabled() const override;

private:
	bool m_limitsRequested;
};

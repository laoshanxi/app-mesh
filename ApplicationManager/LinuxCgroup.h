#ifndef LINUX_CGROUP_H
#define LINUX_CGROUP_H
#include <string>
class LinuxCgroup
{
public:
	explicit LinuxCgroup(long long memLimitBytes, long long memSwapBytes, long long cpuShares);
	virtual ~LinuxCgroup();
	void setCgroup(const std::string& appName, int pid, int index);

private:
	void retrieveCgroupHeirarchy();
	void setPhysicalMemory(const std::string& cgroupPath, long long memLimitBytes);
	void setSwapMemory(const std::string& cgroupPath, long long memSwapBytes);
	void setCpuShares(const std::string& cgroupPath, long long cpuShares);
	void writeFile(const std::string& cgroupPath, long long value);

private:
	long long m_memLimitMb;
	long long m_memSwapMb;
	long long m_cpuShares;

	int m_pid;
	std::string cgroupMemoryPath;
	std::string cgroupCpuPath;
	bool cgroupEnabled;

	static std::string cgroupMemRootName;
	static std::string cgroupCpuRootName;
	static const std::string cgroupBaseDir;
};

#endif

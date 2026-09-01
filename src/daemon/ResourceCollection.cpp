// src/daemon/ResourceCollection.cpp
#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ace/OS.h>

#include "../common/DateTime.h"
#include "../common/Utility.h"
#include "../common/json.h"
#include "../common/os/net.h"
#include "../common/os/pstree.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "application/Application.h"
#include "process/LinuxCgroup.h"

ResourceCollection::ResourceCollection()
	: m_appmeshStartTime(std::chrono::system_clock::now())
{
}

std::unique_ptr<ResourceCollection> &ResourceCollection::instance()
{
	static auto singleton = std::make_unique<ResourceCollection>();
	return singleton;
}

std::string ResourceCollection::getHostName() const
{
	return net::hostname();
}

HostResource ResourceCollection::getHostResource()
{
	const bool isContainer = Utility::runningInContainer();
	HostResource resources;
	resources.m_inContainer = isContainer;

	auto nets = net::getNetworkLinks();
	// Net
	for (auto &net : nets)
	{
		HostNetInterface inet;
		inet.address = net.address;
		inet.ipv6 = net.ipv6;
		inet.name = net.name;
		resources.m_ipaddress.push_back(std::move(inet));
	}
	if (resources.m_ipaddress.empty())
		resources.m_collectorErrors.push_back("network_interfaces_unavailable");
	// Report host topology and effective cgroup capacity separately.
	static auto cpus = os::cpus();
	std::set<unsigned int> uniqueSockets;
	std::set<std::pair<unsigned int, unsigned int>> uniqueCores;

	for (const auto &cpu : cpus)
	{
		uniqueSockets.insert(cpu.socket);
		uniqueCores.emplace(cpu.socket, cpu.core);
	}

	resources.m_processors = cpus.size();
	resources.m_cores = uniqueCores.size();
	resources.m_sockets = uniqueSockets.size();
	resources.m_effectiveProcessors = resources.m_processors;
	if (cpus.empty())
		resources.m_collectorErrors.push_back("host_cpu_topology_unavailable");

#if defined(__linux__)
	// Cgroup limits also apply outside containers, such as systemd services.
	static auto cgroup = LinuxCgroup::create(0, 0, 100);
	LinuxCgroup *hostCgroup = cgroup.get();
	const auto cgroupVersion = LinuxCgroup::detectCgroupVersion();
	resources.m_cgroupVersion = cgroupVersion == CgroupVersion::V2 ? "v2" : (cgroupVersion == CgroupVersion::V1 ? "v1" : "none");
	const auto effectiveProcessors = hostCgroup->readHostCpuCount();
	if (effectiveProcessors && *effectiveProcessors > 0)
	{
		const auto constrained = static_cast<std::size_t>(*effectiveProcessors);
		resources.m_effectiveProcessors = resources.m_processors > 0
			? std::min(resources.m_processors, constrained) : constrained;
		resources.m_cpuSource = "cgroup";
	}
	else if (!effectiveProcessors && cgroupVersion != CgroupVersion::None)
		resources.m_collectorErrors.push_back("cgroup_cpu_count_unavailable");
	const auto cpuQuota = hostCgroup->readHostCpuQuotaCores();
	if (cpuQuota)
	{
		resources.m_cpuQuotaCores = *cpuQuota;
		if (*cpuQuota > 0)
			resources.m_cpuSource = "cgroup";
	}
	else if (cgroupVersion != CgroupVersion::None)
		resources.m_collectorErrors.push_back("cgroup_cpu_quota_unavailable");
#endif
	// Memory
	const auto hostMemory = os::memory();
	bool swapCollected = false;
#if defined(__linux__)
	if (hostCgroup != nullptr && cgroupVersion != CgroupVersion::None)
	{
		// Cgroup v1 encodes unlimited memory near LONG_MAX.
		constexpr long long CGROUP_V1_UNLIMITED_THRESHOLD = 9223372036854771712LL;
		const auto isFiniteLimit = [](long long value) {
			return value > 0 && value < CGROUP_V1_UNLIMITED_THRESHOLD;
		};
		const auto memoryLimitValue = hostCgroup->readHostMemoryValue("memory.limit_in_bytes");
		const auto memoryCurrentValue = hostCgroup->readHostMemoryValue("memory.usage_in_bytes");
		const auto memoryAvailableValue = hostCgroup->readHostMemoryAvailableValue("memory.limit_in_bytes", "memory.usage_in_bytes");
		if (!memoryLimitValue)
			resources.m_collectorErrors.push_back("cgroup_memory_limit_unavailable");
		if (!memoryCurrentValue)
			resources.m_collectorErrors.push_back("cgroup_memory_current_unavailable");
		const auto memoryLimit = memoryLimitValue.value_or(0);
		const auto memoryCurrent = memoryCurrentValue.value_or(0);
		const bool useCgroupMemory = isFiniteLimit(memoryLimit) && memoryCurrentValue &&
			(hostMemory == nullptr || static_cast<uint64_t>(memoryLimit) <= hostMemory->total_bytes);
		if (useCgroupMemory)
		{
			resources.m_total_bytes = static_cast<uint64_t>(memoryLimit);
			resources.m_current_bytes = static_cast<uint64_t>(std::max(0LL, memoryCurrent));
			const auto capacityHeadroom = resources.m_current_bytes < resources.m_total_bytes
				? resources.m_total_bytes - resources.m_current_bytes : 0;
			resources.m_available_bytes = memoryAvailableValue && *memoryAvailableValue < CGROUP_V1_UNLIMITED_THRESHOLD
				? static_cast<uint64_t>(std::max(0LL, *memoryAvailableValue))
				: capacityHeadroom;
			if (hostMemory != nullptr)
				resources.m_available_bytes = std::min(resources.m_available_bytes, hostMemory->available_bytes);
			resources.m_available_bytes = std::min(resources.m_available_bytes, capacityHeadroom);
			resources.m_memorySource = "cgroup";
			if (!memoryAvailableValue)
				resources.m_collectorErrors.push_back("cgroup_memory_available_unavailable");
		}

		if (hostCgroup->isSwapLimitSupported())
		{
			const auto swap = hostCgroup->readHostSwapStats();
			if (swap && (swap->limitBytes || hostMemory != nullptr))
			{
				resources.m_totalSwap_bytes = swap->limitBytes
					? static_cast<uint64_t>(std::max(0LL, *swap->limitBytes))
					: hostMemory->totalSwap_bytes;
				if (hostMemory != nullptr)
					resources.m_totalSwap_bytes = std::min(resources.m_totalSwap_bytes, hostMemory->totalSwap_bytes);
				resources.m_currentSwap_bytes = static_cast<uint64_t>(std::max(0LL, swap->currentBytes));
				resources.m_freeSwap_bytes = resources.m_currentSwap_bytes < resources.m_totalSwap_bytes
					? resources.m_totalSwap_bytes - resources.m_currentSwap_bytes : 0;
				if (swap->headroomBytes)
					resources.m_freeSwap_bytes = std::min<uint64_t>(
						resources.m_freeSwap_bytes, static_cast<uint64_t>(std::max(0LL, *swap->headroomBytes)));
				if (hostMemory != nullptr)
					resources.m_freeSwap_bytes = std::min(resources.m_freeSwap_bytes, hostMemory->freeSwap_bytes);
				resources.m_swapSource = "cgroup";
				swapCollected = true;
			}
			else
				resources.m_collectorErrors.push_back("cgroup_swap_unavailable");
		}
	}
#endif
	if (resources.m_total_bytes == 0)
	{
		if (hostMemory != nullptr)
		{
			resources.m_total_bytes = hostMemory->total_bytes;
			resources.m_available_bytes = hostMemory->available_bytes;
			resources.m_current_bytes = resources.m_total_bytes > hostMemory->free_bytes
										 ? resources.m_total_bytes - hostMemory->free_bytes
										 : 0;
		}
		else
		{
			resources.m_collectorErrors.push_back("host_memory_unavailable");
		}
	}
	if (!swapCollected && hostMemory != nullptr && hostMemory->swapAvailable)
	{
		resources.m_totalSwap_bytes = hostMemory->totalSwap_bytes;
		resources.m_freeSwap_bytes = hostMemory->freeSwap_bytes;
		resources.m_currentSwap_bytes = resources.m_totalSwap_bytes > resources.m_freeSwap_bytes
			? resources.m_totalSwap_bytes - resources.m_freeSwap_bytes : 0;
	}
	else if (!swapCollected)
	{
		resources.m_collectorErrors.push_back("swap_accounting_unavailable");
	}
	return resources;
}

pid_t ResourceCollection::getPid()
{
	static auto pid = getpid();
	return pid;
}

void ResourceCollection::dump(const HostResource &resources)
{
	const static char fname[] = "ResourceCollection::dump() ";

	LOG_DBG << fname << "host_name:" << getHostName();
	LOG_DBG << fname << "os_user:" << os::getUsernameByUid();
	for (const auto &pair : resources.m_ipaddress)
	{
		LOG_DBG << fname << "m_ipaddress: " << pair.name << "," << pair.ipv6 << "," << pair.address;
	}
	LOG_DBG << fname << "m_cores:" << resources.m_cores;
	LOG_DBG << fname << "m_sockets:" << resources.m_sockets;
	LOG_DBG << fname << "m_processors:" << resources.m_processors;
	LOG_DBG << fname << "m_total_bytes:" << resources.m_total_bytes;
	LOG_DBG << fname << "m_available_bytes:" << resources.m_available_bytes;
	LOG_DBG << fname << "m_totalSwap_bytes:" << resources.m_totalSwap_bytes;
	LOG_DBG << fname << "m_freeSwap_bytes:" << resources.m_freeSwap_bytes;
}

nlohmann::json ResourceCollection::AsJson()
{
	const static char fname[] = "ResourceCollection::AsJson() ";
	LOG_DBG << fname << "Entered";

	auto res = this->getHostResource();

	nlohmann::json result = nlohmann::json::object();
	result["schema_version"] = 3;
	result["collected_at_unix_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(
										  std::chrono::system_clock::now().time_since_epoch())
										  .count();
	result["in_container"] = res.m_inContainer;
	result["appmesh_version"] = std::string(__MICRO_VAR__(BUILD_TAG));
#if defined(__linux__)
	result["os"] = "linux";
#elif defined(__APPLE__)
	result["os"] = "macos";
#elif defined(_WIN32)
	result["os"] = "windows";
#else
	result["os"] = "unknown";
#endif
#if defined(__x86_64__) || defined(_M_X64)
	result["architecture"] = "amd64";
#elif defined(__aarch64__) || defined(_M_ARM64)
	result["architecture"] = "arm64";
#elif defined(__i386__) || defined(_M_IX86)
	result["architecture"] = "386";
#else
	result["architecture"] = "unknown";
#endif
	result[("host_name")] = std::string((getHostName()));
	result[("host_description")] = std::string(Configuration::instance()->getDescription());
	static const auto osUser = os::getUsernameByUid();
	result[("os_user")] = osUser;
	auto arr = nlohmann::json::array();
	for (const auto &network : res.m_ipaddress)
	{
		arr.push_back({{"name", network.name}, {"ipv6", network.ipv6}, {"address", network.address}});
	}
	result[("net")] = std::move(arr);
	result[("cpu_cores")] = (res.m_cores);
	result[("cpu_sockets")] = (res.m_sockets);
	result[("cpu_processors")] = (res.m_processors);
	result["cpu_effective_processors"] = res.m_effectiveProcessors;
	result["cpu_quota_cores"] = res.m_cpuQuotaCores;
	result["cpu_source"] = res.m_cpuSource;
	result["memory_source"] = res.m_memorySource;
	result["swap_source"] = res.m_swapSource;
	result["cgroup_version"] = res.m_cgroupVersion;
	result[("mem_total_bytes")] = (res.m_total_bytes);
	result["mem_available_bytes"] = res.m_available_bytes;
	result["mem_current_bytes"] = res.m_current_bytes;
	result["mem_swap_total_bytes"] = res.m_totalSwap_bytes;
	result["mem_swap_free_bytes"] = res.m_freeSwap_bytes;
	result["mem_swap_current_bytes"] = res.m_currentSwap_bytes;
	auto collectorErrors = nlohmann::json::array();
	for (const auto &error : res.m_collectorErrors)
		collectorErrors.push_back(error);
	const auto applications = Configuration::instance()->getApps();
	std::vector<pid_t> processRoots = {getPid()};
	for (const auto &app : applications)
	{
		const auto pid = app->getpid();
		if (pid > 1)
			processRoots.push_back(pid);
	}
	// One selected-root snapshot is reused for daemon, managed and recovered trees.
	const auto processes = os::processes(processRoots);
	auto daemonTree = os::pstree(getPid(), processes);
	if (daemonTree)
	{
		result["mem_daemon_process_tree_bytes"] = daemonTree->totalRssMemBytes();
		result[("fd")] = daemonTree->totalFileDescriptors();
	}
	else
	{
		result["mem_daemon_process_tree_bytes"] = 0;
		result[("fd")] = 0;
		collectorErrors.push_back("daemon_process_tree_unavailable");
	}
	// Daemon process only. "fd" above sums the whole daemon tree (dex, agent,
	// app children) whose churn is unrelated to daemon-side fd leaks.
	result["fd_daemon"] = os::getOpenFileDescriptorCount(getPid());

	std::unordered_map<pid_t, std::vector<pid_t>> children;
	for (const auto &process : processes)
		children[process.parent].push_back(process.pid);
	std::unordered_set<pid_t> applicationPids;
	for (const auto &app : applications)
	{
		const auto pid = app->getpid();
		if (pid <= 1)
			continue;
		applicationPids.insert(pid);
		const auto descendants = os::collectDescendants(pid, children);
		applicationPids.insert(descendants.begin(), descendants.end());
	}
	uint64_t applicationMemory = 0;
	for (const auto &process : processes)
	{
		if (applicationPids.count(process.pid) != 0)
			applicationMemory += process.rss_bytes;
	}
	result["mem_applications"] = applicationMemory;
	// Load
	auto load = os::loadavg();
	if (load != nullptr)
	{
		nlohmann::json sysLoad = nlohmann::json::object();
		sysLoad["1min"] = (load->one);
		sysLoad["5min"] = (load->five);
		sysLoad["15min"] = (load->fifteen);
		result[("load")] = std::move(sysLoad);
	}
	else
	{
#if !defined(_WIN32)
		collectorErrors.push_back("load_average_unavailable");
#endif
	}
	// FS
	auto mountPoints = os::getMountPoints();
	auto fsArr = nlohmann::json::array();
	bool filesystemError = mountPoints.empty();
	for (const auto &mount : mountPoints)
	{
		auto usage = os::df(mount.first);
		if (usage != nullptr)
		{
			nlohmann::json fs = nlohmann::json::object();
			fs["size"] = (usage->totalSize);
			fs["used"] = (usage->usedSize);
			fs["available"] = usage->availableSize;
			fs["usage"] = (usage->usagePercentage);
			fs["device"] = Utility::localEncodingToUtf8(mount.second);
			fs["mount_point"] = mount.first;
			fsArr.push_back(fs);
		}
		else
		{
			filesystemError = true;
		}
	}
	if (filesystemError)
		collectorErrors.push_back("filesystem_usage_unavailable");
	result[("fs")] = std::move(fsArr);
	result[("systime")] = std::string(DateTime::formatLocalTime(std::chrono::system_clock::now()));
	result[("appmesh_start_time")] = std::string(DateTime::formatLocalTime(m_appmeshStartTime));
	result["appmesh_start_time_unix_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(
											m_appmeshStartTime.time_since_epoch())
											.count();
	result[("pid")] = (getPid());
	result[("home")] = (Utility::getHomeDir());
	result["collector_errors"] = std::move(collectorErrors);
	LOG_DBG << fname << "Exit";
	return result;
}

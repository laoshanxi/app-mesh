// src/daemon/ResourceCollection.h
#pragma once

#include <chrono>
#include <list>
#include <memory>
#include <string>
#include <vector>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include <nlohmann/json.hpp>

struct HostNetInterface
{
	std::string name;
	bool ipv6;
	std::string address;
};
//////////////////////////////////////////////////////////////////////////
/// Host resource attribute
//////////////////////////////////////////////////////////////////////////
struct HostResource
{
	// CPU
	std::size_t m_cores = 0;
	std::size_t m_sockets = 0;
	std::size_t m_processors = 0;
	std::size_t m_effectiveProcessors = 0;
	double m_cpuQuotaCores = 0.0;
	// MEM
	uint64_t m_total_bytes = 0;
	uint64_t m_available_bytes = 0;
	uint64_t m_current_bytes = 0;
	uint64_t m_totalSwap_bytes = 0;
	uint64_t m_freeSwap_bytes = 0;
	uint64_t m_currentSwap_bytes = 0;
	bool m_inContainer = false;
	std::string m_cpuSource = "host";
	std::string m_memorySource = "host";
	std::string m_swapSource = "host";
	std::string m_cgroupVersion = "none";
	std::vector<std::string> m_collectorErrors;
	// NET
	std::list<HostNetInterface> m_ipaddress;
};

//////////////////////////////////////////////////////////////////////////
// Collect host and application resource usage metrics
//////////////////////////////////////////////////////////////////////////
class ResourceCollection
{
public:
	ResourceCollection();
	~ResourceCollection() = default;
	// Internal Singleton.
	static std::unique_ptr<ResourceCollection> &instance();

	std::string getHostName() const;
	// Return a snapshot rather than exposing the mutable collector state.
	HostResource getHostResource();
	pid_t getPid();

	void dump(const HostResource &resources);

	nlohmann::json AsJson();

private:
	const std::chrono::system_clock::time_point m_appmeshStartTime;
};

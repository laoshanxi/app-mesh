#pragma once

#include <chrono>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#if !defined(WIN32)
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
	HostResource() : m_cores(0), m_sockets(0), m_processors(0), m_total_bytes(0), m_free_bytes(0), m_totalSwap_bytes(0), m_freeSwap_bytes(0) {}

	// CPU
	std::size_t m_cores;
	std::size_t m_sockets;
	std::size_t m_processors;
	// MEM
	uint64_t m_total_bytes;
	uint64_t m_free_bytes;
	uint64_t m_totalSwap_bytes;
	uint64_t m_freeSwap_bytes;
	// TODO: disk

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
	virtual ~ResourceCollection();
	// Internal Singleton.
	static std::unique_ptr<ResourceCollection> &instance();

	const std::string getHostName(bool refresh = false);
	const HostResource &getHostResource();
	pid_t getPid();

	void dump();

	nlohmann::json AsJson();

private:
	HostResource m_resources;
	std::recursive_mutex m_mutex;
	const std::chrono::system_clock::time_point m_appmeshStartTime;
};

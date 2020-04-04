#pragma once

#include <mutex>
#include <memory>
#include <string>
#include <list>
#include <unistd.h>
#include <chrono>
#include <cpprest/json.h>

struct HostNetInterface
{
	std::string name;
	bool ipv4;
	std::string address;
};
//////////////////////////////////////////////////////////////////////////
/// Host resource attribute
//////////////////////////////////////////////////////////////////////////
struct HostResource
{
	HostResource() :m_cores(0), m_sockets(0), m_processors(0), m_total_bytes(0), m_free_bytes(0), m_totalSwap_bytes(0), m_freeSwap_bytes(0) {}

	// CPU
	size_t m_cores;
	size_t m_sockets;
	size_t m_processors;
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
	static std::unique_ptr<ResourceCollection>& instance();

	std::string getHostName(bool refresh = false);
	const HostResource& getHostResource();
	const pid_t getPid();

	uint64_t getRssMemory(pid_t pid = getpid());

	void dump();

	web::json::value AsJson();
	web::json::value getConsulJson();

private:
	HostResource m_resources;
	std::recursive_mutex m_mutex;
	const std::chrono::system_clock::time_point m_appmgrStartTime;
};

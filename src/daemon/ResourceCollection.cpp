#include <set>

#include <ace/OS.h>
#include <boost/asio.hpp>

#include "../common/DateTime.h"
#include "../common/Utility.h"
#if !defined(WIN32)
#include "../common/os/net.hpp"
#include "../common/os/pstree.hpp"
#endif
#include "Configuration.h"
#include "ResourceCollection.h"
#include "process/LinuxCgroup.h"

ResourceCollection::ResourceCollection()
	: m_appmeshStartTime(std::chrono::system_clock::now())
{
}

ResourceCollection::~ResourceCollection()
{
}

std::unique_ptr<ResourceCollection> &ResourceCollection::instance()
{
	static auto singleton = std::make_unique<ResourceCollection>();
	return singleton;
}

const std::string ResourceCollection::getHostName(bool refresh)
{
#if defined(WIN32)
	boost::asio::io_context io;
	boost::asio::ip::tcp::resolver resolver(io);
	return boost::asio::ip::host_name();
#else
	return net::hostname();
#endif
}

const HostResource &ResourceCollection::getHostResource()
{
#if !defined(WIN32)
	auto nets = net::getNetworkLinks();
	bool isDocker = Utility::runningInContainer();

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_resources.m_ipaddress.clear();

	// CPU
	if (isDocker)
	{
		static auto cpus = LinuxCgroup(0, 0, 100).readHostCpuSet();
		m_resources.m_cores = m_resources.m_sockets = m_resources.m_processors = cpus;
	}
	if (m_resources.m_cores == 0)
	{
		// Get CPU topology information
		static auto cpus = os::cpus();
		std::set<unsigned int> uniqueSockets;
		std::set<unsigned int> uniqueCores;

		// Count unique cores and sockets
		for (const auto &cpu : cpus)
		{
			uniqueSockets.insert(cpu.socket);
			// Create a unique core identifier combining socket and core ID
			// to handle same core IDs across different sockets
			uniqueCores.insert((cpu.socket << 16) | cpu.core);
		}

		m_resources.m_processors = cpus.size();		  // Total logical processors
		m_resources.m_cores = uniqueCores.size();	  // Total physical cores
		m_resources.m_sockets = uniqueSockets.size(); // Total physical CPUs
	}

	// Memory
	if (isDocker)
	{
		static LinuxCgroup cgroup(0, 0, 100);
		static auto limit_in_bytes = cgroup.readHostMemValue("memory.limit_in_bytes");
		m_resources.m_total_bytes = limit_in_bytes;
		m_resources.m_free_bytes = m_resources.m_total_bytes - cgroup.readHostMemValue("memory.usage_in_bytes");

		if (cgroup.swapSupport())
		{
			static auto memsw_limit_in_bytes = cgroup.readHostMemValue("memory.memsw.limit_in_bytes");
			m_resources.m_totalSwap_bytes = memsw_limit_in_bytes;
			m_resources.m_freeSwap_bytes = m_resources.m_totalSwap_bytes - cgroup.readHostMemValue("memory.memsw.usage_in_bytes");
		}
	}
	if (m_resources.m_total_bytes <= 0 || m_resources.m_total_bytes >= 9223372036854771712L)
	{
		auto mem = os::memory();
		if (mem != nullptr)
		{
			m_resources.m_total_bytes = mem->total_bytes;
			m_resources.m_free_bytes = mem->free_bytes;

			m_resources.m_totalSwap_bytes = mem->totalSwap_bytes;
			m_resources.m_freeSwap_bytes = mem->freeSwap_bytes;
		}
		else
		{
			m_resources.m_total_bytes = m_resources.m_totalSwap_bytes = m_resources.m_free_bytes = m_resources.m_freeSwap_bytes = 0;
		}
	}

	// Net
	for (auto &net : nets)
	{
		// do not need show lo
		if (net.address != "127.0.0.1" && net.name != "lo" && net.address != "::1")
		{
			HostNetInterface inet;
			inet.address = net.address;
			inet.ipv6 = net.ipv6;
			inet.name = net.name;
			m_resources.m_ipaddress.push_back(std::move(inet));
		}
	}
#endif
	return m_resources;
}

pid_t ResourceCollection::getPid()
{
	static auto pid = getpid();
	return pid;
}

void ResourceCollection::dump()
{
	const static char fname[] = "ResourceCollection::dump() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);

	LOG_DBG << fname << "host_name:" << getHostName();
#if !defined(WIN32)
	LOG_DBG << fname << "os_user:" << Utility::getUsernameByUid();
#endif
	for (auto &pair : m_resources.m_ipaddress)
	{
		LOG_DBG << fname << "m_ipaddress: " << pair.name << "," << pair.ipv6 << "," << pair.address;
	}
	LOG_DBG << fname << "m_cores:" << m_resources.m_cores;
	LOG_DBG << fname << "m_sockets:" << m_resources.m_sockets;
	LOG_DBG << fname << "m_processors:" << m_resources.m_processors;
	LOG_DBG << fname << "m_total_bytes:" << m_resources.m_total_bytes;
	LOG_DBG << fname << "m_free_bytes:" << m_resources.m_free_bytes;
	LOG_DBG << fname << "m_totalSwap_bytes:" << m_resources.m_totalSwap_bytes;
	LOG_DBG << fname << "m_freeSwap_bytes:" << m_resources.m_freeSwap_bytes;
}

nlohmann::json ResourceCollection::AsJson()
{
	const static char fname[] = "ResourceCollection::AsJson() ";
	LOG_DBG << fname << "Entered";

	const auto &res = this->getHostResource();
	std::lock_guard<std::recursive_mutex> guard(m_mutex);

	nlohmann::json result = nlohmann::json::object();
	result[("host_name")] = std::string((getHostName()));
	result[("host_description")] = std::string(Configuration::instance()->getDescription());
#if !defined(WIN32)
	static const auto osUser = Utility::getUsernameByUid();
	result[("os_user")] = osUser;
	auto arr = nlohmann::json::array();
	std::for_each(res.m_ipaddress.begin(), res.m_ipaddress.end(), [&arr](const HostNetInterface &pair)
				  {
					  nlohmann::json net_detail = nlohmann::json::object();
					  net_detail["name"] = std::string(pair.name);
					  net_detail["ipv6"] = (pair.ipv6);
					  net_detail["address"] = std::string(pair.address);
					  arr.push_back(net_detail); });
	result[("net")] = std::move(arr);
	result[("cpu_cores")] = (res.m_cores);
	result[("cpu_sockets")] = (res.m_sockets);
	result[("cpu_processors")] = (res.m_processors);
	result[("mem_total_bytes")] = (res.m_total_bytes);
	result[("mem_free_bytes")] = (res.m_free_bytes);
	result[("mem_totalSwap_bytes")] = (res.m_totalSwap_bytes);
	result[("mem_freeSwap_bytes")] = (res.m_freeSwap_bytes);
	auto allAppMem = os::pstree();
	if (nullptr != allAppMem)
	{
		result[("mem_applications")] = (allAppMem->totalRssMemBytes());
	}
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
	// FS
	auto mountPoints = os::getMountPoints();
	auto fsArr = nlohmann::json::array();
	std::for_each(mountPoints.begin(), mountPoints.end(), [&fsArr](const std::pair<std::string, std::string> &pair)
				  {
					  auto usage = os::df(pair.first);
					  if (usage != nullptr)
					  {
						  nlohmann::json fs = nlohmann::json::object();
						  fs["size"] = (usage->totalSize);
						  fs["used"] = (usage->usedSize);
						  fs["usage"] = (usage->usagePercentage);
						  fs["device"] = std::string(pair.second);
						  fs["mount_point"] = std::string(pair.first);
						  fsArr.push_back(fs);
					  } });

	result[("fs")] = std::move(fsArr);
	result[("systime")] = std::string(DateTime::formatLocalTime(std::chrono::system_clock::now()));
	result[("appmesh_start_time")] = std::string(DateTime::formatLocalTime(m_appmeshStartTime));
	result[("pid")] = (getPid());
	result[("home")] = (Utility::getHomeDir());
	result[("fd")] = (os::pstree()->totalFileDescriptors());
#endif
	LOG_DBG << fname << "Exit";
	return result;
}

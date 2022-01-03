#include <set>

#include <ace/OS.h>

#include "../common/DateTime.h"
#include "../common/Utility.h"
#include "../common/os/net.hpp"
#include "../common/os/pstree.hpp"
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
	static std::string hostname;
	if (hostname.empty() || refresh)
	{
		hostname = net::hostname();
	}
	return hostname;
}

const HostResource &ResourceCollection::getHostResource()
{

	auto nets = net::links();
	bool isDocker = LinuxCgroup::runningInContainer();

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
		static auto cpus = os::cpus();
		std::set<int> sockets;
		std::set<int> processers;
		for (auto c : cpus)
		{
			sockets.insert(c.socket);
			processers.insert(c.id);
		}
		m_resources.m_cores = cpus.size();
		m_resources.m_sockets = sockets.size();
		m_resources.m_processors = processers.size();
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
	for (auto net : nets)
	{
		// do not need show lo
		if (net.address != "127.0.0.1" && net.name != "lo" && net.address != "::1")
		{
			HostNetInterface inet;
			inet.address = net.address;
			inet.ipv4 = net.ipv4;
			inet.name = net.name;
			m_resources.m_ipaddress.push_back(inet);
		}
	}

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
	LOG_DBG << fname << "os_user:" << Utility::getOsUserName();
	for (auto &pair : m_resources.m_ipaddress)
	{
		LOG_DBG << fname << "m_ipaddress: " << pair.name << "," << pair.ipv4 << "," << pair.address;
	}
	LOG_DBG << fname << "m_cores:" << m_resources.m_cores;
	LOG_DBG << fname << "m_sockets:" << m_resources.m_sockets;
	LOG_DBG << fname << "m_processors:" << m_resources.m_processors;
	LOG_DBG << fname << "m_total_bytes:" << m_resources.m_total_bytes;
	LOG_DBG << fname << "m_free_bytes:" << m_resources.m_free_bytes;
	LOG_DBG << fname << "m_totalSwap_bytes:" << m_resources.m_totalSwap_bytes;
	LOG_DBG << fname << "m_freeSwap_bytes:" << m_resources.m_freeSwap_bytes;
}

web::json::value ResourceCollection::AsJson()
{
	const static char fname[] = "ResourceCollection::AsJson() ";
	LOG_DBG << fname << "Entered";

	this->getHostResource();
	std::lock_guard<std::recursive_mutex> guard(m_mutex);

	web::json::value result = web::json::value::object();
	result[GET_STRING_T("host_name")] = web::json::value::string(GET_STRING_T(getHostName()));
	result[GET_STRING_T("os_user")] = web::json::value::string(GET_STRING_T(Utility::getOsUserName()));
	result[GET_STRING_T("host_description")] = web::json::value::string(Configuration::instance()->getDescription());
	auto arr = web::json::value::array(m_resources.m_ipaddress.size());
	int idx = 0;
	std::for_each(m_resources.m_ipaddress.begin(), m_resources.m_ipaddress.end(), [&arr, &idx](const HostNetInterface &pair)
				  {
					  web::json::value net_detail = web::json::value::object();
					  net_detail["name"] = web::json::value::string(pair.name);
					  net_detail["ipv4"] = web::json::value::boolean(pair.ipv4);
					  net_detail["address"] = web::json::value::string(pair.address);
					  arr[idx++] = net_detail;
				  });
	result[GET_STRING_T("net")] = arr;
	result[GET_STRING_T("cpu_cores")] = web::json::value::number(m_resources.m_cores);
	result[GET_STRING_T("cpu_sockets")] = web::json::value::number(m_resources.m_sockets);
	result[GET_STRING_T("cpu_processors")] = web::json::value::number(m_resources.m_processors);
	result[GET_STRING_T("mem_total_bytes")] = web::json::value::number(m_resources.m_total_bytes);
	result[GET_STRING_T("mem_free_bytes")] = web::json::value::number(m_resources.m_free_bytes);
	result[GET_STRING_T("mem_totalSwap_bytes")] = web::json::value::number(m_resources.m_totalSwap_bytes);
	result[GET_STRING_T("mem_freeSwap_bytes")] = web::json::value::number(m_resources.m_freeSwap_bytes);
	auto allAppMem = os::pstree();
	if (nullptr != allAppMem)
	{
		result[GET_STRING_T("mem_applications")] = web::json::value::number(allAppMem->totalRssMemBytes());
	}
	// Load
	auto load = os::loadavg();
	if (load != nullptr)
	{
		web::json::value sysLoad = web::json::value::object();
		sysLoad["1min"] = web::json::value::number(load->one);
		sysLoad["5min"] = web::json::value::number(load->five);
		sysLoad["15min"] = web::json::value::number(load->fifteen);
		result[GET_STRING_T("load")] = sysLoad;
	}
	// FS
	auto mountPoints = os::getMoundPoints();
	auto fsArr = web::json::value::array(mountPoints.size());
	idx = 0;
	std::for_each(mountPoints.begin(), mountPoints.end(), [&fsArr, &idx](const std::pair<std::string, std::string> &pair)
				  {
					  auto usage = os::df(pair.first);
					  if (usage != nullptr)
					  {
						  web::json::value fs = web::json::value::object();
						  fs["size"] = web::json::value::number(usage->size);
						  fs["used"] = web::json::value::number(usage->used);
						  fs["usage"] = web::json::value::number(usage->usage);
						  fs["device"] = web::json::value::string(pair.second);
						  fs["mount_point"] = web::json::value::string(pair.first);
						  fsArr[idx++] = fs;
					  }
				  });

	result[GET_STRING_T("fs")] = fsArr;
	result[GET_STRING_T("systime")] = web::json::value::string(DateTime::formatLocalTime(std::chrono::system_clock::now()));
	result[GET_STRING_T("appmesh_start_time")] = web::json::value::string(DateTime::formatLocalTime(m_appmeshStartTime));
	result[GET_STRING_T("pid")] = web::json::value::number(getPid());
	result[GET_STRING_T("fd")] = web::json::value::number(os::fileDescriptors());
	LOG_DBG << fname << "Exit";
	return result;
}

web::json::value ResourceCollection::getConsulJson()
{
	static auto cpus = os::cpus();
	auto mem = os::memory();

	web::json::value result = web::json::value::object();
	result[GET_STRING_T("cpu_cores")] = web::json::value::number(cpus.size());
	result[GET_STRING_T("mem_total_bytes")] = web::json::value::number(mem->total_bytes);
	//result[GET_STRING_T("mem_free_bytes")] = web::json::value::number(mem->free_bytes);
	//result[GET_STRING_T("mem_totalSwap_bytes")] = web::json::value::number(mem->totalSwap_bytes);
	//result[GET_STRING_T("mem_freeSwap_bytes")] = web::json::value::number(mem->freeSwap_bytes);

	return result;
}

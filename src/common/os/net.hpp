#pragma once

#include <ifaddrs.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include <list>
#include <string>

#include <ace/OS.h>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include "../../common/Utility.h"

namespace net
{

	struct NetInterface
	{
		std::string name;
		bool ipv4;
		std::string address;
	};

	inline struct addrinfo createAddrInfo(int socktype, int family, int flags)
	{
		struct addrinfo addr;
		memset(&addr, 0, sizeof(addr));
		addr.ai_socktype = socktype;
		addr.ai_family = family;
		addr.ai_flags |= flags;

		return addr;
	}

	// Returns a Try of the IP for the provided hostname or an error if no IP is
	// obtained.
	inline std::shared_ptr<sockaddr> getIP(const std::string &hostname, int family = AF_UNSPEC)
	{
		const static char fname[] = "net::getIP() ";

		struct addrinfo hints = createAddrInfo(SOCK_STREAM, family, 0);
		struct addrinfo *result = nullptr;

		int error = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);

		if (error != 0)
		{
			LOG_ERR << fname << "getaddrinfo failed with error :" << std::strerror(errno);
			return nullptr;
		}

		if (result->ai_addr == nullptr)
		{
			freeaddrinfo(result);
			LOG_WAR << fname << "No addresses found";
			return nullptr;
		}

		auto ip = std::make_shared<sockaddr>(*result->ai_addr);

		freeaddrinfo(result);
		return ip;
	}

	/**
	 * Get hostname with FQDN
	 * https://stackoverflow.com/questions/504810/how-do-i-find-the-current-machines-full-hostname-in-c-hostname-and-domain-info
	 * @return {std::string}  : 
	 */
	inline std::string hostname()
	{
		const static char fname[] = "net::hostname() ";
		char host[512];
		std::string hostname;

		if (gethostname(host, sizeof(host)) < 0)
		{
			LOG_WAR << fname << "Failed to call gethostname()";
		}

		struct addrinfo hints = createAddrInfo(SOCK_STREAM, AF_UNSPEC, AI_CANONNAME);
		struct addrinfo *result = nullptr;

		int error = getaddrinfo(host, nullptr, &hints, &result);
		if (error != 0)
		{
			LOG_ERR << fname << Utility::stringFormat("getaddrinfo() failed with error: %s", gai_strerror(error));
			hostname = host;
		}
		else
		{
			hostname = result->ai_canonname;
		}
		if (result)
		{
			freeaddrinfo(result);
		}

		return hostname;
	}

	inline std::string getAddressStr(const struct sockaddr *storage)
	{
		const static char fname[] = "net::getAddressStr() ";

		char buffer[NI_MAXHOST] = {0};
		socklen_t length;

		if (storage->sa_family == AF_INET)
		{
			length = sizeof(struct sockaddr_in);
		}
		else if (storage->sa_family == AF_INET6)
		{
			length = sizeof(struct sockaddr_in6);
		}
		else
		{
			LOG_WAR << fname << "Unsupported family :" << storage->sa_family;
			return "";
		}

		int error = getnameinfo(storage, length, buffer, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

		if (error != 0)
		{
			LOG_ERR << fname << "getnameinfo failed, error :" << std::strerror(errno);
			return "";
		}

		// remove % from ipv6 address (fe80::bacd:a28c:186c:a9cd%enp0s3)
		if (storage->sa_family == AF_INET6 && strchr(buffer, '%') > (char *)NULL)
		{
			*(strchr(buffer, '%')) = '\0';
		}

		return std::string(buffer);
	}

	inline std::set<std::string> virtLinks()
	{
		const static char fname[] = "net::virtLinks() ";

		std::set<std::string> result;
		const fs::path virtNetDir("/sys/devices/virtual/net/");
		const boost::filesystem::directory_iterator itEnd;
		if (fs::exists(virtNetDir) && ACE_OS::access(virtNetDir.c_str(), R_OK) == 0)
		{
			for (boost::filesystem::directory_iterator it(virtNetDir); it != itEnd; it++)
			{
				if (fs::is_directory(*it))
				{
					auto deviceName = it->path().leaf().c_str();
					result.insert(deviceName);
					LOG_DBG << fname << "virtual network device :" << deviceName;
				}
			}
		}
		return result;
	}

	// Returns the names of all the link devices in the system.
	inline std::list<NetInterface> links()
	{
		const static char fname[] = "net::links() ";

		struct ifaddrs *ifaddr = nullptr;
		if (getifaddrs(&ifaddr) == -1)
		{
			LOG_ERR << fname << "getifaddrs failed, error :" << std::strerror(errno);
			return std::list<NetInterface>();
		}

		auto virtDevices = virtLinks();
		std::list<NetInterface> names;
		for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_name != nullptr && (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) && virtDevices.count(ifa->ifa_name) == 0)
			{
				NetInterface mi;
				mi.name = ifa->ifa_name;
				mi.ipv4 = (AF_INET == ifa->ifa_addr->sa_family);
				mi.address = getAddressStr(ifa->ifa_addr);
				names.push_back(mi);
			}
		}

		freeifaddrs(ifaddr);
		return names;
	}

} // namespace net

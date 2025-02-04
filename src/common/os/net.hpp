#pragma once

#include <atomic>
#include <cerrno>		// for errno
#include <cstring>		// for strerror
#include <ifaddrs.h>	// for getifaddrs
#include <list>			// for std::list
#include <memory>		// for unique_ptr
#include <netinet/in.h> // for internet operations
#include <set>			// for std::set
#include <string>		// for string operations

#include <ace/OS.h>
#include <boost/asio.hpp>

#include "../../common/Utility.h"

namespace net
{
	/**
	 * @struct NetworkInterfaceInfo
	 * @brief Represents a network interface with its properties
	 */
	struct NetworkInterfaceInfo
	{
		std::string name;	 ///< Name of the network interface
		bool ipv6;			 ///< True if IPv6, false if IPv4
		std::string address; ///< IP address as string
	};

	/**
	 * @brief Gets the Fully Qualified Domain Name (FQDN) of the host
	 * @return Host's FQDN, or short hostname if FQDN lookup fails
	 */
	inline std::string hostname()
	{
		static const auto hostname = []() -> std::string
		{
			const auto shortHostname = boost::asio::ip::host_name();
			try
			{
				boost::asio::io_context io_context;
				boost::asio::ip::tcp::resolver resolver(io_context);

				// Try to resolve FQDN
				try
				{
					auto results = resolver.resolve(shortHostname, "");
					for (const auto &entry : results)
					{
						const auto &fqdn = entry.host_name();
						if (!fqdn.empty())
						{
							return fqdn;
						}
					}
				}
				catch (const boost::system::system_error &e)
				{
					// Log and fall back to short hostname
					LOG_WAR << "FQDN resolution failed: " << e.what();
				}
			}
			catch (const std::exception &e)
			{
				LOG_ERR << "Failed to retrieve hostname: " << e.what();
			}
			// Fall back to short hostname
			return shortHostname;
		}();

		return hostname;
	}

	/**
	 * @brief Converts a sockaddr structure to a string representation of the address
	 *
	 * @param storage Pointer to sockaddr structure containing the address
	 * @return String representation of the address, empty string on error
	 */
	inline std::string sockaddrToString(const struct sockaddr *storage)
	{
		static const char fname[] = "net::sockaddrToString() ";

		if (!storage)
		{
			LOG_ERR << fname << "Null address storage provided";
			return std::string();
		}

		socklen_t length;
		switch (storage->sa_family)
		{
		case AF_INET:
			length = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			length = sizeof(struct sockaddr_in6);
			break;
		default:
			LOG_WAR << fname << "Unsupported address family: " << storage->sa_family;
			return std::string();
		}

		std::unique_ptr<char[]> buffer(new char[NI_MAXHOST]());
		int error = getnameinfo(storage, length, buffer.get(), NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);

		if (error != 0)
		{
			LOG_ERR << fname << "getnameinfo failed: " << (error == EAI_SYSTEM ? std::strerror(errno) : gai_strerror(error));
			return std::string();
		}

		std::string result(buffer.get());
		if (storage->sa_family == AF_INET6)
		{
			size_t percent_pos = result.find('%');
			if (percent_pos != std::string::npos)
			{
				result.erase(percent_pos);
			}
		}

		return result;
	}

	/**
	 * @brief Returns the names of all virtual network devices
	 * @return Set of virtual network device names
	 */
	inline std::set<std::string> getVirtualNetworkDevices()
	{
		static const char fname[] = "net::getVirtualNetworkDevices() ";
		std::set<std::string> result;

#ifdef __linux__
		static const char virtNetPath[] = "/sys/devices/virtual/net/";

		if (!fs::exists(virtNetPath))
		{
			LOG_WAR << fname << "Virtual network directory does not exist: " << virtNetPath;
			return result;
		}

		if (ACE_OS::access(virtNetPath, R_OK) != 0)
		{
			LOG_ERR << fname << "No read permission for directory: " << virtNetPath << " (errno=" << errno << ": " << std::strerror(errno) << ")";
			return result;
		}

		try
		{
			for (const auto &entry : fs::directory_iterator(virtNetPath))
			{
				if (!fs::is_directory(entry))
				{
					continue;
				}

				std::string deviceName = entry.path().filename().string();
				result.insert(deviceName);
				LOG_DBG << fname << "Found virtual network device: " << deviceName;
			}
		}
		catch (const fs::filesystem_error &ex)
		{
			LOG_ERR << fname << "Filesystem error while reading " << virtNetPath << ": " << ex.what();
			return result;
		}
#elif defined(__APPLE__)
		try
		{
			struct ifaddrs *ifaddr, *ifa;

			if (getifaddrs(&ifaddr) == -1)
			{
				LOG_ERR << fname << "Failed to get interface addresses (errno="
						<< errno << ": " << std::strerror(errno) << ")";
				return result;
			}

			// Ensure cleanup of ifaddr
			std::unique_ptr<struct ifaddrs, decltype(&freeifaddrs)>
				ifaddr_guard(ifaddr, freeifaddrs);

			// Iterate through all interfaces
			for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
			{
				if (ifa->ifa_name == nullptr)
					continue;

				std::string interface(ifa->ifa_name);

				// Check if it's a virtual interface
				if (Utility::startWith(interface, "lo") ||
					Utility::startWith(interface, "bridge") ||
					Utility::startWith(interface, "tun") ||
					Utility::startWith(interface, "tap") ||
					Utility::startWith(interface, "utun") ||
					Utility::startWith(interface, "gif") ||
					Utility::startWith(interface, "stf") ||
					Utility::startWith(interface, "vlan"))
				{
					result.insert(interface);
					LOG_DBG << fname << "Found virtual network device: " << interface;
				}
			}
		}
		catch (const std::exception &ex)
		{
			LOG_ERR << fname << "Unexpected error: " << ex.what();
			return result;
		}
#else
#error "Unsupported platform"
#endif

		if (result.empty())
		{
			LOG_DBG << fname << "No virtual network devices found";
		}
		else
		{
			LOG_DBG << fname << "Found " << result.size() << " virtual network device(s)";
		}

		return result;
	}

	/**
	 * @brief Retrieves the network link devices (excluding virtual ones) in the system
	 * @return A list of NetworkInterfaceInfo  objects representing the system's network devices
	 */
	inline std::list<NetworkInterfaceInfo> getNetworkLinks()
	{
		static const char fname[] = "net::getNetworkLinks() ";
		std::list<NetworkInterfaceInfo> interfaces;

		struct ifaddrs *ifaddr = nullptr;
		if (getifaddrs(&ifaddr) == -1)
		{
			LOG_ERR << fname << "getifaddrs failed, error: " << std::strerror(errno);
			return interfaces;
		}

		std::unique_ptr<struct ifaddrs, decltype(&freeifaddrs)> ifaddr_guard(ifaddr, freeifaddrs);

		std::set<std::string> virtDevices = getVirtualNetworkDevices();

		for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
		{
			if (!ifa->ifa_name || !ifa->ifa_addr)
			{
				continue;
			}

			if ((ifa->ifa_addr->sa_family == AF_INET ||
				 ifa->ifa_addr->sa_family == AF_INET6) &&
				virtDevices.count(ifa->ifa_name) == 0)
			{

				NetworkInterfaceInfo interface;
				interface.name = ifa->ifa_name;
				interface.ipv6 = (AF_INET6 == ifa->ifa_addr->sa_family);
				interface.address = sockaddrToString(ifa->ifa_addr);
				interfaces.push_back(std::move(interface));
			}
		}

		return interfaces;
	}

} // namespace net
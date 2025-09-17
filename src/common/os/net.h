#pragma once

#include <list>
#include <memory>
#include <set>
#include <string>

namespace net
{
	// Network interface with its properties
	struct NetworkInterfaceInfo
	{
		std::string name;	 ///< Name of the network interface (ifname on POSIX, FriendlyName on Windows)
		bool ipv6;			 ///< True if IPv6, false if IPv4
		std::string address; ///< IP address as string (numeric form)
	};

	// Fully Qualified Domain Name (FQDN) of the host
	std::string hostname();

	// Converts a sockaddr structure to a string
	std::string sockaddrToString(const struct sockaddr *storage);

	// Get all virtual network devices name in the system
	std::set<std::string> getVirtualNetworkDevices();

	// Retrieves the network link devices in the system
	std::list<NetworkInterfaceInfo> getNetworkLinks();

} // namespace net

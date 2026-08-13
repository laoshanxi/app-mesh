// src/common/os/net.h
#pragma once

#include <list>
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

	// Retrieves active physical and virtual network interfaces, excluding loopback.
	std::list<NetworkInterfaceInfo> getNetworkLinks();

} // namespace net

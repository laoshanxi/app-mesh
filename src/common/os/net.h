#pragma once

#include <list>
#include <memory>
#include <set>
#include <string>

namespace net
{
	/**
	 * @struct NetworkInterfaceInfo
	 * @brief Represents a network interface with its properties
	 */
	struct NetworkInterfaceInfo
	{
		std::string name;	 ///< Name of the network interface (ifname on POSIX, FriendlyName on Windows)
		bool ipv6;			 ///< True if IPv6, false if IPv4
		std::string address; ///< IP address as string (numeric form)
	};

	/**
	 * @brief Gets the Fully Qualified Domain Name (FQDN) of the host
	 * @return Host's FQDN, or short hostname if FQDN lookup fails
	 */
	std::string hostname();

	/**
	 * @brief Converts a sockaddr structure to a string representation of the address
	 *
	 * @param storage Pointer to sockaddr structure containing the address
	 * @return String representation of the address, empty string on error
	 */
	std::string sockaddrToString(const struct sockaddr *storage);

	/**
	 * @brief Returns the names of all virtual network devices
	 * @return Set of virtual network device names
	 */
	std::set<std::string> getVirtualNetworkDevices();

	/**
	 * @brief Retrieves the network link devices (excluding virtual ones) in the system
	 * @return A list of NetworkInterfaceInfo objects representing the system's network devices
	 */
	std::list<NetworkInterfaceInfo> getNetworkLinks();

} // namespace net
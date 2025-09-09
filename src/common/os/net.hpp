#pragma once

// Common C++/POSIX
#include <cerrno>  // errno
#include <cstring> // strerror, strcmp
#include <list>	   // std::list
#include <memory>  // std::unique_ptr
#include <set>	   // std::set
#include <string>  // std::string
#include <utility> // std::move

// Sockets & name resolution
#ifdef __APPLE__
#include <arpa/inet.h>
#include <ifaddrs.h> // getifaddrs on macOS
#include <netinet/in.h>
#include <sys/socket.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#include <ifaddrs.h> // getifaddrs on Linux
#include <netinet/in.h>
#include <sys/socket.h>
#elif defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <iphlpapi.h> // GetAdaptersAddresses
#include <winsock2.h>
#include <ws2tcpip.h> // getnameinfo, NI_MAXHOST
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
// POSIX-like defines used in code paths
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#else
#error "Unsupported platform"
#endif

#include <boost/asio.hpp>

#include "../../common/Utility.h"

namespace net
{

// -----------------------------
// Windows-only helpers
// -----------------------------
#if defined(_WIN32)

	// Minimal, safe Winsock initializer that runs once and never calls WSACleanup()
	// to avoid teardown races at shutdown.
	struct WinsockOnce
	{
		WinsockOnce()
		{
			WSADATA wsa{};
			const int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
			if (rc != 0)
			{
				// We only log; continuing allows callers to fail gracefully.
				LOG_ERR << "WSAStartup failed: " << rc;
			}
		}
		WinsockOnce(const WinsockOnce &) = delete;
		WinsockOnce &operator=(const WinsockOnce &) = delete;
	};
	inline void ensure_winsock()
	{
		static WinsockOnce once;
		(void)once;
	}

	// Convert UTF-16 (Windows wide) to UTF-8
	inline std::string wideToUtf8(const wchar_t *w)
	{
		if (!w)
			return {};
		int needed = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
		if (needed <= 0)
			return {};
		std::string out(static_cast<size_t>(needed - 1), '\0');
		::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), needed, nullptr, nullptr);
		return out;
	}

	inline bool starts_with_icase(const std::string &s, const char *prefix)
	{
		const size_t n = std::strlen(prefix);
		if (s.size() < n)
			return false;
		for (size_t i = 0; i < n; ++i)
		{
			char a = s[i];
			char b = prefix[i];
			if ('A' <= a && a <= 'Z')
				a = char(a - 'A' + 'a');
			if ('A' <= b && b <= 'Z')
				b = char(b - 'A' + 'a');
			if (a != b)
				return false;
		}
		return true;
	}

	inline bool is_virtual_adapter_win(const IP_ADAPTER_ADDRESSES *a)
	{
		if (!a)
			return false;

		// Filter by interface type first
		switch (a->IfType)
		{
		case IF_TYPE_SOFTWARE_LOOPBACK:
			return true;
		case IF_TYPE_TUNNEL:
			return true;
		// Many virtual adapters also report as ETHERNET_CSMACD (6) or OTHER (1),
		// so we additionally heuristic-match common virtual names below.
		default:
			break;
		}

		// Heuristic check on names commonly used by virtual adapters
		const std::string friendly = wideToUtf8(a->FriendlyName);
		if (friendly.empty())
			return false;

		static const char *kVirtualPrefixes[] = {
			"vEthernet",	  // Hyper-V
			"Hyper-V",		  // Hyper-V
			"Virtual",		  // Generic virtual
			"TAP", "TUN",	  // TAP/TUN
			"Npcap Loopback", // Npcap
			"Loopback",		  // Loopback
			"VMware",		  // VMware
			"VirtualBox",	  // VirtualBox
			"WSL",			  // WSL virtual adapters
			"Docker",		  // Docker virtual NICs
		};
		for (auto *p : kVirtualPrefixes)
		{
			if (starts_with_icase(friendly, p))
				return true;
		}
		return false;
	}

#endif // _WIN32

	// -----------------------------
	// Types
	// -----------------------------

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

	// -----------------------------
	// API
	// -----------------------------

	/**
	 * @brief Gets the Fully Qualified Domain Name (FQDN) of the host
	 * @return Host's FQDN, or short hostname if FQDN lookup fails
	 */
	inline std::string hostname()
	{
		static const auto cached = []() -> std::string
		{
			const auto shortHostname = boost::asio::ip::host_name();
			try
			{
				boost::asio::io_context io;
				boost::asio::ip::tcp::resolver r(io);

				// Try to resolve FQDN
				try
				{
					auto results = r.resolve(shortHostname, "");
					for (const auto &entry : results)
					{
						const auto &fq = entry.host_name();
						if (!fq.empty())
							return fq;
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
		return cached;
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
			return {};
		}

#if defined(_WIN32)
		ensure_winsock();
#endif

		socklen_t length = 0;
		switch (storage->sa_family)
		{
		case AF_INET:
			length = static_cast<socklen_t>(sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			length = static_cast<socklen_t>(sizeof(struct sockaddr_in6));
			break;
		default:
			LOG_WAR << fname << "Unsupported address family: " << storage->sa_family;
			return {};
		}

		std::unique_ptr<char[]> buffer(new char[NI_MAXHOST]());
		const int rc = ::getnameinfo(storage, length, buffer.get(), NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
		if (rc != 0)
		{
#if defined(_WIN32)
			// On Windows, gai_strerrorA is available via ws2tcpip.h
			LOG_ERR << fname << "getnameinfo failed: " << (rc == EAI_SYSTEM ? ACE_OS::strerror(ACE_OS::last_error()) : gai_strerrorA(rc));
#else
			LOG_ERR << fname << "getnameinfo failed: " << (rc == EAI_SYSTEM ? ACE_OS::strerror(ACE_OS::last_error()) : gai_strerror(rc));
#endif
			return {};
		}

		std::string result(buffer.get());
		if (storage->sa_family == AF_INET6)
		{
			// Strip scope id suffix like "%eth0" / "%12"
			const size_t pos = result.find('%');
			if (pos != std::string::npos)
				result.erase(pos);
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

#if defined(__linux__)
		static const char virtNetPath[] = "/sys/devices/virtual/net/";
		if (!fs::exists(virtNetPath))
		{
			LOG_WAR << fname << "Virtual network directory does not exist: " << virtNetPath;
			return result;
		}
		if (ACE_OS::access(virtNetPath, R_OK) != 0)
		{
			LOG_ERR << fname << "No read permission for directory: " << virtNetPath
					<< " (errno=" << errno << ": " << ACE_OS::strerror(ACE_OS::last_error()) << ")";
			return result;
		}
		try
		{
			for (const auto &entry : fs::directory_iterator(virtNetPath))
			{
				if (!fs::is_directory(entry))
					continue;
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
			struct ifaddrs *ifaddr = nullptr;
			if (getifaddrs(&ifaddr) == -1)
			{
				LOG_ERR << fname << "Failed to get interface addresses (errno=" << errno << ": " << ACE_OS::strerror(ACE_OS::last_error()) << ")";
				return result;
			}

			// Ensure cleanup of ifaddr
			std::unique_ptr<struct ifaddrs, decltype(&freeifaddrs)> guard(ifaddr, freeifaddrs);

			// Iterate through all interfaces
			for (auto *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
			{
				if (!ifa->ifa_name)
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

#elif defined(_WIN32)
		ensure_winsock();

		// Use IP Helper API to enumerate adapters and classify virtual ones
		ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
		ULONG family = AF_UNSPEC;

		ULONG size = 16 * 1024;
		std::unique_ptr<BYTE[]> buf(new BYTE[size]);
		IP_ADAPTER_ADDRESSES *aa = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buf.get());

		ULONG rc = ::GetAdaptersAddresses(family, flags, nullptr, aa, &size);
		if (rc == ERROR_BUFFER_OVERFLOW)
		{
			buf.reset(new BYTE[size]);
			aa = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buf.get());
			rc = ::GetAdaptersAddresses(family, flags, nullptr, aa, &size);
		}
		if (rc != NO_ERROR)
		{
			LOG_ERR << fname << "GetAdaptersAddresses failed: " << rc;
			return result;
		}

		for (auto *a = aa; a != nullptr; a = a->Next)
		{
			if (is_virtual_adapter_win(a))
			{
				const std::string friendly = wideToUtf8(a->FriendlyName);
				if (!friendly.empty())
					result.insert(friendly);
			}
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
	 * @return A list of NetworkInterfaceInfo objects representing the system's network devices
	 */
	inline std::list<NetworkInterfaceInfo> getNetworkLinks()
	{
		static const char fname[] = "net::getNetworkLinks() ";

		std::list<NetworkInterfaceInfo> interfaces;

#if defined(__linux__) || defined(__APPLE__)
		struct ifaddrs *ifaddr = nullptr;
		if (getifaddrs(&ifaddr) == -1)
		{
			LOG_ERR << fname << "getifaddrs failed, error: " << ACE_OS::strerror(ACE_OS::last_error());
			return interfaces;
		}
		std::unique_ptr<struct ifaddrs, decltype(&freeifaddrs)> guard(ifaddr, freeifaddrs);

		std::set<std::string> virtDevices = getVirtualNetworkDevices();

		for (auto *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
		{
			if (!ifa->ifa_name || !ifa->ifa_addr)
				continue;

			const int fam = ifa->ifa_addr->sa_family;
			if (fam != AF_INET && fam != AF_INET6)
				continue;

			// Skip virtual interfaces
			if (virtDevices.count(ifa->ifa_name) != 0)
				continue;

			NetworkInterfaceInfo ni;
			ni.name = ifa->ifa_name;
			ni.ipv6 = (fam == AF_INET6);
			ni.address = sockaddrToString(ifa->ifa_addr);
			if (!ni.address.empty())
				interfaces.push_back(std::move(ni));
		}

#elif defined(_WIN32)
		ensure_winsock();

		ULONG flags = GAA_FLAG_INCLUDE_PREFIX; // keep default unicast list
		ULONG family = AF_UNSPEC;

		ULONG size = 16 * 1024;
		std::unique_ptr<BYTE[]> buf(new BYTE[size]);
		IP_ADAPTER_ADDRESSES *aa = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buf.get());

		ULONG rc = ::GetAdaptersAddresses(family, flags, nullptr, aa, &size);
		if (rc == ERROR_BUFFER_OVERFLOW)
		{
			buf.reset(new BYTE[size]);
			aa = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buf.get());
			rc = ::GetAdaptersAddresses(family, flags, nullptr, aa, &size);
		}
		if (rc != NO_ERROR)
		{
			LOG_ERR << fname << "GetAdaptersAddresses failed: " << rc;
			return interfaces;
		}

		// Build set of virtual adapter names for filtering (FriendlyName key)
		std::set<std::string> virtNames = getVirtualNetworkDevices();

		for (auto *a = aa; a != nullptr; a = a->Next)
		{
			// Skip down/disabled adapters
			if (a->OperStatus != IfOperStatusUp)
				continue;

			const std::string name = wideToUtf8(a->FriendlyName);
			if (name.empty())
				continue;

			// Skip loopback & tunnel and any heuristic-virtual names
			if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfType == IF_TYPE_TUNNEL)
				continue;
			if (virtNames.count(name) != 0)
				continue;

			// Enumerate unicast addresses
			for (auto *ua = a->FirstUnicastAddress; ua != nullptr; ua = ua->Next)
			{
				if (!ua->Address.lpSockaddr)
					continue;
				const int fam = ua->Address.lpSockaddr->sa_family;
				if (fam != AF_INET && fam != AF_INET6)
					continue;

				NetworkInterfaceInfo ni;
				ni.name = name;
				ni.ipv6 = (fam == AF_INET6);
				ni.address = sockaddrToString(ua->Address.lpSockaddr);
				if (!ni.address.empty())
					interfaces.push_back(std::move(ni));
			}
		}

#else
#error "Unsupported platform"
#endif

		return interfaces;
	}

} // namespace net

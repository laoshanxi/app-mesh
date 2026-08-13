// src/common/os/net.cpp
#include <cerrno>  // errno
#include <memory>
#include <utility> // std::move

// Sockets & name resolution
#ifdef __APPLE__
#include <arpa/inet.h>
#include <ifaddrs.h> // getifaddrs on macOS
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#include <ifaddrs.h> // getifaddrs on Linux
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#elif defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h> // getnameinfo, NI_MAXHOST

#include <iphlpapi.h> // GetAdaptersAddresses, keep behind ws2tcpip.h
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

#include "../Utility.h"
#include "net.h"

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
			const static char fname[] = "net::WinsockOnce() ";

			WSADATA wsa{};
			const int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
			if (rc != 0)
			{
				// We only log; continuing allows callers to fail gracefully.
				LOG_ERR << fname << "WSAStartup failed with error: " << rc;
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
		std::string out(static_cast<size_t>(needed), '\0');
		const int written = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), needed, nullptr, nullptr);
		if (written <= 0)
			return {};
		out.resize(static_cast<size_t>(written - 1));
		return out;
	}

#endif // _WIN32

	/**
	 * @brief Gets the Fully Qualified Domain Name (FQDN) of the host
	 * @return Host's FQDN, or short hostname if FQDN lookup fails
	 */
	std::string hostname()
	{
		static const auto cached = []() -> std::string
		{
			const static char fname[] = "net::hostname() ";

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
					LOG_WAR << fname << "FQDN resolution failed for host <" << shortHostname << ">: " << e.what();
				}
			}
			catch (const std::exception &e)
			{
				LOG_WAR << fname << "Unexpected error resolving FQDN for host <" << shortHostname << ">, falling back to short hostname: " << e.what();
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
	std::string sockaddrToString(const struct sockaddr *storage)
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
			LOG_ERR << fname << "getnameinfo failed: " << (rc == EAI_SYSTEM ? last_error_msg() : gai_strerrorA(rc));
#else
			LOG_ERR << fname << "getnameinfo failed: " << (rc == EAI_SYSTEM ? last_error_msg() : gai_strerror(rc));
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
	 * @brief Retrieves the network link devices in the system
	 * @return A list of NetworkInterfaceInfo objects representing the system's network devices
	 */
	std::list<NetworkInterfaceInfo> getNetworkLinks()
	{
		static const char fname[] = "net::getNetworkLinks() ";

		std::list<NetworkInterfaceInfo> interfaces;

#if defined(__linux__) || defined(__APPLE__)
		struct ifaddrs *ifaddr = nullptr;
		if (getifaddrs(&ifaddr) == -1)
		{
			LOG_ERR << fname << "getifaddrs failed, error: " << last_error_msg();
			return interfaces;
		}
		std::unique_ptr<struct ifaddrs, decltype(&freeifaddrs)> guard(ifaddr, freeifaddrs);

		for (auto *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
		{
			if (!ifa->ifa_name || !ifa->ifa_addr)
				continue;
			if ((ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_LOOPBACK) != 0)
				continue;

			const int fam = ifa->ifa_addr->sa_family;
			if (fam != AF_INET && fam != AF_INET6)
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

		for (auto *a = aa; a != nullptr; a = a->Next)
		{
			// Skip down/disabled adapters
			if (a->OperStatus != IfOperStatusUp)
				continue;

			if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
				continue;

			const std::string name = wideToUtf8(a->FriendlyName);
			if (name.empty())
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

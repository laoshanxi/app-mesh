// src/common/os/net.cpp
#include <cerrno>  // errno
#include <chrono>
#include <condition_variable>
#include <exception> // std::exception
#include <memory>
#include <mutex>
#include <thread>
#include <utility> // std::move

// Sockets & name resolution
#include <arpa/inet.h>
#include <ifaddrs.h> // getifaddrs
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <boost/asio.hpp>

#include "../Utility.h"
#include "net.h"

namespace net
{

	/**
	 * @brief Gets the Fully Qualified Domain Name (FQDN) of the host
	 * @return Host's FQDN, or the short hostname while the lookup is pending or has failed
	 */
	std::string hostname()
	{
		const static char fname[] = "net::hostname() ";
		// Industry practice: the OS short hostname identifies the node without
		// DNS; the FQDN is only an enrichment. A stalled resolver (multicast-DNS,
		// an unreachable name server) must not block callers, so the lookup runs
		// once in the background and upgrades the cached value when it settles.
		struct FqdnCache
		{
			std::mutex mutex;
			std::condition_variable settled;
			const std::string shortName = boost::asio::ip::host_name();
			std::string value = shortName;
			bool dispatched = false;
			bool finished = false;
		};
		// Leaked on purpose: the detached lookup thread may still write at shutdown.
		static FqdnCache *const cache = new FqdnCache();

		bool dispatch = false;
		{
			std::lock_guard<std::mutex> lock(cache->mutex);
			if (!cache->dispatched)
			{
				cache->dispatched = true;
				dispatch = true;
			}
		}
		if (dispatch)
		{
			const std::string shortHostname = cache->shortName;
			std::thread(
				[shortHostname]
				{
					std::string fqdn;
					std::string error = "FQDN resolution returned no canonical name";
					try
					{
						boost::asio::io_context io;
						boost::asio::ip::tcp::resolver resolver(io);
						for (const auto &entry : resolver.resolve(shortHostname, ""))
						{
							const auto &fq = entry.host_name();
							if (!fq.empty())
							{
								fqdn = fq;
								error.clear();
								break;
							}
						}
					}
					catch (const std::exception &e)
					{
						error = e.what();
					}
					catch (...)
					{
						error = "unknown exception";
					}

					std::lock_guard<std::mutex> lock(cache->mutex);
					if (fqdn.empty())
						LOG_WAR << fname << "FQDN resolution failed for host <" << shortHostname << ">: " << error;
					else
					{
						cache->value = fqdn;
						LOG_INF << fname << "FQDN resolved to <" << fqdn << ">";
					}
					cache->finished = true;
					cache->settled.notify_all();
				})
				.detach();

			// Give the first caller the FQDN when the resolver answers quickly.
			std::unique_lock<std::mutex> lock(cache->mutex);
			if (!cache->settled.wait_for(lock, std::chrono::seconds(1), [] { return cache->finished; }))
			{
				LOG_WAR << fname << "FQDN resolution for host <" << shortHostname << "> did not complete within 1 second, using the short hostname until the lookup completes";
			}
		}

		std::lock_guard<std::mutex> lock(cache->mutex);
		return cache->value;
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
			LOG_ERR << fname << "getnameinfo failed: " << (rc == EAI_SYSTEM ? last_error_msg() : gai_strerror(rc));
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

		return interfaces;
	}

} // namespace net

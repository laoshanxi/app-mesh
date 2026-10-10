// src/daemon/process/SpawnInitializers.h
#pragma once

#if !defined(_WIN32)

#include <cerrno>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include <boost/system/error_code.hpp>
#include <boost/process/v2/default_launcher.hpp>

/// Child-side identity initializer for the Boost.Process V2 posix launcher.
/// Runs between fork and execve: joins a fresh process group, attaches to the
/// cgroup leaves the parent prepared (writing "0" moves the writer itself),
/// then drops to the target gid/uid. Every call is async-signal-safe (raw
/// open/write/close, no allocation). A failure returns the errno to the
/// launcher, which reports it over the internal error pipe and rejects the
/// spawn while the parent reaps the child.
class PosixProcessIdentity
{
public:
	PosixProcessIdentity(unsigned int uid, unsigned int gid, std::vector<std::string> cgroupProcsPaths)
		: m_uid(uid), m_gid(gid), m_cgroupProcsPaths(std::move(cgroupProcsPaths))
	{
	}

	boost::system::error_code on_exec_setup(boost::process::v2::posix::default_launcher &,
											const boost::process::v2::filesystem::path &,
											const char *const *)
	{
		// New process group so a terminate kills the whole tree.
		if (::setpgid(0, 0) != 0)
			return {errno, boost::system::system_category()};

		// Still root here: the parent created the leaves, the child joins them.
		static const char selfPid[] = "0";
		for (const auto &path : m_cgroupProcsPaths)
		{
			const int fd = ::open(path.c_str(), O_WRONLY);
			if (fd < 0)
				return {errno, boost::system::system_category()};
			const bool written = ::write(fd, selfPid, sizeof(selfPid)) == static_cast<ssize_t>(sizeof(selfPid));
			const int writeErrno = errno;
			::close(fd);
			if (!written)
				return {writeErrno, boost::system::system_category()};
		}

		// Drop privileges last: setgid before setuid, else the group stays.
		if (m_uid != 0)
		{
			if (::setgid(m_gid) != 0 || ::setuid(m_uid) != 0)
				return {errno, boost::system::system_category()};
		}
		return boost::system::error_code();
	}

private:
	const unsigned int m_uid;
	const unsigned int m_gid;
	const std::vector<std::string> m_cgroupProcsPaths;
};

#endif // !_WIN32

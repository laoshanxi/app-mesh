// src/daemon/process/ForkExec.cpp
//
// The daemon's only process-launch primitive. fork() runs daemon code in the
// child, so the child side here is exclusively raw system calls — no library
// calls, no allocation, no logging — between fork and execve (the pattern the
// previous Boost.Process launcher broke by calling asio's notify_fork and
// opendir in the child). The parent learns from the child over a pipe:
// EOF means execve succeeded (the pipe is close-on-exec), an 8-byte report
// means a step failed and carries its errno; silence past the timeout means
// a stuck child, which is killed so a launch can never wedge the daemon.
#if !defined(_WIN32)

#include "ForkExec.h"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

namespace
{
	// Report codes sent over the pipe; the parent maps them to stage names.
	constexpr int32_t STAGE_CHDIR = 1;
	constexpr int32_t STAGE_DUP2 = 2;
	constexpr int32_t STAGE_SETPGID = 3;
	constexpr int32_t STAGE_CGROUP = 4;
	constexpr int32_t STAGE_SETGROUPS = 5;
	constexpr int32_t STAGE_SETGID = 6;
	constexpr int32_t STAGE_SETUID = 7;
	constexpr int32_t STAGE_EXECVE = 8;

	const char *stageName(int stage)
	{
		switch (stage)
		{
		case STAGE_CHDIR:
			return "chdir";
		case STAGE_DUP2:
			return "dup2";
		case STAGE_SETPGID:
			return "setpgid";
		case STAGE_CGROUP:
			return "cgroup";
		case STAGE_SETGROUPS:
			return "setgroups";
		case STAGE_SETGID:
			return "setgid";
		case STAGE_SETUID:
			return "setuid";
		case STAGE_EXECVE:
			return "execve";
		default:
			return "exec";
		}
	}

	struct ChildReport
	{
		int32_t stage;
		int32_t error;
	};

	// The child reports one stage and exits; the write is pipe-atomic.
	[[noreturn]] void failInChild(int32_t stage, int reportFd)
	{
		const int savedErrno = errno;
		const ChildReport report{stage, savedErrno};
		ssize_t written;
		do
		{
			written = ::write(reportFd, &report, sizeof(report));
		} while (written < 0 && errno == EINTR);
		::_exit(127);
	}

	// Descriptors opened by other threads after the parent's scan still take
	// the lowest free slot, so the scanned highest value plus this margin
	// bounds the table the child has to sweep on systems without close_range.
	constexpr int FD_SCAN_MARGIN = 128;

	int closeSweepLimit()
	{
		DIR *dir = ::opendir("/dev/fd");
		if (!dir)
			return getdtablesize() - 1; // unreadable table: sweep all of it
		int highest = STDERR_FILENO;
		while (const dirent *entry = ::readdir(dir))
		{
			char *end = nullptr;
			const long fd = std::strtol(entry->d_name, &end, 10);
			if (end && *end == '\0' && fd > highest && fd < INT_MAX - FD_SCAN_MARGIN)
				highest = static_cast<int>(fd);
		}
		::closedir(dir);
		return highest + FD_SCAN_MARGIN;
	}

	// Close everything above stderr except the report pipe. Linux closes the
	// whole range with one syscall (kernel 5.9+); other systems, or ENOSYS,
	// sweep up to the parent-computed bound.
	void closeInheritedDescriptors(int keepFd, int closeLimit)
	{
#if defined(__linux__) && defined(SYS_close_range)
		const auto last = static_cast<unsigned int>(INT_MAX);
		bool ranged = true;
		if (keepFd > STDERR_FILENO + 1)
			ranged = ::syscall(SYS_close_range, STDERR_FILENO + 1, keepFd - 1, 0) == 0;
		if (ranged)
			ranged = ::syscall(SYS_close_range, keepFd + 1, last, 0) == 0;
		if (ranged)
			return;
#endif
		for (int fd = STDERR_FILENO + 1; fd <= closeLimit; ++fd)
			if (fd != keepFd)
				::close(fd);
	}
} // namespace

ForkExecResult forkExec(const ForkExecRequest &request)
{
	ForkExecResult result;

	// Everything the child touches is prepared parent-side: only the prepared
	// pointers are used between fork and execve.
	std::vector<const char *> argv;
	argv.reserve(request.argv.size() + 1);
	for (const auto &arg : request.argv)
		argv.push_back(arg.c_str());
	argv.push_back(nullptr);
	std::vector<const char *> envp;
	envp.reserve(request.environment.size() + 1);
	for (const auto &kv : request.environment)
		envp.push_back(kv.c_str());
	envp.push_back(nullptr);
	std::vector<const char *> cgroups;
	cgroups.reserve(request.cgroupProcsFiles.size());
	for (const auto &path : request.cgroupProcsFiles)
		cgroups.push_back(path.c_str());
	const char *const workDir = request.workingDirectory.c_str();
	const char *const executable = request.executable.c_str();

	int reportPipe[2] = {-1, -1};
	if (::pipe(reportPipe) != 0)
	{
		result.error = errno;
		result.stage = "pipe";
		return result;
	}
	// The child's dup2 onto 0-2 must not clobber the report pipe (a daemon
	// started with closed stdio would hand out those numbers).
	if (reportPipe[1] <= STDERR_FILENO)
	{
		const int moved = ::fcntl(reportPipe[1], F_DUPFD, STDERR_FILENO + 1);
		if (moved >= 0)
		{
			::close(reportPipe[1]);
			reportPipe[1] = moved;
		}
	}
	// Close-on-exec on the child's write end turns a successful execve into EOF.
	if (::fcntl(reportPipe[0], F_SETFD, FD_CLOEXEC) != 0 || ::fcntl(reportPipe[1], F_SETFD, FD_CLOEXEC) != 0)
	{
		result.error = errno;
		result.stage = "fcntl";
		::close(reportPipe[0]);
		::close(reportPipe[1]);
		return result;
	}
	const int closeLimit = closeSweepLimit();

	const pid_t pid = ::fork();
	if (pid < 0)
	{
		result.error = errno;
		result.stage = "fork";
		::close(reportPipe[0]);
		::close(reportPipe[1]);
		return result;
	}
	if (pid == 0)
	{
		// Child: raw system calls only until execve.
		const int reportFd = reportPipe[1];
		if (!request.workingDirectory.empty() && ::chdir(workDir) != 0)
			failInChild(STAGE_CHDIR, reportFd);
		if (request.stdinFd >= 0 && ::dup2(request.stdinFd, STDIN_FILENO) < 0)
			failInChild(STAGE_DUP2, reportFd);
		if (request.stdoutFd >= 0 && ::dup2(request.stdoutFd, STDOUT_FILENO) < 0)
			failInChild(STAGE_DUP2, reportFd);
		if (request.stderrFd >= 0 && ::dup2(request.stderrFd, STDERR_FILENO) < 0)
			failInChild(STAGE_DUP2, reportFd);
		if (::setpgid(0, 0) != 0)
			failInChild(STAGE_SETPGID, reportFd);
		// Join the leaves while still root: writing "0" moves the writer itself,
		// so the limits apply from the program's first instruction.
		static const char selfPid[] = "0\n";
		for (std::size_t i = 0; i < cgroups.size(); ++i)
		{
			const int fd = ::open(cgroups[i], O_WRONLY);
			if (fd < 0)
				failInChild(STAGE_CGROUP, reportFd);
			const ssize_t written = ::write(fd, selfPid, sizeof(selfPid) - 1);
			const int writeErrno = errno;
			::close(fd);
			if (written != static_cast<ssize_t>(sizeof(selfPid) - 1))
			{
				errno = writeErrno;
				failInChild(STAGE_CGROUP, reportFd);
			}
		}
		if (request.uid != 0)
		{
			// Supplementary groups are the daemon's; gid before uid, because
			// after setuid the process may no longer change groups.
			if (::geteuid() == 0 && ::setgroups(0, nullptr) != 0)
				failInChild(STAGE_SETGROUPS, reportFd);
			if (::setgid(static_cast<gid_t>(request.gid)) != 0)
				failInChild(STAGE_SETGID, reportFd);
			if (::setuid(static_cast<uid_t>(request.uid)) != 0)
				failInChild(STAGE_SETUID, reportFd);
		}
		closeInheritedDescriptors(reportFd, closeLimit);
		::execve(executable, const_cast<char *const *>(argv.data()), const_cast<char *const *>(envp.data()));
		failInChild(STAGE_EXECVE, reportFd);
	}

	// Parent: EOF reports a successful exec, bytes report a failed step.
	::close(reportPipe[1]);
	const auto deadline = std::chrono::steady_clock::now() + request.execTimeout;
	for (;;)
	{
		// Always look at the pipe before judging the deadline: a child that
		// exec'd while this thread was starved has its EOF waiting and must not
		// be killed as stuck.
		auto remaining =
			std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
		if (remaining < 0)
			remaining = 0;
		pollfd pfd{reportPipe[0], POLLIN, 0};
		const int ready = ::poll(&pfd, 1, static_cast<int>(remaining));
		if (ready < 0)
		{
			if (errno == EINTR)
				continue;
			result.error = errno;
			result.stage = "poll";
			break;
		}
		if (ready == 0)
		{
			if (remaining > 0)
				continue; // the wait ran out; the next pass makes one last zero-wait check
			::kill(pid, SIGKILL);
			// A SIGKILLed child is reaped opportunistically; a kernel-stuck one
			// may outlive this loop and stay a zombie until the daemon exits.
			for (int i = 0; i < 50 && ::waitpid(pid, nullptr, WNOHANG) == 0; ++i)
				::usleep(20000);
			result.error = ETIMEDOUT;
			result.stage = "exec";
			break;
		}
		ChildReport report{};
		ssize_t count = 0;
		do
		{
			count = ::read(reportPipe[0], &report, sizeof(report));
		} while (count < 0 && errno == EINTR);
		if (count == 0)
		{
			result.pid = pid;
			break;
		}
		if (count == static_cast<ssize_t>(sizeof(report)))
		{
			::waitpid(pid, nullptr, 0);
			result.error = report.error;
			result.stage = stageName(report.stage);
			break;
		}
		// Partial read: impossible for an atomic 8-byte write; treat as a failure.
		result.error = EIO;
		result.stage = "pipe";
		break;
	}
	::close(reportPipe[0]);
	return result;
}

#endif // !_WIN32

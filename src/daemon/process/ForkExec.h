// src/daemon/process/ForkExec.h
#pragma once

#if !defined(_WIN32)

#include <chrono>
#include <string>
#include <sys/types.h>
#include <vector>

/// One child launch: fork, prepare the child with raw system calls only, exec.
struct ForkExecRequest
{
	std::string executable;               ///< resolved path passed to execve
	std::vector<std::string> argv;        ///< argv[0] included
	std::vector<std::string> environment; ///< "KEY=VALUE" entries, replaces the environment
	std::string workingDirectory;         ///< empty: inherit the parent's
	int stdinFd = -1;                     ///< -1: inherit the parent's descriptor
	int stdoutFd = -1;
	int stderrFd = -1;
	unsigned int uid = 0; ///< 0: keep the parent's identity
	unsigned int gid = 0;
	std::vector<std::string> cgroupProcsFiles;    ///< cgroup.procs leaves the child joins before exec
	std::chrono::milliseconds execTimeout{10000}; ///< bound on the wait for the child's exec report
};

struct ForkExecResult
{
	pid_t pid = -1;              ///< > 0 when the child has exec'd
	int error = 0;               ///< errno of the failed step
	const char *stage = nullptr; ///< name of the failed step ("fork", "chdir", "execve", ...)
};

/// Launches the request. The child runs only async-signal-safe calls between
/// fork and execve, closes every descriptor other than the mapped stdio, and
/// reports an exec failure to the parent over a pipe; a child that reports
/// nothing within execTimeout is killed and the launch fails.
ForkExecResult forkExec(const ForkExecRequest &request);

#endif // !_WIN32

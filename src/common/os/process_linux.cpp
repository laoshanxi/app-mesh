// src/common/os/process_linux.cpp
// Linux-specific process utilities using /proc filesystem.

#include "process.h"

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <queue>
#include <unordered_map>
#include <unistd.h>

#include <assert.h>

#include "../Utility.h"

namespace os
{

	size_t pagesize()
	{
		long result = ::sysconf(_SC_PAGESIZE);
		assert(result >= 0);
		return static_cast<size_t>(result);
	}

	std::shared_ptr<ProcessStatus> status(pid_t pid)
	{
		const static char fname[] = "proc::status() ";

		if (pid <= 0)
		{
			return nullptr;
		}

		const std::string path = "/proc/" + std::to_string(pid) + "/stat";

		std::ifstream statFile(path);
		if (!statFile.is_open())
			return nullptr;

		std::string content;
		content.reserve(512);
		content.assign(std::istreambuf_iterator<char>(statFile), std::istreambuf_iterator<char>());
		if (content.empty())
		{
			LOG_DBG << fname << "Process does not exist or file is empty: " << path;
			return nullptr;
		}

		std::string comm;
		char state;
		pid_t ppid;
		pid_t pgrp;
		pid_t session;
		int tty_nr;
		pid_t tpgid;
		unsigned int flags;
		unsigned long minflt, cminflt, majflt, cmajflt;
		unsigned long utime, stime;
		long cutime, cstime;
		long priority, nice, num_threads, itrealvalue;
		unsigned long long starttime;
		unsigned long vsize;
		long rss;
		unsigned long rsslim, startcode, endcode, startstack, kstkeip;
		unsigned long signal_val, blocked, sigcatch, wchan, nswap, cnswap;

		size_t lastParenPos = content.find_last_of(')');
		if (lastParenPos == std::string::npos)
		{
			LOG_DBG << fname << "Malformed stat file: " << path;
			return nullptr;
		}

		pid_t parsedPid;
		if (sscanf(content.c_str(), "%d", &parsedPid) != 1)
		{
			LOG_WAR << fname << "Failed to parse PID from stat file: " << path;
			return nullptr;
		}

		size_t firstParenPos = content.find('(');
		if (firstParenPos == std::string::npos || firstParenPos >= lastParenPos)
		{
			LOG_WAR << fname << "Malformed command name in stat file: " << path;
			return nullptr;
		}
		comm = content.substr(firstParenPos + 1, lastParenPos - firstParenPos - 1);

		const char *afterParen = content.c_str() + lastParenPos + 1;
		if (sscanf(afterParen, " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
				   &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags, &minflt, &cminflt, &majflt, &cmajflt,
				   &utime, &stime, &cutime, &cstime, &priority, &nice, &num_threads, &itrealvalue, &starttime,
				   &vsize, &rss, &rsslim, &startcode, &endcode, &startstack, &kstkeip, &signal_val, &blocked,
				   &sigcatch, &wchan, &nswap, &cnswap) != 33)
		{
			LOG_WAR << fname << "Failed to parse all fields from stat file: " << path;
			return nullptr;
		}

		return std::make_shared<ProcessStatus>(
			pid, comm, state, ppid, pgrp, session, utime, stime, cutime, cstime, starttime, vsize, rss);
	}

	std::string cmdline(pid_t pid /* = 0 */)
	{
		const static char fname[] = "proc::cmdline() ";

		std::string path = (pid > 0) ? ("/proc/" + std::to_string(pid) + "/cmdline") : std::string("/proc/self/cmdline");

		std::ifstream ifs(path, std::ios::binary);
		if (!ifs.is_open())
		{
			if (!Utility::isFileExist(path))
				LOG_WAR << fname << "Process (pid=" << pid << ") may have terminated, file does not exist: " << path;
			else
				LOG_WAR << fname << "Failed to open " << path << " error: " << last_error_msg();
			return {};
		}

		std::string raw;
		raw.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());

		if (raw.empty())
			return {};

		std::string result;
		result.reserve(raw.size());
		for (size_t i = 0; i < raw.size(); ++i)
		{
			char c = raw[i];
			if (c == '\0')
			{
				if (i + 1 < raw.size())
					result.push_back(' ');
			}
			else
			{
				result.push_back(c);
			}
		}

		return result;
	}

	std::unordered_set<pid_t> child_pids(pid_t rootPid)
	{
		std::unordered_set<pid_t> result;
		std::unordered_map<pid_t, std::vector<pid_t>> children;

		std::unique_ptr<DIR, void (*)(DIR *)> proc(opendir("/proc"), [](DIR *d)
												   { if(d) closedir(d); });
		if (!proc)
			return result;

		struct dirent *entry;
		while ((entry = readdir(proc.get())) != nullptr)
		{
			char *endptr = nullptr;
			long lpid = strtol(entry->d_name, &endptr, 10);
			if (!endptr || *endptr != '\0' || lpid <= 0)
				continue;

			pid_t pid = static_cast<pid_t>(lpid);
			char statPath[64];
			snprintf(statPath, sizeof(statPath), "/proc/%ld/stat", lpid);

			std::unique_ptr<FILE, void (*)(FILE *)> f(fopen(statPath, "r"), [](FILE *fp)
													  { if (fp) fclose(fp); });
			if (!f)
				continue;

			char line[1024];
			if (fgets(line, sizeof(line), f.get()) != nullptr)
			{
				char *rparen = strrchr(line, ')');
				if (rparen)
				{
					int ppid = 0;
					char state = 0;
					if (sscanf(rparen + 1, " %c %d", &state, &ppid) == 2)
					{
						children[static_cast<pid_t>(ppid)].push_back(pid);
					}
				}
			}
		}

		std::queue<pid_t> q;
		q.push(rootPid);
		while (!q.empty())
		{
			pid_t p = q.front();
			q.pop();
			auto it = children.find(p);
			if (it == children.end())
				continue;
			for (pid_t c : it->second)
			{
				if (result.insert(c).second)
					q.push(c);
			}
		}
		return result;
	}

} // namespace os

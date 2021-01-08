#include <fstream>
#include <thread>

#include <ace/OS.h>
#include <boost/filesystem.hpp>

#include "../../common/DateTime.h"
#include "../../common/Utility.h"
#include "../../common/os/pstree.hpp"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "AppProcess.h"
#include "LinuxCgroup.h"

constexpr const char *STDOUT_BAK_POSTFIX = ".bak";

AppProcess::AppProcess()
	: m_delayKillTimerId(0), m_stdOutSizeTimerId(0), m_stdOutMaxSize(0),
	  m_stdinHandler(ACE_INVALID_HANDLE), m_stdoutHandler(ACE_INVALID_HANDLE),
	  m_lastProcCpuTime(0), m_lastSysCpuTime(0), m_uuid(Utility::createUUID())
{
	const static char fname[] = "AppProcess::AppProcess() ";
	LOG_DBG << fname << "Entered";
}

AppProcess::~AppProcess()
{
	const static char fname[] = "AppProcess::~AppProcess() ";
	LOG_DBG << fname << "Entered";

	if (this->running())
	{
		killgroup();
	}

	CLOSE_ACE_HANDLER(m_stdoutHandler);
	CLOSE_ACE_HANDLER(m_stdinHandler);

	Utility::removeFile(m_stdinFileName);
	CLOSE_STREAM(m_stdoutReadStream);
	this->cancelTimer(m_stdOutSizeTimerId);

	this->close_dup_handles();
	this->close_passed_handles();

	if (m_stdoutFileName.length())
	{
		Utility::removeFile(m_stdoutFileName + STDOUT_BAK_POSTFIX);
	}
}

void AppProcess::attach(int pid)
{
	this->child_id_ = pid;
}

void AppProcess::detach(void)
{
	attach(ACE_INVALID_PID);
}

pid_t AppProcess::getpid(void) const
{
	return ACE_Process::getpid();
}

void AppProcess::killgroup(int timerId)
{
	const static char fname[] = "AppProcess::killgroup() ";

	LOG_INF << fname << "kill process <" << getpid() << ">.";

	if (timerId == 0)
	{
		// killed before timer event, cancel timer event
		this->cancelTimer(m_delayKillTimerId);
	}
	if (m_delayKillTimerId > 0 && m_delayKillTimerId == timerId)
	{
		// clean timer id, trigger-ing this time.
		m_delayKillTimerId = 0;
	}

	if (this->running() && this->getpid() > 1)
	{
		ACE_OS::kill(-(this->getpid()), 9);
		this->terminate();
		if (this->wait() < 0 && errno != 10) // 10 is ECHILD:No child processes
		{
			//avoid  zombie process (Interrupted system call)
			LOG_WAR << fname << "Wait process <" << getpid() << "> to exit failed with error : " << std::strerror(errno);
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			if (this->wait() < 0)
			{
				LOG_ERR << fname << "Retry wait process <" << getpid() << "> failed with error : " << std::strerror(errno);
			}
			else
			{
				LOG_INF << fname << "Retry wait process <" << getpid() << "> success";
			}
		}
	}
	this->cancelTimer(m_stdOutSizeTimerId);
}

void AppProcess::setCgroup(std::shared_ptr<ResourceLimitation> &limit)
{
	// https://blog.csdn.net/u011547375/article/details/9851455
	if (limit != nullptr)
	{
		m_cgroup = std::make_unique<LinuxCgroup>(limit->m_memoryMb, limit->m_memoryVirtMb - limit->m_memoryMb, limit->m_cpuShares);
		m_cgroup->setCgroup(limit->m_name, getpid(), ++(limit->m_index));
	}
}

const std::string AppProcess::getuuid() const
{
	return m_uuid;
}

void AppProcess::delayKill(std::size_t timeout, const std::string &from)
{
	const static char fname[] = "AppProcess::delayKill() ";

	if (0 == m_delayKillTimerId)
	{
		m_delayKillTimerId = this->registerTimer(1000L * timeout, 0, std::bind(&AppProcess::killgroup, this, std::placeholders::_1), from);
	}
	else
	{
		LOG_ERR << fname << "already pending for kill with timer id: " << m_delayKillTimerId;
	}
}

void AppProcess::regCheckStdout()
{
	const static char fname[] = "AppProcess::regCheckStdout() ";

	if (0 == m_stdOutSizeTimerId)
	{
		int timeoutSec = 5;
		m_stdOutSizeTimerId = this->registerTimer(1000L * timeoutSec, timeoutSec, std::bind(&AppProcess::checkStdout, this, std::placeholders::_1), fname);
	}
	else
	{
		LOG_ERR << fname << "already registered stdout check timer id: " << m_delayKillTimerId;
	}
}

void AppProcess::checkStdout(int timerId)
{
	const static char fname[] = "AppProcess::checkStdout() ";

	if (m_stdoutHandler != ACE_INVALID_HANDLE && m_stdOutMaxSize)
	{
		ACE_stat stat;
		if (0 == ACE_OS::fstat(m_stdoutHandler, &stat))
		{
			if (stat.st_size > m_stdOutMaxSize)
			{
				// https://stackoverflow.com/questions/10195343/copy-a-file-in-a-sane-safe-and-efficient-way
				auto backupFile = boost::filesystem::path(m_stdoutFileName + STDOUT_BAK_POSTFIX);
				boost::filesystem::copy_file(boost::filesystem::path(m_stdoutFileName), backupFile, boost::filesystem::copy_option::overwrite_if_exists);
				ACE_OS::ftruncate(m_stdoutHandler, 0);
				LOG_INF << fname << "file size: " << stat.st_size << " reached: " << m_stdOutMaxSize << ", switched stdout file: " << m_stdoutFileName;
			}
		}
	}
	// automatic release timer reference when not running
	if (!this->running())
	{
		this->cancelTimer(timerId);
	}
}

// tuple: 1 cmdRoot, 2 parameters
std::tuple<std::string, std::string> AppProcess::extractCommand(const std::string &cmd)
{
	std::unique_ptr<char[]> buff(new char[cmd.length() + 1]);

	// find the string at the first blank not in a quote, quotes are removed
	std::size_t idxSrc = 0, idxDst = 0;
	bool isInQuote = false;
	while (cmd[idxSrc] != '\0')
	{
		if (cmd[idxSrc] == ' ' && !isInQuote)
		{
			break;
		}
		else if (cmd[idxSrc] == '\"')
		{
			isInQuote = isInQuote ^ true;
		}
		else
		{
			buff[idxDst++] = cmd[idxSrc];
		}
		idxSrc++;
	}
	buff[idxDst] = '\0';

	// remaining string are the parameters
	std::string params = cmd.substr(idxSrc);
	std::string cmdroot = buff.get();
	return std::tuple<std::string, std::string>(params, cmdroot);
}

int AppProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile, const std::string &stdinFileContent, const int maxStdoutSize)
{
	const static char fname[] = "AppProcess::spawnProcess() ";

	int pid = -1;

	// check command file existence & permission
	auto cmdRoot = std::get<1>(extractCommand(cmd));
	bool checkCmd = true;
	if (cmdRoot.rfind('/') == std::string::npos && cmdRoot.rfind('\\') == std::string::npos)
	{
		checkCmd = false;
	}
	if (checkCmd && !Utility::isFileExist(cmdRoot))
	{
		LOG_WAR << fname << "command file <" << cmdRoot << "> does not exist";
		startError(Utility::stringFormat("command file <%s> does not exist", cmdRoot.c_str()));
		return ACE_INVALID_PID;
	}
	if (checkCmd && ACE_OS::access(cmdRoot.c_str(), X_OK) != 0)
	{
		LOG_WAR << fname << "command file <" << cmdRoot << "> does not have execution permission";
		startError(Utility::stringFormat("command file <%s> does not have execution permission", cmdRoot.c_str()));
		return ACE_INVALID_PID;
	}

	envMap[ENV_APP_MANAGER_LAUNCH_TIME] = DateTime::formatLocalTime(std::chrono::system_clock::now(), DATE_TIME_FORMAT);
	std::size_t cmdLength = cmd.length() + ACE_Process_Options::DEFAULT_COMMAND_LINE_BUF_LEN;
	int totalEnvSize = 0;
	int totalEnvArgs = 0;
	Utility::getEnvironmentSize(envMap, totalEnvSize, totalEnvArgs);
	ACE_Process_Options option(1, cmdLength, totalEnvSize, totalEnvArgs);
	option.command_line("%s", cmd.c_str());
	//option.avoid_zombies(1);
	if (user.empty())
		user = Configuration::instance()->getDefaultExecUser();
	if (user != "root")
	{
		unsigned int gid, uid;
		if (Utility::getUid(user, uid, gid))
		{
			option.seteuid(uid);
			option.setruid(uid);
			option.setegid(gid);
			option.setrgid(gid);
		}
		else
		{
			startError(Utility::stringFormat("user <%s> does not exist", user.c_str()));
			return ACE_INVALID_PID;
		}
	}
	option.setgroup(0); // set group id with the process id, used to kill process group
	option.inherit_environment(true);
	option.handle_inheritance(0);
	if (workDir.length())
	{
		option.working_directory(workDir.c_str());
	}
	else
	{
		option.working_directory(Configuration::instance()->getDefaultWorkDir().c_str()); // set default working dir
	}
	std::for_each(envMap.begin(), envMap.end(), [&option](const std::pair<std::string, std::string> &pair) {
		option.setenv(pair.first.c_str(), "%s", pair.second.c_str());
		LOG_DBG << "spawnProcess with env: " << pair.first.c_str() << "=" << pair.second.c_str();
	});
	option.release_handles();
	// clean if necessary
	CLOSE_ACE_HANDLER(m_stdoutHandler);
	CLOSE_ACE_HANDLER(m_stdinHandler);
	ACE_HANDLE dummy = ACE_INVALID_HANDLE;
	m_stdoutFileName = stdoutFile;
	if (stdoutFile.length() || stdinFileContent.length())
	{
		dummy = ACE_OS::open("/dev/null", O_RDWR);
		m_stdoutHandler = m_stdinHandler = dummy;
		if (stdoutFile.length())
		{
			m_stdoutHandler = ACE_OS::open(stdoutFile.c_str(), O_CREAT | O_WRONLY | O_APPEND | O_TRUNC, 00664);
			LOG_DBG << fname << "std_out: " << stdoutFile;
		}
		if (stdinFileContent.length() && stdinFileContent != JSON_KEY_APP_CLOUD_APP)
		{
			m_stdinFileName = Utility::stringFormat("appmesh.%s.stdin", m_uuid.c_str());
			std::ofstream inputFile(m_stdinFileName, std::ios::trunc);
			inputFile << stdinFileContent;
			inputFile.close();
			assert(Utility::isFileExist(m_stdinFileName));
			m_stdinHandler = ACE_OS::open(m_stdinFileName.c_str(), O_RDONLY, 00664);
			LOG_DBG << fname << "std_in: " << m_stdinFileName << " : " << stdinFileContent;
		}
		option.set_handles(m_stdinHandler, m_stdoutHandler, m_stdoutHandler);
	}
	// do not inherit LD_LIBRARY_PATH to child
	static const std::string ldEnv = ACE_OS::getenv("LD_LIBRARY_PATH") ? ACE_OS::getenv("LD_LIBRARY_PATH") : "";
	if (!ldEnv.empty() && !envMap.count("LD_LIBRARY_PATH"))
	{
		std::string env = ldEnv;
		env = Utility::stringReplace(env, "/opt/appmesh/lib64:", "");
		env = Utility::stringReplace(env, ":/opt/appmesh/lib64", "");
		option.setenv("LD_LIBRARY_PATH", "%s", env.c_str());
	}
	if (this->spawn(option) >= 0)
	{
		pid = this->getpid();
		LOG_INF << fname << "Process <" << cmd << "> started with pid <" << pid << ">.";
		this->setCgroup(limit);
		if (m_stdoutHandler != ACE_INVALID_HANDLE && maxStdoutSize)
		{
			m_stdOutMaxSize = maxStdoutSize;
			this->regCheckStdout();
		}
	}
	else
	{
		pid = -1;
		LOG_ERR << fname << "Process:<" << cmd << "> start failed with error : " << std::strerror(errno);
		startError(Utility::stringFormat("start failed with error <%s>", std::strerror(errno)));
	}
	if (dummy != ACE_INVALID_HANDLE)
		ACE_OS::close(dummy);
	return pid;
}

const std::string AppProcess::fetchOutputMsg()
{
	std::lock_guard<std::recursive_mutex> guard(m_outFileMutex);
	if (m_stdoutReadStream == nullptr)
		m_stdoutReadStream = std::make_shared<std::ifstream>(m_stdoutFileName, ios::in);
	if (m_stdoutReadStream->is_open() && m_stdoutReadStream->good())
	{
		std::stringstream buffer;
		buffer << m_stdoutReadStream->rdbuf();
		return buffer.str();
	}
	return std::string();
}

const std::string AppProcess::fetchLine()
{
	char buffer[512] = {0};
	std::lock_guard<std::recursive_mutex> guard(m_outFileMutex);
	if (m_stdoutReadStream == nullptr)
		m_stdoutReadStream = std::make_shared<std::ifstream>(m_stdoutFileName, ios::in);
	if (m_stdoutReadStream->is_open() && m_stdoutReadStream->good())
	{
		m_stdoutReadStream->getline(buffer, sizeof(buffer));
	}
	return buffer;
}

void AppProcess::startError(const std::string &err)
{
	m_startError = err;
}

const std::string AppProcess::startError() const
{
	return m_startError;
}

std::tuple<bool, uint64_t, float> AppProcess::getProcUsage()
{
	auto pid = this->getpid();
	if (pid > 0)
	{
		auto tree = os::pstree(this->getpid());
		auto totalMemory = tree ? tree->totalRssMemBytes() : 0;

		// https://stackoverflow.com/questions/1420426/how-to-calculate-the-cpu-usage-of-a-process-by-pid-in-linux-from-c/1424556
		auto curSysCpuTime = os::cpuTotalTime();
		float cpuUsage(0);
		auto curProcCpuTime = tree ? tree->totalCpuTime() : 0;
		static auto cpuNumber = os::cpus().size(); //static int cpuNumber = sysconf(_SC_NPROCESSORS_ONLN);
		std::lock_guard<std::recursive_mutex> guard(m_cpuMutex);
		// only calculate when there have previous cpu time record
		if (m_lastSysCpuTime && curSysCpuTime && curProcCpuTime)
		{
			auto totalTimeDiff = curSysCpuTime - m_lastSysCpuTime;
			cpuUsage = 100.0 * cpuNumber * (curProcCpuTime - m_lastProcCpuTime) / totalTimeDiff;
		}
		m_lastProcCpuTime = curProcCpuTime;
		m_lastSysCpuTime = curSysCpuTime;
		return std::make_tuple(true, totalMemory, cpuUsage);
	}
	return std::make_tuple(false, uint64_t(0), float(0));
}

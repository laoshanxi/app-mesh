#include <fstream>
#include <thread>

#include <ace/File_Lock.h>
#include <ace/OS.h>
#include <ace/Process_Manager.h>
#include <boost/filesystem.hpp>

#include "../../common/DateTime.h"
#include "../../common/Utility.h"
#include "../../common/os/pstree.hpp"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "AppProcess.h"
#include "LinuxCgroup.h"
#include <ace/Map_Manager.h>

constexpr const char *STDOUT_BAK_POSTFIX = ".bak";
ACE_Map_Manager<pid_t, AppProcess *, ACE_Recursive_Thread_Mutex> m_processMap(ACE_Process_Manager::DEFAULT_SIZE);

AppProcess::AppProcess()
	: m_delayKillTimerId(INVALID_TIMER_ID), m_stdOutSizeTimerId(INVALID_TIMER_ID), m_stdOutMaxSize(0),
	  m_stdinHandler(ACE_INVALID_HANDLE), m_stdoutHandler(ACE_INVALID_HANDLE),
	  m_lastProcCpuTime(0), m_lastSysCpuTime(0), m_uuid(Utility::createUUID()),
	  m_pid(ACE_INVALID_PID), m_returnValue(-1)
{
	const static char fname[] = "AppProcess::AppProcess() ";
	LOG_DBG << fname << "Entered, ID: " << m_uuid;
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
	this->cancelTimer(m_stdOutSizeTimerId);

	if (m_stdoutFileName.length())
	{
		Utility::removeFile(m_stdoutFileName + STDOUT_BAK_POSTFIX);
	}

	m_processMap.unbind(m_pid.load());
}

void AppProcess::attach(int pid, const std::string &stdoutFile)
{
	this->m_pid.store(pid);
	m_stdoutFileName = stdoutFile;

	CLOSE_ACE_HANDLER(m_stdoutHandler);
	auto stdout = Utility::stringFormat("/proc/%d/fd/1", getpid());
	m_stdoutHandler = ACE_OS::open(stdout.c_str(), O_RDWR);
	m_stdOutMaxSize = APP_STD_OUT_MAX_FILE_SIZE;
}

void AppProcess::detach(void)
{
	attach(ACE_INVALID_PID, std::string());
}

pid_t AppProcess::getpid(void) const
{
	return m_pid.load();
}

int AppProcess::returnValue(void) const
{
	return m_returnValue.load();
}

void AppProcess::returnValue(int value)
{
	m_returnValue.store(value);
}

bool AppProcess::running() const
{
	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_processMap.mutex());
	return (m_processMap.find(m_pid.load()) == 0);
}

pid_t AppProcess::wait(const ACE_Time_Value &tv, ACE_exitcode *status)
{
	// Not use timed wait for ACE_Process_Manager, that will impact ProcessExitHandler::handle_exit
	ACE_Time_Value shortInterval;
	shortInterval.msec(10);
	const auto endTime = (ACE_OS::gettimeofday() + tv);
	while (this->running() && ACE_OS::gettimeofday() < endTime)
	{
		auto pid = ACE_Process_Manager::instance()->wait(m_pid.load(), ACE_Time_Value::zero, status);
		if (pid > 0)
			return pid;
		ACE_OS::sleep(shortInterval);
	}
	return ACE_Process_Manager::instance()->wait(m_pid.load(), ACE_Time_Value::zero, status);
}

pid_t AppProcess::wait(ACE_exitcode *status)
{
	return ACE_Process_Manager::instance()->wait(m_pid.load(), status);
}

void AppProcess::killgroup()
{
	const static char fname[] = "AppProcess::killgroup() ";

	LOG_INF << fname << "kill process <" << getpid() << ">.";
	{
		std::lock_guard<std::recursive_mutex> guard(m_processMutex);
		if (this->running() && this->getpid() > 1)
		{
			ACE_OS::kill(-(this->getpid()), 9);
			EXITHANDLER::instance()->onTerminate(this->getpid());
			LOG_DBG << fname << "process <" << getpid() << "> killed";
		}

		CLOSE_ACE_HANDLER(m_stdoutHandler);
		CLOSE_ACE_HANDLER(m_stdinHandler);
	}
	this->cancelTimer(m_stdOutSizeTimerId);
	this->cancelTimer(m_delayKillTimerId);
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

	std::lock_guard<std::recursive_mutex> guard(m_processMutex);
	if (INVALID_TIMER_ID == m_delayKillTimerId)
	{
		m_delayKillTimerId = this->registerTimer(1000L * timeout, 0, std::bind(&AppProcess::killgroup, this), from);
	}
	else
	{
		LOG_ERR << fname << "already pending for kill with timer id: " << m_delayKillTimerId;
	}
}

void AppProcess::registerCheckStdoutTimer()
{
	const static char fname[] = "AppProcess::registerCheckStdoutTimer() ";

	if (INVALID_TIMER_ID == m_stdOutSizeTimerId)
	{
		static const int timeoutSec = 20;
		m_stdOutSizeTimerId = this->registerTimer(1000L * timeoutSec, timeoutSec, std::bind(&AppProcess::checkStdout, this), fname);
		LOG_INF << fname << "register stdout check timer id: " << m_stdOutSizeTimerId;
	}
	else
	{
		LOG_ERR << fname << "already registered stdout check timer id: " << m_delayKillTimerId;
	}
}

void AppProcess::checkStdout()
{
	const static char fname[] = "AppProcess::checkStdout() ";

	{
		std::lock_guard<std::recursive_mutex> guard(m_processMutex);
		if (m_stdoutHandler != ACE_INVALID_HANDLE && m_stdOutMaxSize)
		{
			ACE_stat stat;
			if (0 == ACE_OS::fstat(m_stdoutHandler, &stat))
			{
				if (stat.st_size > m_stdOutMaxSize)
				{
					// Acquire an exclusive lock on the file
					ACE_File_Lock fileLock(m_stdoutHandler, false);
					if (fileLock.acquire() == -1)
					{
						LOG_WAR << fname << "acquire exclusive lock on the stdout file failed: " << m_stdoutFileName;
					}

					// https://stackoverflow.com/questions/10195343/copy-a-file-in-a-sane-safe-and-efficient-way
					const auto backupFile = fs::path(m_stdoutFileName + STDOUT_BAK_POSTFIX);
					fs::copy_file(fs::path(m_stdoutFileName), backupFile, fs::copy_options::overwrite_existing);
					ACE_OS::ftruncate(m_stdoutHandler, 0);

					// Release the lock
					fileLock.release();
					LOG_INF << fname << "file size: " << stat.st_size << " reached: " << m_stdOutMaxSize << ", switched stdout file: " << m_stdoutFileName;
				}
			}
			else
			{
				LOG_ERR << fname << "fstat failed with error : " << std::strerror(errno);
				CLOSE_ACE_HANDLER(m_stdoutHandler);
				auto stdout = Utility::stringFormat("/proc/%d/fd/1", getpid());
				m_stdoutHandler = ACE_OS::open(stdout.c_str(), O_RDWR);
			}
		}
	}
	// automatic release timer reference when not running
	if (!this->running())
	{
		this->cancelTimer(m_stdOutSizeTimerId);
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

int AppProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile, const nlohmann::json &stdinFileContent, const int maxStdoutSize, bool sudoSwitchUser)
{
	const static char fname[] = "AppProcess::spawnProcess() ";

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

	envMap[ENV_APPMESH_LAUNCH_TIME] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
	std::size_t cmdLength = cmd.length() + ACE_Process_Options::DEFAULT_COMMAND_LINE_BUF_LEN;
	int totalEnvSize = 0;
	int totalEnvArgs = 0;
	Utility::getEnvironmentSize(envMap, totalEnvSize, totalEnvArgs);
	ACE_Process_Options option(1, cmdLength, totalEnvSize, totalEnvArgs);
	option.command_line("%s", cmd.c_str());
	// option.avoid_zombies(1);
	if (!user.empty() && user != "root" && !sudoSwitchUser)
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

	if (workDir.empty())
	{
		workDir = Configuration::instance()->getWorkDir();
	}
	option.working_directory(workDir.c_str());
	std::for_each(envMap.begin(), envMap.end(), [&option](const std::pair<std::string, std::string> &pair)
				  {
					  option.setenv(pair.first.c_str(), "%s", pair.second.c_str());
					  LOG_DBG << fname << "spawnProcess with env: " << pair.first.c_str() << "=" << pair.second.c_str(); });
	option.release_handles();
	// clean if necessary
	CLOSE_ACE_HANDLER(m_stdoutHandler);
	CLOSE_ACE_HANDLER(m_stdinHandler);
	m_stdoutFileName = stdoutFile;
	if (m_stdoutFileName.length() || stdinFileContent != EMPTY_STR_JSON)
	{
		/*
		*
			444 r--r--r--
			600 rw-------
			644 rw-r--r--
			666 rw-rw-rw-
			700 rwx------
			744 rwxr--r--
			755 rwxr-xr-x
			777 rwxrwxrwx
		*/
		m_stdoutHandler = m_stdinHandler = ACE_INVALID_HANDLE;
		if (m_stdoutFileName.length())
		{
			m_stdoutHandler = ACE_OS::open(m_stdoutFileName.c_str(), O_CREAT | O_WRONLY | O_APPEND | O_TRUNC, 0666);
			LOG_DBG << fname << "std_out: " << m_stdoutFileName << " m_stdoutHandler: " << m_stdoutHandler;
		}
		else
		{
			m_stdoutHandler = ACE_OS::open("/dev/null", O_RDWR);
		}
		if (stdinFileContent != EMPTY_STR_JSON && stdinFileContent != CLOUD_STR_JSON)
		{
			m_stdinFileName = Utility::stringFormat("appmesh.%s.stdin", m_uuid.c_str());
			std::ofstream inputFile(m_stdinFileName, std::ios::trunc);
			if (stdinFileContent.is_string())
				inputFile << stdinFileContent.get<std::string>();
			else
				inputFile << stdinFileContent.dump();
			inputFile.close();
			assert(Utility::isFileExist(m_stdinFileName));
			m_stdinHandler = ACE_OS::open(m_stdinFileName.c_str(), O_RDONLY, 0444);
			LOG_DBG << fname << "std_in: " << m_stdinFileName << " : " << stdinFileContent;
		}
		else
		{
			m_stdinHandler = ACE_OS::open("/dev/null", O_RDWR);
		}
		option.set_handles(m_stdinHandler, m_stdoutHandler, m_stdoutHandler);
	}
	// do not inherit LD_LIBRARY_PATH to child
	static const std::string ldEnv = ACE_OS::getenv(ENV_LD_LIBRARY_PATH) ? ACE_OS::getenv(ENV_LD_LIBRARY_PATH) : "";
	if (!ldEnv.empty() && !envMap.count(ENV_LD_LIBRARY_PATH))
	{
		std::string env = ldEnv;
		env = Utility::stringReplace(env, Utility::getParentDir() + "/lib64:", "");
		env = Utility::stringReplace(env, Utility::getParentDir() + "/lib64", "");
		option.setenv(ENV_LD_LIBRARY_PATH, "%s", env.c_str());
		LOG_DBG << fname << "replace LD_LIBRARY_PATH with " << env.c_str();
	}
	if (this->spawn(option) >= 0)
	{
		LOG_INF << fname << "Process <" << cmd << "> started with pid <" << m_pid.load() << ">.";
		this->setCgroup(limit);
		if (m_stdoutHandler != ACE_INVALID_HANDLE && maxStdoutSize)
		{
			m_stdOutMaxSize = maxStdoutSize;
		}
	}
	else
	{
		LOG_ERR << fname << "Process:<" << cmd << "> start failed with error : " << std::strerror(errno);
		startError(Utility::stringFormat("start failed with error <%s>", std::strerror(errno)));
	}
	return m_pid.load();
}

pid_t AppProcess::spawn(ACE_Process_Options &option)
{
	auto pid = ACE_Process_Manager::instance()->spawn(option);
	m_pid.store(pid);
	if (pid != ACE_INVALID_PID)
	{
		m_processMap.bind(pid, this);
		ACE_Process_Manager::instance()->register_handler(EXITHANDLER::instance(), pid);
	}
	return pid;
}

const std::string AppProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	std::lock_guard<std::recursive_mutex> guard(m_outFileMutex);
	return Utility::readFileCpp(m_stdoutFileName, position, maxSize, readLine);
}

void AppProcess::startError(const std::string &err)
{
	m_startError = err;
}

const std::string AppProcess::startError() const
{
	return m_startError;
}

std::tuple<bool, uint64_t, float, uint64_t, std::string> AppProcess::getProcessDetails(void *ptree)
{
	auto tree = os::pstree(this->getpid(), ptree);

	auto totalMemory = tree ? tree->totalRssMemBytes() : 0;
	auto totalFileDescriptors = tree ? tree->totalFileDescriptors() : 0;
	std::string pstreeStr;
	if (tree)
	{
		std::stringstream ss;
		ss << *tree;
		pstreeStr = ss.str();
	}

	// https://stackoverflow.com/questions/1420426/how-to-calculate-the-cpu-usage-of-a-process-by-pid-in-linux-from-c/1424556
	auto curSysCpuTime = os::cpuTotalTime();
	float cpuUsage(0);
	auto curProcCpuTime = tree ? tree->totalCpuTime() : 0;
	static auto cpuNumber = os::cpus().size(); // static int cpuNumber = sysconf(_SC_NPROCESSORS_ONLN);
	std::lock_guard<std::recursive_mutex> guard(m_cpuMutex);
	// only calculate when there have previous cpu time record
	if (m_lastSysCpuTime && curSysCpuTime && curProcCpuTime)
	{
		auto totalTimeDiff = curSysCpuTime - m_lastSysCpuTime;
		cpuUsage = 100.0 * cpuNumber * (curProcCpuTime - m_lastProcCpuTime) / totalTimeDiff;
	}
	m_lastProcCpuTime = curProcCpuTime;
	m_lastSysCpuTime = curSysCpuTime;
	return std::make_tuple(true, totalMemory, cpuUsage, totalFileDescriptors, pstreeStr);
}

ProcessExitHandler::ProcessExitHandler()
{
}

int ProcessExitHandler::handle_exit(ACE_Process *process)
{
	const static char fname[] = "ProcessExitHandler::handle_exit() ";

	LOG_INF << fname << "Process <" << process->getpid() << "> exited with exit code <" << process->return_value() << ">, process map size: " << m_processMap.current_size();

	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_processMap.mutex());
	AppProcess *p = nullptr;
	if (m_processMap.find(process->getpid(), p) == 0 && p)
	{
		p->returnValue(process->return_value());
		m_processMap.unbind(process->getpid());
	}
	return 0;
}

void ProcessExitHandler::onTerminate(pid_t pid)
{
	const static char fname[] = "ProcessExitHandler::onTerminate() ";
	LOG_INF << fname << "Process <" << pid << "> killed, process map size: " << m_processMap.current_size();
	{
		ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_processMap.mutex());
		ACE_Process_Manager::instance()->remove(pid);
		AppProcess *p = nullptr;
		if (m_processMap.find(pid, p) == 0 && p)
		{
			p->returnValue(9);
			m_processMap.unbind(pid);
		}
	}
	ACE_Process_Manager::instance()->wait(pid);
}
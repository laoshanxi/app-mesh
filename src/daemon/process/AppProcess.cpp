#include <fstream>
#include <thread>

#include <ace/File_Lock.h>
#include <ace/Hash_Multi_Map_Manager_T.h>
#include <ace/Map_Manager.h>
#include <ace/OS.h>
#include <ace/Process_Manager.h>
#include <boost/filesystem.hpp>

#include "../../common/DateTime.h"
#include "../../common/Utility.h"
#include "../../common/os/pstree.hpp"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../application/Application.h"
#include "../rest/HttpRequest.h"
#include "AppProcess.h"
#include "LinuxCgroup.h"

extern APP_OUT_MULTI_MAP_TYPE APP_OUT_VIEW_MAP;
constexpr const char *STDOUT_BAK_POSTFIX = ".bak";

AppProcess::AppProcess(void *owner)
	: m_owner(owner), m_delayKillTimerId(INVALID_TIMER_ID), m_stdOutSizeTimerId(INVALID_TIMER_ID),
	  m_stdOutMaxSize(0), m_stdinHandler(ACE_INVALID_HANDLE), m_stdoutHandler(ACE_INVALID_HANDLE),
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
		terminate();
	}

	CLOSE_ACE_HANDLER(m_stdoutHandler);
	CLOSE_ACE_HANDLER(m_stdinHandler);

	Utility::removeFile(m_stdinFileName);
	this->cancelTimer(m_stdOutSizeTimerId);

	if (m_stdoutFileName.length())
	{
		Utility::removeFile(m_stdoutFileName + STDOUT_BAK_POSTFIX);
	}
}

void AppProcess::attach(int pid, const std::string &stdoutFile)
{
	this->m_pid = pid;
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
	return m_pid;
}

int AppProcess::returnValue(void) const
{
	return m_returnValue;
}

void AppProcess::onExit(int exitCode)
{
	const static char fname[] = "AppProcess::onExit() ";
	m_pid = ACE_INVALID_PID;
	m_returnValue = exitCode;
	this->registerTimer(0, 0, std::bind(&AppProcess::handleAppExit, this), fname);
}

void AppProcess::handleAppExit()
{
	if (m_owner)
	{
		auto app = Configuration::instance()->getApp(m_owner);
		if (app)
		{
			// update app exit information
			app->onExitUpdate(m_returnValue);
		}
	}
}

bool AppProcess::running() const
{
	return running(this->getpid());
}

bool AppProcess::running(pid_t pid)
{
	// from ACE_Process::running()
	if (ACE_INVALID_PID == pid)
		return 0;
	else
		return ACE_OS::kill(pid, 0) == 0 || errno != ESRCH;
}

pid_t AppProcess::wait(const ACE_Time_Value &tv, ACE_exitcode *status)
{
	// Not use timed wait for Process_Manager, that will impact ProcessExitHandler::handle_exit
	const static ACE_Time_Value shortInterval(0, 10000); // 10 milliseconds

	if (tv != ACE_Time_Value::zero)
	{
		const auto endTime = (ACE_OS::gettimeofday() + tv);
		while (this->running() && ACE_OS::gettimeofday() < endTime)
		{
			{
				ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
				auto pid = Process_Manager::instance()->wait(m_pid, ACE_Time_Value::zero, status);
				if (pid > 0)
				{
					return pid;
				}
			}
			ACE_OS::sleep(shortInterval);
		}
	}
	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
	return Process_Manager::instance()->wait(m_pid, ACE_Time_Value::zero, status);
}

pid_t AppProcess::wait(ACE_exitcode *status)
{
	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
	return Process_Manager::instance()->wait(m_pid, status);
}

void AppProcess::terminate()
{
	const static char fname[] = "AppProcess::terminate() ";

	pid_t pid = m_pid;
	bool terminated = false;
	{
		std::lock_guard<std::recursive_mutex> guard(m_processMutex);
		if (this->running(pid))
		{
			terminated = true;
			LOG_INF << fname << "kill process <" << pid << ">.";

			ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
			if (ACE_OS::kill(-pid, SIGKILL) == 0)
			{
				// kill group success
				if (Process_Manager::instance()->remove(pid) == 0)
				{
					// removed from Process_Manager, wait outside Process_Manager
					AttachProcess(pid).wait();
				}
			}
			else
			{
				LOG_WAR << fname << "kill process group <" << pid << "> failed with error: " << std::strerror(errno);
				// use Process_Manager terminate and wait
				if (Process_Manager::instance()->terminate(pid) == 0)
				{
					Process_Manager::instance()->wait(pid);
				}
				else
				{
					// both terminate failed
					if (Process_Manager::instance()->remove(pid) == 0)
					{
						// removed from Process_Manager, wait outside Process_Manager
						ACE::terminate_process(pid);
						AttachProcess(pid).wait();
					}
				}
			}
			LOG_DBG << fname << "process <" << pid << "> killed";
		}

		CLOSE_ACE_HANDLER(m_stdoutHandler);
		CLOSE_ACE_HANDLER(m_stdinHandler);
	}
	if (terminated)
		ProcessExitHandler::terminate(pid);
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
		m_delayKillTimerId = this->registerTimer(1000L * timeout, 0, std::bind(&AppProcess::terminate, this), from);
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
		m_stdOutSizeTimerId = this->registerTimer(1000L * timeoutSec, timeoutSec, std::bind(&AppProcess::handleCheckStdout, this), fname);
		LOG_INF << fname << "register stdout check timer id: " << m_stdOutSizeTimerId;
	}
	else
	{
		LOG_ERR << fname << "already registered stdout check timer id: " << m_delayKillTimerId;
	}
}

void AppProcess::handleCheckStdout()
{
	const static char fname[] = "AppProcess::handleCheckStdout() ";

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

int AppProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile, const nlohmann::json &stdinFileContent, const int maxStdoutSize, bool sudoSwitchUser)
{
	const static char fname[] = "AppProcess::spawnProcess() ";

	// check command file existence & permission
	auto argv = Utility::str2argv(cmd);
	auto cmdRoot = argv.size() > 0 ? argv[0] : cmd;
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
		LOG_INF << fname << "Process <" << cmd << "> started with pid <" << m_pid << ">.";
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
	return m_pid;
}

pid_t AppProcess::spawn(ACE_Process_Options &option)
{
	auto pid = Process_Manager::instance()->spawn(option);
	m_pid = pid;
	if (pid != ACE_INVALID_PID)
	{
		Process_Manager::instance()->register_handler(this, pid);
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

AttachProcess::AttachProcess(pid_t pid)
{
	child_id_ = pid;
}

AttachProcess::~AttachProcess()
{
}

Process_Manager::~Process_Manager()
{
}

ACE_Recursive_Thread_Mutex &Process_Manager::mutex()
{
	return m_mutex;
}

Process_Manager *Process_Manager::instance()
{
	static Process_Manager *pm = new Process_Manager();
	return pm;
}

ProcessExitHandler::ProcessExitHandler()
	: m_exitPid(ACE_INVALID_PID), m_exitCode(ACE_INVALID_PID)
{
}

ProcessExitHandler::~ProcessExitHandler()
{
}

int ProcessExitHandler::handle_exit(ACE_Process *process)
{
	const static char fname[] = "ProcessExitHandler::handle_exit() ";
	LOG_INF << fname << "Process <" << process->getpid() << "> exit with code <" << process->return_value() << "> APP_OUT_VIEW_MAP size: " << APP_OUT_VIEW_MAP.current_size();
	// NOTE: here hold the lock: Process_Manager::instance(), avoid access app lock

	m_exitPid = process->getpid();
	m_exitCode = process->return_value();
	this->registerTimer(0, 0, std::bind(&ProcessExitHandler::handleClean, this), fname);
	return 0;
}

void ProcessExitHandler::terminate(pid_t pid)
{
	const static char fname[] = "ProcessExitHandler::terminate() ";
	LOG_INF << fname << "Process <" << pid << "> killed";

	if (pid > 1)
	{
		m_exitPid = pid;
		m_exitCode = 9;
		handleClean();
	}
}

void ProcessExitHandler::handleClean()
{
	const static char fname[] = "ProcessExitHandler::handleClean() ";

	// update exit code
	if (auto appProcess = dynamic_cast<AppProcess *>(this))
		appProcess->onExit(m_exitCode);
	else
		LOG_ERR << fname << "cast ProcessExitHandler to AppProcess failed";

	// response standby request
	ACE_Unbounded_Set<std::shared_ptr<HttpRequestOutputView>> requests;
	APP_OUT_VIEW_MAP.unbind(m_exitPid, requests);
	for (auto &req : requests)
		req->response();
}
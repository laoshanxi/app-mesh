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
#include "../../common/json.hpp"
#if defined(_WIN32)
#include "../../common/os/jobobject.hpp"
#endif
#include "../../common/os/pstree.hpp"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../application/Application.h"
#include "../rest/HttpRequest.h"
#include "AppProcess.h"
#include "LinuxCgroup.h"

constexpr const char *STDOUT_BAK_POSTFIX = ".bak";

AppProcess::AppProcess(void *owner)
	: m_owner(owner), m_timerTerminateId(INVALID_TIMER_ID), m_timerCheckStdoutId(INVALID_TIMER_ID),
	  m_stdOutMaxSize(0), m_stdinHandler(ACE_INVALID_HANDLE), m_stdoutHandler(ACE_INVALID_HANDLE),
#if defined(_WIN32)
	  m_job(nullptr, ::CloseHandle),
#endif
	  m_lastProcCpuTime(0), m_lastSysCpuTime(0), m_uuid(Utility::createUUID()),
	  m_pid(ACE_INVALID_PID), m_returnValue(-1)
{
	const static char fname[] = "AppProcess::AppProcess() ";
	LOG_DBG << fname << "Entered, ID: " << m_uuid;

	const auto inputDir = (fs::path(Configuration::instance()->getWorkDir()) / "stdin");
	m_stdinFileName = (inputDir / Utility::stringFormat("appmesh.%s.stdin", m_uuid.c_str())).string();
}

AppProcess::~AppProcess()
{
	const static char fname[] = "AppProcess::~AppProcess() ";
	LOG_DBG << fname << "Entered";

	if (this->running())
	{
		terminate();
	}

	// Utility::removeFile(m_stdoutFileName);
	Utility::removeFile(m_stdoutFileName + STDOUT_BAK_POSTFIX);
}

void AppProcess::attach(int pid, const std::string &stdoutFile)
{
	this->m_pid = pid;
	m_stdoutFileName = stdoutFile;

	CLOSE_ACE_HANDLER(m_stdoutHandler);
	std::string stdOut = Utility::stringFormat("/proc/%d/fd/1", getpid());
	m_stdoutHandler = ACE_OS::open(stdOut.c_str(), O_RDWR);
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

	// update PID
	m_pid = ACE_INVALID_PID;

	// save return code
	m_returnValue = exitCode;

	// clean OS resource
	cleanResource();

	// notify App exit event
	this->registerTimer(0, 0, std::bind(&AppProcess::onTimerAppExit, this), fname);
}

bool AppProcess::onTimerAppExit()
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
	return false;
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

bool AppProcess::onTimerTerminate()
{
	CLEAR_TIMER_ID(m_timerTerminateId);
	terminate();
	return false;
}

void AppProcess::cleanResource()
{
	CLOSE_ACE_HANDLER(m_stdoutHandler);
	CLOSE_ACE_HANDLER(m_stdinHandler);
	Utility::removeFile(m_stdinFileName);
	this->cancelTimer(m_timerCheckStdoutId);
	this->cancelTimer(m_timerTerminateId);
}

void AppProcess::terminate()
{
	const static char fname[] = "AppProcess::terminate() ";

	bool terminated = false;
	pid_t pid = m_pid.exchange(ACE_INVALID_PID);
	if (this->running(pid))
	{
		std::lock_guard<std::recursive_mutex> lock(m_processMutex);
		terminated = true;
		LOG_INF << fname << "kill process <" << pid << ">.";

		ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
#if defined(_WIN32)
		if (os::kill_job(m_job))
#else
		if (ACE_OS::kill(-pid, SIGKILL) == 0)
#endif
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
			LOG_WAR << fname << "kill process group <" << pid << "> failed with error: " << last_error_msg();
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

	cleanResource();
	if (terminated)
		ProcessExitHandler::terminate(pid);
	m_task.terminate();
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

	if (!IS_VALID_TIMER_ID(m_timerTerminateId))
	{
		m_timerTerminateId = this->registerTimer(1000L * timeout, 0, std::bind(&AppProcess::onTimerTerminate, this), from);
	}
	else
	{
		LOG_ERR << fname << "already pending for kill by timer ID: " << m_timerTerminateId;
	}
}

void AppProcess::registerCheckStdoutTimer()
{
	const static char fname[] = "AppProcess::registerCheckStdoutTimer() ";

	if (!IS_VALID_TIMER_ID(m_timerCheckStdoutId))
	{
		static const int timeoutSec = STDOUT_FILE_SIZE_CHECK_INTERVAL;
		m_timerCheckStdoutId = this->registerTimer(1000L * timeoutSec, timeoutSec, std::bind(&AppProcess::onTimerCheckStdout, this), fname);
	}
	else
	{
		LOG_ERR << fname << "already registered stdout check timer ID: " << m_timerTerminateId;
	}
}

bool AppProcess::onTimerCheckStdout()
{
	const static char fname[] = "AppProcess::onTimerCheckStdout() ";

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
				LOG_ERR << fname << "fstat failed with error : " << last_error_msg();
				CLOSE_ACE_HANDLER(m_stdoutHandler);
				auto stdOut = Utility::stringFormat("/proc/%d/fd/1", getpid());
				m_stdoutHandler = ACE_OS::open(stdOut.c_str(), O_RDWR);
			}
		}
	}

	return IS_VALID_TIMER_ID(m_timerCheckStdoutId);
}

int AppProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile, const nlohmann::json &stdinFileContent, const int maxStdoutSize)
{
	const static char fname[] = "AppProcess::spawnProcess() ";

	std::lock_guard<std::recursive_mutex> guard(m_processMutex);
	// check command file existence & permission
	auto argv = Utility::str2argv(cmd);
	auto &cmdRoot = argv.size() > 0 ? argv[0] : cmd;
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

	// AppMesh build-in env
	envMap[ENV_APPMESH_PROCESS_ID] = getuuid();
	envMap[ENV_APPMESH_LAUNCH_TIME] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
	auto app = Configuration::instance()->getApp(m_owner);
	if (app)
	{
		envMap[ENV_APPMESH_APPLICATION_NAME] = app->getName();
	}

	std::size_t cmdLength = cmd.length() + ACE_Process_Options::DEFAULT_COMMAND_LINE_BUF_LEN;
	int totalEnvSize = 0;
	int totalEnvArgs = 0;
	Utility::getEnvironmentSize(envMap, totalEnvSize, totalEnvArgs);
	ACE_Process_Options option(1, cmdLength, totalEnvSize, totalEnvArgs);
	option.command_line("%s", cmd.c_str());
	// option.avoid_zombies(1);
#if !defined(_WIN32)
	if (!user.empty() && user != "root")
	{
		unsigned int gid, uid;
		if (os::getUidByName(user, uid, gid))
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
#endif

	if (workDir.empty())
	{
		workDir = (fs::path(Configuration::instance()->getWorkDir()) / APPMESH_WORK_TMP_DIR).string();
	}
	if (fs::exists(workDir))
	{
		option.working_directory(workDir.c_str());
	}
	else
	{
		startError(Utility::stringFormat("working_directory <%s> does not exist", workDir.c_str()));
		LOG_WAR << fname << "working_directory <" << workDir << "> does not exist, use default";
	}
	std::for_each(envMap.begin(), envMap.end(), [&option](const std::pair<std::string, std::string> &pair)
				  {
					  option.setenv(pair.first.c_str(), "%s", pair.second.c_str());
					  // LOG_DBG << fname << "spawnProcess with env: " << pair.first.c_str() << "=" << pair.second.c_str();
				  });
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

		// STDOUT
		if (m_stdoutFileName.length())
		{
			m_stdoutHandler = ACE_OS::open(m_stdoutFileName.c_str(), O_CREAT | O_WRONLY | O_APPEND | O_TRUNC);
			LOG_DBG << fname << "std_out: " << m_stdoutFileName << " m_stdoutHandler: " << m_stdoutHandler;
			if (m_stdoutHandler == ACE_INVALID_HANDLE)
			{
				LOG_ERR << fname << "Failed to open file: <" << m_stdoutFileName << "> with error: " << ACE_OS::last_error();
			}
		}
		else
		{
			m_stdoutHandler = ACE_OS::open("/dev/null", O_RDWR);
		}

		// STDIN
		if (stdinFileContent != EMPTY_STR_JSON)
		{
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
		env = Utility::stringReplace(env, Utility::getHomeDir() + "/lib64:", "");
		env = Utility::stringReplace(env, Utility::getHomeDir() + "/lib64", "");
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
		LOG_ERR << fname << "Process:<" << cmd << "> start failed with error : " << last_error_msg();
		startError(Utility::stringFormat("start failed with error <%s>", last_error_msg()));
	}
	return m_pid;
}

pid_t AppProcess::spawn(ACE_Process_Options &option)
{
	const static char fname[] = "AppProcess::spawn() ";

	auto pid = Process_Manager::instance()->spawn(option);
	m_pid = pid;
	if (pid != ACE_INVALID_PID)
	{
		if (Process_Manager::instance()->register_handler(this, pid) == -1)
		{
			LOG_ERR << fname << "Failed to register process handler for PID <" << pid << ">: " << last_error_msg();
		}
#if defined(_WIN32)
		// This creates a named job object in the Windows kernel.
		// This handle must remain in scope (and open) until a running process is assigned to it.
		m_job = os::create_job(os::name_job(pid));
		os::assign_job(m_job, pid);
#endif
	}
	return pid;
}

const std::string AppProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	std::lock_guard<std::recursive_mutex> guard(m_outFileMutex);
	return JSON::localEncodingToUtf8(Utility::readFileCpp(m_stdoutFileName, position, maxSize, readLine));
}

void AppProcess::sendMessage(std::shared_ptr<void> asyncHttpRequest)
{
	m_task.sendMessage(asyncHttpRequest);
}

void AppProcess::getMessage(const std::string &processId, std::shared_ptr<void> &serverRequest, std::shared_ptr<HttpRequestWithTimeout> &msgRequest)
{
	if (processId != m_uuid)
		throw std::invalid_argument("Process ID mismatch: Illegal request.");
	m_task.getMessage(serverRequest, msgRequest);
}

void AppProcess::respMessage(const std::string &processId, std::shared_ptr<void> &serverRequest, std::shared_ptr<HttpRequestWithTimeout> &msgRequest)
{
	if (processId != m_uuid)
		throw std::invalid_argument("Process ID mismatch: Illegal request.");
	m_task.respMessage(serverRequest, msgRequest);
}

const std::string AppProcess::startError() const
{
	auto ptr = this->m_startError.load();
	return ptr ? *ptr : std::string();
}

void AppProcess::startError(const std::string &err)
{
	m_startError.store(boost::shared_ptr<std::string>(new std::string(err)));
}

std::tuple<bool, uint64_t, float, uint64_t, std::string, pid_t> AppProcess::getProcessDetails(void *ptree)
{
	auto tree = os::pstree(this->getpid(), ptree);

	auto totalMemory = tree ? tree->totalRssMemBytes() : 0;
	auto totalFileDescriptors = tree ? tree->totalFileDescriptors() : 0;
	std::string pstreeStr;
	pid_t leafPid = ACE_INVALID_PID;
	if (tree)
	{
		std::stringstream ss;
		ss << *tree;
		pstreeStr = ss.str();

		leafPid = tree->findLeafPid();
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
	return std::make_tuple(true, totalMemory, cpuUsage, totalFileDescriptors, pstreeStr, leafPid);
}

AttachProcess::AttachProcess(pid_t pid)
{
#if defined(_WIN32)
	process_info_.hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, pid);
	if (process_info_.hProcess)
		process_info_.dwProcessId = pid;
#else
	child_id_ = pid;
#endif
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
	LOG_INF << fname << "Process <" << process->getpid() << "> exited with code <" << process->return_value() << ">";

	// NOTE: here hold the lock: Process_Manager::instance(), avoid access app lock

	m_exitPid = process->getpid();
	m_exitCode = process->return_value();
	this->registerTimer(0, 0, std::bind(&ProcessExitHandler::onProcessExit, this), fname);
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
		onProcessExit();
	}
}

bool ProcessExitHandler::onProcessExit()
{
	const static char fname[] = "ProcessExitHandler::onProcessExit() ";

	// update exit code
	if (auto appProcess = dynamic_cast<AppProcess *>(this))
		appProcess->onExit(m_exitCode);
	else
		LOG_ERR << fname << "cast ProcessExitHandler to AppProcess failed";

	// response standby request
	HttpRequestOutputView::onProcessExitResponse(m_exitPid);

	return false;
}

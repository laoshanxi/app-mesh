// src/daemon/process/AppProcess.cpp
#include <ace/File_Lock.h>
#include <ace/Hash_Multi_Map_Manager_T.h>
#include <ace/Map_Manager.h>
#include <ace/OS.h>
#include <ace/OS_NS_fcntl.h>
#include <ace/Pipe.h>
#include <ace/Process_Manager.h>
#include <ace/Reactor.h>
#include <boost/filesystem.hpp>
#include <boost/smart_ptr/make_shared.hpp>

#include "../../common/Utility.h"
#if defined(_WIN32)
#include "../../common/os/jobobject.hpp"
#endif
#include "../../common/Password.h"
#include "../../common/os/pstree.h"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../application/Application.h"
#include "../rest/EventDispatcher.h"
#include "../rest/HttpRequest.h"
#include "AppProcess.h"
#include "LinuxCgroup.h"
#include "StdoutPump.h"

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/socket.h>
#endif

namespace
{
	constexpr const char *STDOUT_BAK_POSTFIX = ".bak";
}

AppProcess::AppProcess(std::weak_ptr<Application> owner)
	: m_owner(owner),
	  m_timerTerminateId(INVALID_TIMER_ID),
	  m_timerCheckStdoutId(INVALID_TIMER_ID),
	  m_stdOutMaxSize(0),
#if defined(_WIN32)
	  m_job(nullptr, ::CloseHandle),
#endif
	  m_lastProcCpuTime(0),
	  m_lastSysCpuTime(0),
	  m_uuid(Utility::shortID()),
	  m_key(generatePassword(10, true, true, true, false)),
	  m_pid(ACE_INVALID_PID),
	  m_returnValue(-1)
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

	if (running())
	{
		terminate();
	}

	// Always cleanResource() — child-already-exited path must still unregister the pump.
	cleanResource();

	// Keep main stdout file, only remove backup
	Utility::removeFile(m_stdoutFileName + STDOUT_BAK_POSTFIX);
}

void AppProcess::attach(int pid, const std::string &stdoutFile)
{
	m_pid.store(pid);
	m_stdoutFileName = stdoutFile;

#if !defined(_WIN32)
	if (pid != ACE_INVALID_PID)
	{
		const std::string stdOut = Utility::stringFormat("/proc/%d/fd/1", pid);
		m_stdoutHandler.reset(ACE_OS::open(stdOut.c_str(), O_RDWR));
		if (m_stdoutHandler.valid())
		{
			m_stdOutMaxSize = APP_STD_OUT_MAX_FILE_SIZE;
		}
	}
#endif
}

void AppProcess::detach()
{
	m_pid.store(ACE_INVALID_PID);
	m_stdoutFileName.clear();
	m_stdoutHandler.reset();
	m_stdOutMaxSize = 0;
}

pid_t AppProcess::getpid() const
{
	return m_pid.load();
}

int AppProcess::returnValue() const
{
	return m_returnValue.load();
}

void AppProcess::onExit(int exitCode)
{
	const static char fname[] = "AppProcess::onExit() ";

	// Update PID and exit code
	m_pid.store(ACE_INVALID_PID);
	m_returnValue.store(exitCode);

	// onExit runs under Process_Manager mutex; defer pump teardown spin to a timer thread.
	registerTimer(0, 0, fname, std::bind(&AppProcess::onTimerAppExit, this, exitCode));
}

bool AppProcess::onTimerAppExit(int exitCode)
{
	cleanResource();
	if (auto owner = m_owner.lock())
	{
		// Update application with exit information
		owner->onExitUpdate(exitCode);
	}
	return false;
}

bool AppProcess::running() const
{
	return running(getpid());
}

bool AppProcess::running(pid_t pid)
{
	// Check if process exists using kill signal 0
	return (pid != ACE_INVALID_PID) && (ACE_OS::kill(pid, 0) == 0 || errno != ESRCH);
}

pid_t AppProcess::wait(const ACE_Time_Value &tv, ACE_exitcode *status)
{
	// Note: Not using timed wait for Process_Manager, which would impact ProcessExitHandler::handle_exit
	const static ACE_Time_Value SHORT_INTERVAL(0, 10000); // 10 milliseconds

	if (tv != ACE_Time_Value::zero)
	{
		const auto endTime = ACE_OS::gettimeofday() + tv;
		while (running() && ACE_OS::gettimeofday() < endTime)
		{
			{
				ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
				auto result = Process_Manager::instance()->wait(m_pid.load(), ACE_Time_Value::zero, status);
				if (result > 0)
				{
					return result;
				}
			}
			ACE_OS::sleep(SHORT_INTERVAL);
		}
	}

	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
	return Process_Manager::instance()->wait(m_pid.load(), ACE_Time_Value::zero, status);
}

pid_t AppProcess::wait(ACE_exitcode *status)
{
	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
	return Process_Manager::instance()->wait(m_pid.load(), status);
}

bool AppProcess::onTimerTerminate()
{
	CLEAR_TIMER_ID(m_timerTerminateId);
	terminate();
	return false;
}

void AppProcess::cleanResource()
{
	teardownStdoutPump();
	m_stdoutHandler.reset();
	m_stdinHandler.reset();
	Utility::removeFile(m_stdinFileName);
	cancelTimer(m_timerCheckStdoutId);
	cancelTimer(m_timerTerminateId);
#if defined(_WIN32)
	cancelTimer(m_timerStdoutDispatchId);
#endif
}

void AppProcess::teardownStdoutPump()
{
	std::lock_guard<std::recursive_mutex> guard(m_processMutex);
	if (!m_stdoutPump) return;

	// Order: stop → remove_handler → cancel_timer → waitInflight → flush → snapshot bytes.
	m_stdoutPump->stop();
	ACE_Reactor::instance()->remove_handler(m_stdoutPump.get(), ACE_Event_Handler::READ_MASK | ACE_Event_Handler::DONT_CALL);
	ACE_Reactor::instance()->cancel_timer(m_stdoutPump.get());
	const bool drained = m_stdoutPump->waitInflight();
	m_stdoutPump->cancelCoalesceTimerAndFlush();
	m_lastDispatchedBytes.store(m_stdoutPump->acceptedBytes(), std::memory_order_release);
	if (!drained)
	{
		// Reactor still in upcall after timeout — leak rather than UAF.
		LOG_ERR << "AppProcess::teardownStdoutPump() handle_input in-flight after timeout; leaking pump";
		static std::mutex s_leakMutex;
		static std::vector<std::shared_ptr<StdoutPump>> s_leakedPumps;
		std::lock_guard<std::mutex> leakGuard(s_leakMutex);
		s_leakedPumps.push_back(m_stdoutPump);
	}
	m_stdoutPump.reset();
}

#if defined(_WIN32)
bool AppProcess::onTimerStdoutDispatch()
{
	auto owner = m_owner.lock();
	if (!owner) return true;
	const auto &appName = owner->getName();
	if (!EventDispatcher::instance()->hasStdoutSubscriber(appName)) return true;
	try
	{
		long pos = m_lastDispatchedBytes.load(std::memory_order_acquire);
		const long startPos = pos;
		auto result = owner->getOutput(pos, 64 * 1024, "", 0, 0);
		auto &output = std::get<0>(result);
		if (!output.empty())
		{
			nlohmann::json data;
			data["output"] = output;
			data["position"] = startPos;
			data["finished"] = std::get<1>(result);
			EventDispatcher::instance()->dispatch(appName, AppEventType::STDOUT_OUTPUT, data);
			m_lastDispatchedBytes.store(pos, std::memory_order_release);
		}
	}
	catch (const std::exception &e)
	{
		LOG_WAR << "AppProcess::onTimerStdoutDispatch() dispatch failed for app=" << appName << ": " << e.what();
	}
	return true;
}
#endif

void AppProcess::terminate()
{
	const static char fname[] = "AppProcess::terminate() ";

	bool terminated = false;
	pid_t pid = m_pid.exchange(ACE_INVALID_PID);

	if (running(pid))
	{
		std::lock_guard<std::recursive_mutex> lock(m_processMutex);
		terminated = true;
		LOG_INF << fname << "kill process <" << pid << ">.";

		ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
#if defined(_WIN32)
		const bool killSuccess = os::kill_job(m_job);
#else
		// Kill process group with negative PID
		const bool killSuccess = (ACE_OS::kill(-pid, SIGKILL) == 0);
#endif

		if (killSuccess)
		{
			// Kill group succeeded
			if (Process_Manager::instance()->remove(pid) == 0)
			{
				// Removed from Process_Manager, wait outside Process_Manager lock
				AttachProcess(pid).wait();
			}
		}
		else
		{
			LOG_WAR << fname << "kill process group <" << pid << "> failed with error: " << last_error_msg();

			// Use Process_Manager terminate and wait
			if (Process_Manager::instance()->terminate(pid) == 0)
			{
				Process_Manager::instance()->wait(pid);
			}
			else if (Process_Manager::instance()->remove(pid) == 0)
			{
				// Both terminate methods failed, try direct termination
				ACE::terminate_process(pid);
				AttachProcess(pid).wait();
			}
		}

		LOG_DBG << fname << "process <" << pid << "> killed";
	}

	cleanResource();
	if (terminated)
	{
		ProcessExitHandler::terminate(pid);
	}
}

void AppProcess::setCgroup(std::shared_ptr<ResourceLimitation> &limit)
{
	// Reference: https://blog.csdn.net/u011547375/article/details/9851455
	if (limit)
	{
		auto mbToBytes = [](long long mb) -> long long
		{ return mb > 0 ? mb * 1024LL * 1024LL : 0; };

		long long swapMb = (limit->m_memoryVirtMb > limit->m_memoryMb) ? (limit->m_memoryVirtMb - limit->m_memoryMb) : 0;
		m_cgroup = LinuxCgroup::create(mbToBytes(limit->m_memoryMb), mbToBytes(swapMb), limit->m_cpuShares);
		m_cgroup->applyLimits(limit->m_name, getpid(), ++(limit->m_index));
	}
}

const std::string &AppProcess::getuuid() const
{
	return m_uuid;
}

const std::string &AppProcess::getkey() const
{
	return m_key;
}

void AppProcess::delayKill(std::size_t timeout, const std::string &from)
{
	const static char fname[] = "AppProcess::delayKill() ";

	if (!IS_VALID_TIMER_ID(m_timerTerminateId))
	{
		m_timerTerminateId = registerTimer(1000L * timeout, 0, from, std::bind(&AppProcess::onTimerTerminate, this));
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
		static const int TIMEOUT_SEC = STDOUT_FILE_SIZE_CHECK_INTERVAL;
		m_timerCheckStdoutId = registerTimer(1000L * TIMEOUT_SEC, 1000L * TIMEOUT_SEC, fname, std::bind(&AppProcess::onTimerCheckStdout, this));
	}
	else
	{
		LOG_ERR << fname << "already registered stdout check timer ID: " << m_timerCheckStdoutId;
	}
}

bool AppProcess::onTimerCheckStdout()
{
	const static char fname[] = "AppProcess::onTimerCheckStdout() ";

	std::lock_guard<std::recursive_mutex> guard(m_processMutex);

	// Pump owns the disk fd and tracks bytes monotonically; ftruncate or fd
	// re-open would desynchronize m_lastDispatchedBytes from on-disk content.
	if (m_stdoutPump) return true;

	if (m_stdoutHandler.valid() && m_stdOutMaxSize)
	{
		ACE_stat stat;
		if (ACE_OS::fstat(m_stdoutHandler.get(), &stat) == 0)
		{
			if (stat.st_size > m_stdOutMaxSize)
			{
				// Acquire exclusive lock on the file
				ACE_File_Lock fileLock(m_stdoutHandler.get(), false);
				if (fileLock.acquire() == -1)
				{
					LOG_WAR << fname << "acquire exclusive lock on the stdout file failed: " << m_stdoutFileName;
				}

				// Copy current stdout to backup and truncate original
				// Reference: https://stackoverflow.com/questions/10195343/copy-a-file-in-a-sane-safe-and-efficient-way
				const auto backupFile = fs::path(m_stdoutFileName + STDOUT_BAK_POSTFIX);
				fs::copy_file(fs::path(m_stdoutFileName), backupFile, fs::copy_options::overwrite_existing);
				ACE_OS::ftruncate(m_stdoutHandler.get(), 0);
				fileLock.release();

				LOG_INF << fname << "file size: " << stat.st_size << " reached: " << m_stdOutMaxSize
						<< ", switched stdout file: " << m_stdoutFileName;
			}
		}
		else
		{
			LOG_ERR << fname << "fstat failed with error : " << last_error_msg();
#if !defined(_WIN32)
			// Reopen stdout file descriptor
			const auto stdOut = Utility::stringFormat("/proc/%d/fd/1", getpid());
			m_stdoutHandler.reset(ACE_OS::open(stdOut.c_str(), O_RDWR));
#endif
		}
	}

	return IS_VALID_TIMER_ID(m_timerCheckStdoutId);
}

int AppProcess::spawnProcess(std::string cmd, std::string user, std::string workDir,
							 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							 const std::string &stdoutFile, const nlohmann::json &stdinFileContent, int maxStdoutSize)
{
	const static char fname[] = "AppProcess::spawnProcess() ";

	std::lock_guard<std::recursive_mutex> guard(m_processMutex);

	// Validate command
	if (validateCommand(cmd) != 0)
	{
		return ACE_INVALID_PID;
	}

	// Prepare environment variables
	prepareEnvironment(envMap);

	std::size_t cmdLength = cmd.length() + ACE_Process_Options::DEFAULT_COMMAND_LINE_BUF_LEN;
	int totalEnvSize = 0, totalEnvArgs = 0;
	Utility::getEnvironmentSize(envMap, totalEnvSize, totalEnvArgs);

	ACE_Process_Options option(true /*inherit_environment*/, cmdLength, totalEnvSize, totalEnvArgs);
	option.command_line("%s", cmd.c_str());
	// option.avoid_zombies(1); // Not used to allow proper wait() handling

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
	option.setgroup(0); // Set group id with the process id, used to kill process group
	option.handle_inheritance(0);
#else
	option.handle_inheritance(1);
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

	// Set environment variables
	for (const auto &pair : envMap)
	{
		option.setenv(pair.first.c_str(), "%s", pair.second.c_str());
	}

	option.release_handles();

	// Clean if necessary
	m_stdoutHandler.reset();
	m_stdinHandler.reset();
	teardownStdoutPump();
	m_stdoutFileName = stdoutFile;

	// child writes stdout/stderr to pipeWriteForChild; pump reads from pipeReadForDaemon.
	ACE_HANDLE pipeWriteForChild = ACE_INVALID_HANDLE;
	ACE_HANDLE pipeReadForDaemon = ACE_INVALID_HANDLE;

	if (!m_stdoutFileName.empty() || stdinFileContent != EMPTY_STR_JSON)
	{
		// Setup STDOUT (disk sink)
		if (!m_stdoutFileName.empty())
		{
			m_stdoutHandler.reset(ACE_OS::open(m_stdoutFileName.c_str(), O_CREAT | O_WRONLY | O_TRUNC));
			LOG_DBG << fname << "std_out: " << m_stdoutFileName << " m_stdoutHandler: " << m_stdoutHandler.get();

			if (!m_stdoutHandler.valid())
			{
				LOG_ERR << fname << "Failed to open file: <" << m_stdoutFileName << "> with error: " << ACE_OS::last_error();
			}

#if !defined(_WIN32)
			// Windows ACE_Pipe is socket-based and incompatible with set_handles → legacy direct-file path.
			ACE_HANDLE pipeHandles[2] = {ACE_INVALID_HANDLE, ACE_INVALID_HANDLE};
			ACE_Pipe pipe;
			if (pipe.open(pipeHandles) == 0)
			{
				pipeReadForDaemon = pipeHandles[0];
				pipeWriteForChild = pipeHandles[1];

				// ACE_Pipe may return pipe(2) or socketpair(); try both sizing knobs (1 MB).
				bool sizedRead = false, sizedWrite = false;
				const int desiredSize = 1 << 20;
#if defined(__linux__) && defined(F_SETPIPE_SZ)
				if (::fcntl(pipeReadForDaemon, F_SETPIPE_SZ, desiredSize) >= 0) { sizedRead = sizedWrite = true; }
#endif
#if defined(SO_RCVBUFFORCE)
				if (!sizedRead && ::setsockopt(pipeReadForDaemon, SOL_SOCKET, SO_RCVBUFFORCE, &desiredSize, sizeof(desiredSize)) == 0) sizedRead = true;
#endif
				if (!sizedRead && ::setsockopt(pipeReadForDaemon, SOL_SOCKET, SO_RCVBUF, &desiredSize, sizeof(desiredSize)) == 0) sizedRead = true;
#if defined(SO_SNDBUFFORCE)
				if (!sizedWrite && ::setsockopt(pipeWriteForChild, SOL_SOCKET, SO_SNDBUFFORCE, &desiredSize, sizeof(desiredSize)) == 0) sizedWrite = true;
#endif
				if (!sizedWrite && ::setsockopt(pipeWriteForChild, SOL_SOCKET, SO_SNDBUF, &desiredSize, sizeof(desiredSize)) == 0) sizedWrite = true;
				if (!sizedRead && !sizedWrite)
					LOG_WAR << fname << "stdout pipe stays at default ~64 KB; child may stall on bursts. errno=" << ACE_OS::last_error();

				const int flags = ::fcntl(pipeReadForDaemon, F_GETFL, 0);
				if (flags < 0 || ::fcntl(pipeReadForDaemon, F_SETFL, flags | O_NONBLOCK) < 0)
					LOG_WAR << fname << "pipe O_NONBLOCK setup failed; reads may block. errno=" << ACE_OS::last_error();
			}
			else
			{
				LOG_ERR << fname << "ACE_Pipe::open failed; falling back to direct file stdout. errno=" << ACE_OS::last_error();
			}
#endif // !_WIN32
		}
		else
		{
			m_stdoutHandler.reset(ACE_OS::open(DEV_NULL, O_RDWR));
		}

		// Setup STDIN
		if (stdinFileContent != EMPTY_STR_JSON)
		{
			const std::string content = stdinFileContent.is_string()
											? stdinFileContent.get<std::string>()
											: stdinFileContent.dump();
			m_stdinFileName = os::createTmpFile(m_stdinFileName, content);
			m_stdinHandler.reset(ACE_OS::open(m_stdinFileName.c_str(), O_RDONLY)); // Open for reading by child process

			if (!m_stdinHandler.valid())
			{
				startError(Utility::stringFormat("Failed to reopen stdin file for reading <%s>", last_error_msg()));
			}
			LOG_DBG << fname << "std_in <" << m_stdinFileName << "> handler=" << m_stdinHandler.get();
		}
		else
		{
			m_stdinHandler.reset(ACE_OS::open(DEV_NULL, O_RDONLY));
		}

		// Use pipe write end if available, else direct file.
		const ACE_HANDLE childOutHandle = (pipeWriteForChild != ACE_INVALID_HANDLE) ? pipeWriteForChild : m_stdoutHandler.get();
		option.set_handles(m_stdinHandler.get(), childOutHandle, childOutHandle);
	}

	const bool spawnOk = (spawn(option) >= 0);

	// Parent closes pipe write end so reader gets EOF when child exits.
	if (pipeWriteForChild != ACE_INVALID_HANDLE)
	{
		ACE_OS::close(pipeWriteForChild);
		pipeWriteForChild = ACE_INVALID_HANDLE;
	}

	if (spawnOk)
	{
		LOG_INF << fname << "Process <" << cmd << "> started with pid <" << m_pid.load() << ">.";
		setCgroup(limit);

		if (m_stdoutHandler.valid() && maxStdoutSize)
		{
			m_stdOutMaxSize = maxStdoutSize;
		}

		m_lastDispatchedBytes.store(0, std::memory_order_release);
		if (pipeReadForDaemon != ACE_INVALID_HANDLE && m_stdoutHandler.valid())
		{
			auto owner = m_owner.lock();
			auto appName = owner ? owner->getName() : std::string();
			auto pump = std::make_shared<StdoutPump>(appName, pipeReadForDaemon, m_stdoutHandler.get(), m_outFileMutex);

			if (ACE_Reactor::instance()->register_handler(pump.get(), ACE_Event_Handler::READ_MASK) == -1)
			{
				LOG_WAR << fname << "register_handler for stdout pump failed: " << last_error_msg();
				pipeReadForDaemon = ACE_INVALID_HANDLE; // pump dtor closes it
			}
			else
			{
				std::lock_guard<std::recursive_mutex> guard(m_processMutex);
				m_stdoutPump = std::move(pump);
				pipeReadForDaemon = ACE_INVALID_HANDLE; // ownership transferred
			}
		}

#if defined(_WIN32)
		// Windows has no pump (ACE_Pipe is socket-based, incompatible with set_handles).
		// Fall back to polling the on-disk file at 1 Hz so subscribers still get events.
		if (m_stdoutHandler.valid() && !IS_VALID_TIMER_ID(m_timerStdoutDispatchId))
		{
			const long timerId = registerTimer(0, 1000, fname, std::bind(&AppProcess::onTimerStdoutDispatch, this));
			if (!IS_VALID_TIMER_ID(timerId))
				LOG_WAR << fname << "registerTimer for stdout dispatch failed; subscribers will only see exit flush";
			m_timerStdoutDispatchId = timerId;
		}
#endif
	}
	else
	{
		LOG_ERR << fname << "Process:<" << cmd << "> start failed with error : " << last_error_msg();
		startError(Utility::stringFormat("start failed with error <%s>", last_error_msg()));
	}

	if (pipeReadForDaemon != ACE_INVALID_HANDLE) // pump didn't take ownership
		ACE_OS::close(pipeReadForDaemon);

	return m_pid.load();
}

pid_t AppProcess::spawn(ACE_Process_Options &option)
{
	const static char fname[] = "AppProcess::spawn() ";

	pid_t pid = Process_Manager::instance()->spawn(option);
	if (pid == ACE_INVALID_PID)
	{
		LOG_ERR << fname << "spawn failed: " << last_error_msg();
		return pid;
	}

	m_pid.store(pid);

	// register handler (THIS is how exit is handled)
	if (Process_Manager::instance()->register_handler(this, pid) == -1)
	{
		LOG_ERR << fname << "Failed to register handler for pid=" << pid << ": " << last_error_msg();
	}

#if defined(_WIN32)
	// Create Windows job object and assign process to it
	// This handle must remain in scope until process is assigned
	m_job = os::create_job(os::name_job(pid));
	os::assign_job(m_job, pid);
#endif

	return pid;
}

const std::string AppProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	std::lock_guard<std::recursive_mutex> guard(m_outFileMutex);
	return Utility::readFileCpp(m_stdoutFileName, position, maxSize, readLine);
}

const std::string AppProcess::startError() const
{
	auto ptr = m_startError.load();
	return ptr ? *ptr : std::string();
}

void AppProcess::startError(const std::string &err)
{
	m_startError.store(boost::make_shared<std::string>(err));
}

int AppProcess::validateCommand(const std::string &cmd)
{
	const static char fname[] = "AppProcess::validateCommand() ";

	auto argv = Utility::str2argv(cmd);
	const auto &cmdRoot = argv.empty() ? cmd : argv[0];
	const bool checkCmd = (cmdRoot.find('/') != std::string::npos || cmdRoot.find('\\') != std::string::npos);

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

	return 0;
}

void AppProcess::prepareEnvironment(std::map<std::string, std::string> &envMap)
{
#if defined(_WIN32)
	// Windows: ACE setenv replaces env, so merge manually with parent environment
	const auto currentEnv = Utility::getenvs();
	for (const auto &kv : currentEnv)
	{
		if (!envMap.count(kv.first))
		{
			envMap[kv.first] = kv.second;
		}
	}
#endif

	// Add AppMesh built-in environment variables
	envMap[ENV_APPMESH_PROCESS_KEY] = m_key;
	envMap[ENV_APPMESH_LAUNCH_TIME] = std::to_string(
		std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch())
			.count());

	if (auto owner = m_owner.lock())
	{
		envMap[ENV_APPMESH_APPLICATION_NAME] = owner->getName();
	}
}

std::tuple<bool, uint64_t, float, uint64_t, std::string, pid_t> AppProcess::getProcessDetails(void *ptree)
{
	auto tree = os::pstree(getpid(), ptree);

	const auto totalMemory = tree ? tree->totalRssMemBytes() : 0;
	const auto totalFileDescriptors = tree ? tree->totalFileDescriptors() : 0;
	std::string pstreeStr;
	pid_t leafPid = ACE_INVALID_PID;

	if (tree)
	{
		std::stringstream ss;
		ss << *tree;
		pstreeStr = ss.str();
		leafPid = tree->findLeafPid();
	}

	// Calculate CPU usage
	// Reference: https://stackoverflow.com/questions/1420426/how-to-calculate-the-cpu-usage-of-a-process-by-pid-in-linux-from-c/1424556
	const auto curSysCpuTime = os::cpuTotalTime();
	const auto curProcCpuTime = tree ? tree->totalCpuTime() : 0;
	static const auto cpuNumber = os::cpus().size(); // CPU count

	float cpuUsage = 0.0f;
	std::lock_guard<std::recursive_mutex> guard(m_cpuMutex);

	// Only calculate when we have previous CPU time records
	if (m_lastSysCpuTime && curSysCpuTime && curProcCpuTime)
	{
		const auto totalTimeDiff = curSysCpuTime - m_lastSysCpuTime;
		cpuUsage = 100.0f * cpuNumber * (curProcCpuTime - m_lastProcCpuTime) / totalTimeDiff;
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
	{
		process_info_.dwProcessId = pid;
	}
#else
	child_id_ = pid;
#endif
}

ACE_Recursive_Thread_Mutex &Process_Manager::mutex()
{
	return m_mutex;
}

Process_Manager *Process_Manager::instance()
{
	static Process_Manager pm;
	return &pm;
}

int ProcessExitHandler::handle_exit(ACE_Process *process)
{
	const static char fname[] = "ProcessExitHandler::handle_exit() ";
	LOG_INF << fname << "Process <" << process->getpid() << "> exited with code <" << process->return_value() << ">";

	// NOTE: here holds the lock from Process_Manager::instance(), avoid accessing app lock

	const pid_t exitPid = process->getpid();
	const int exitCode = process->return_value();
	ProcessExitHandler::onProcessExit(exitPid, exitCode);
	return 0;
}

void ProcessExitHandler::terminate(pid_t pid)
{
	const static char fname[] = "ProcessExitHandler::terminate() ";
	LOG_INF << fname << "Process <" << pid << "> killed";

	if (pid > 1)
	{
		const int exitCode = 9;
		onProcessExit(pid, exitCode);
	}
}

bool ProcessExitHandler::onProcessExit(pid_t exitPid, int exitCode)
{
	const static char fname[] = "ProcessExitHandler::onProcessExit() ";

	// Update exit code
	if (auto appProcess = dynamic_cast<AppProcess *>(this))
	{
		appProcess->onExit(exitCode);
	}
	else
	{
		LOG_ERR << fname << "cast ProcessExitHandler to AppProcess failed";
	}

	// Response standby request
	HttpRequestOutputView::onProcessExitResponse(exitPid);
	return false;
}

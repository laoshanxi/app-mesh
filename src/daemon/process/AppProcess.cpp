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
#include "../../common/os/filesystem.h"
#if defined(_WIN32)
#include "../../common/os/jobobject.hpp"
#endif
#include "../../common/Password.h"
#include "../../common/os/pstree.h"
#include "../../common/os/user.h"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../application/Application.h"
#include "../rest/EventDispatcher.h"
#include "../rest/HttpRequest.h"
#include "AppProcess.h"
#if defined(__linux__)
#include "CgroupStartBarrier.h"
#endif
#include "LinuxCgroup.h"
#include "StdoutStrategy.h"
#include "PipeStdoutStrategy.h"
#include "TimerStdoutStrategy.h"

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace
{
	constexpr const char *STDOUT_BAK_POSTFIX = ".bak";

#if !defined(_WIN32)
	// Create a pipe for child stdout redirection. Returns {readEnd, writeEnd}
	// or {INVALID, INVALID} on failure. Attempts to size the pipe buffer to 1 MB.
	std::pair<ACE_HANDLE, ACE_HANDLE> createStdoutPipe()
	{
		const static char fname[] = "createStdoutPipe() ";
		ACE_HANDLE pipeHandles[2] = {ACE_INVALID_HANDLE, ACE_INVALID_HANDLE};
		ACE_Pipe pipe;
		if (pipe.open(pipeHandles) != 0)
		{
			LOG_ERR << fname << "ACE_Pipe::open failed, errno=" << ACE_OS::last_error();
			return {ACE_INVALID_HANDLE, ACE_INVALID_HANDLE};
		}

		bool sizedRead = false, sizedWrite = false;
		const int desiredSize = 1 << 20;
#if defined(__linux__) && defined(F_SETPIPE_SZ)
		if (::fcntl(pipeHandles[0], F_SETPIPE_SZ, desiredSize) >= 0)
		{
			sizedRead = sizedWrite = true;
		}
#endif
#if defined(SO_RCVBUFFORCE)
		if (!sizedRead && ::setsockopt(pipeHandles[0], SOL_SOCKET, SO_RCVBUFFORCE, &desiredSize, sizeof(desiredSize)) == 0)
			sizedRead = true;
#endif
		if (!sizedRead)
			::setsockopt(pipeHandles[0], SOL_SOCKET, SO_RCVBUF, &desiredSize, sizeof(desiredSize));
#if defined(SO_SNDBUFFORCE)
		if (!sizedWrite && ::setsockopt(pipeHandles[1], SOL_SOCKET, SO_SNDBUFFORCE, &desiredSize, sizeof(desiredSize)) == 0)
			sizedWrite = true;
#endif
		if (!sizedWrite)
			::setsockopt(pipeHandles[1], SOL_SOCKET, SO_SNDBUF, &desiredSize, sizeof(desiredSize));

		const int flags = ::fcntl(pipeHandles[0], F_GETFL, 0);
		if (flags < 0 || ::fcntl(pipeHandles[0], F_SETFL, flags | O_NONBLOCK) < 0)
			LOG_WAR << fname << "pipe O_NONBLOCK setup failed, errno=" << ACE_OS::last_error();

		return {pipeHandles[0], pipeHandles[1]};
	}
#endif
}

// ---------------------------------------------------------------------------
// ExitAdapter — per-process bridge registered as exit_notify_ with PM.
// One ACE reference is retained until ProcessManager calls handle_close().
// ---------------------------------------------------------------------------

class AppProcess::ExitAdapter final : public ACE_Event_Handler
{
public:
	explicit ExitAdapter(std::weak_ptr<AppProcess> target)
		: m_target(std::move(target))
	{
		reference_counting_policy().value(ACE_Event_Handler::Reference_Counting_Policy::ENABLED);
	}

	int handle_exit(ACE_Process *process) override
	{
		const static char fname[] = "ExitAdapter::handle_exit() ";
		const pid_t pid = process->getpid();
		const int code = process->return_value();
		LOG_INF << fname << "Process <" << pid << "> exited with code <" << code << ">";

		auto target = m_target.lock();
		if (target && !target->beginExit(code))
			return 0;
		auto notify = [target, pid, code]() {
			if (target)
				target->finishExit(code);
			else
				HttpRequestOutputView::onProcessExitResponse(pid);
		};
		TIMER_MANAGER::instance()->registerTimer(0, 0, fname, [notify]() {
			notify();
			return false;
		});
		return 0;
	}

	int handle_close(ACE_HANDLE, ACE_Reactor_Mask) override
	{
		const static char fname[] = "ExitAdapter::handle_close() ";
		LOG_DBG << fname << "releasing adapter";
		remove_reference();
		return 0;
	}

private:
	const std::weak_ptr<AppProcess> m_target;
};

// ---------------------------------------------------------------------------
// AppProcess
// ---------------------------------------------------------------------------

AppProcess::AppProcess(std::weak_ptr<Application> owner)
	: m_owner(owner),
	  m_timerTerminateId(INVALID_TIMER_ID),
	  m_timerCheckStdoutId(INVALID_TIMER_ID),
	  m_stdOutMaxSize(0),
	  m_outFileMutex(std::make_shared<std::recursive_mutex>()),
#if defined(_WIN32)
	  m_job(nullptr, ::CloseHandle),
#endif
	  m_lastProcCpuTime(0),
	  m_lastCpuSampleTime(),
	  m_lastMetricProcCpuTime(0),
	  m_lastMetricCpuSampleTime(),
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

	// Kill orphaned child if still alive; terminate() handles waitpid to avoid zombie.
	if (running())
		terminate();

	// Idempotent — exit finalization may have cleaned resources already.
	cleanResource();
	Utility::removeFile(m_stdoutFileName + STDOUT_BAK_POSTFIX);
}

long AppProcess::stdoutDispatchedBytes() const
{
	std::lock_guard<std::recursive_mutex> guard(m_processMutex);
	return m_stdoutStrategy ? m_stdoutStrategy->dispatchedBytes() : 0;
}

void AppProcess::attach(int pid, const std::string &stdoutFile)
{
	m_pid.store(pid);
	m_lastPid.store(pid);
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
	if (!beginExit(exitCode))
		return;
	const static char fname[] = "AppProcess::onExit() ";
	this->registerTimer(0, 0, fname, [this, exitCode]() {
		finishExit(exitCode);
		return false;
	});
}

bool AppProcess::beginExit(int exitCode)
{
	const static char fname[] = "AppProcess::onExit() ";

	// Claim and publish the observed exit while ProcessManager may still hold its mutex.
	// Cleanup and callbacks are deferred to finishExit().
	int expected = ExitPhase::Active;
	if (!m_exitPhase.compare_exchange_strong(expected, ExitPhase::Observed, std::memory_order_acq_rel))
	{
		LOG_DBG << fname << "duplicate onExit blocked by CAS guard";
		return false;
	}

	m_returnValue.store(exitCode);
	m_pid.store(ACE_INVALID_PID);
	LOG_DBG << fname << "exitCode=" << exitCode << " uuid=" << m_uuid;
	return true;
}

void AppProcess::finishExit(int exitCode)
{
	const static char fname[] = "AppProcess::finishExit() ";
	// Runs outside the ProcessManager upcall so cleanup and application callbacks may block safely.
	int expected = ExitPhase::Observed;
	if (!m_exitPhase.compare_exchange_strong(expected, ExitPhase::Finalizing, std::memory_order_acq_rel))
		return;
	LOG_DBG << fname << "uuid=" << m_uuid << " exitCode=" << exitCode;
	try
	{
		cleanResource();
	}
	catch (const std::exception &ex)
	{
		LOG_ERR << fname << "exit cleanup failed: " << ex.what();
	}
	catch (...)
	{
		LOG_ERR << fname << "exit cleanup failed";
	}
	if (auto owner = m_owner.lock())
	{
		try
		{
			owner->onExitUpdate(exitCode, !m_terminating.load(), this);
		}
		catch (const std::exception &ex)
		{
			LOG_ERR << fname << "exit update failed: " << ex.what();
		}
		catch (...)
		{
			LOG_ERR << fname << "exit update failed";
		}
	}
	// Wake output long-polls after final stdout and application state have been committed.
	HttpRequestOutputView::onProcessExitResponse(lastPid());
	m_exitPhase.store(ExitPhase::Finalized, std::memory_order_release);
}

bool AppProcess::running() const
{
	return running(getpid());
}

bool AppProcess::running(pid_t pid)
{
	return pid > 1 && (ACE_OS::kill(pid, 0) == 0 || errno != ESRCH);
}

pid_t AppProcess::wait(const ACE_Time_Value &tv, ACE_exitcode *status)
{
	const static ACE_Time_Value SHORT_INTERVAL(0, 10000);
	const pid_t pid = m_pid.load();
	if (pid <= 1)
		return ACE_INVALID_PID;

	if (tv != ACE_Time_Value::zero)
	{
		const auto endTime = ACE_OS::gettimeofday() + tv;
		while (running(pid) && ACE_OS::gettimeofday() < endTime)
		{
			{
				ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
				auto result = Process_Manager::instance()->wait(pid, ACE_Time_Value::zero, status);
				if (result > 0)
					return result;
			}
			ACE_OS::sleep(SHORT_INTERVAL);
		}
	}

	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
	return Process_Manager::instance()->wait(pid, ACE_Time_Value::zero, status);
}

pid_t AppProcess::wait(ACE_exitcode *status)
{
	const static ACE_Time_Value SHORT_INTERVAL(0, 10000);
	const pid_t pid = m_pid.load();
	if (pid <= 1)
		return ACE_INVALID_PID;

	while (true)
	{
		pid_t result;
		{
			ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
			result = Process_Manager::instance()->wait(pid, ACE_Time_Value::zero, status);
		}
		if (result != 0)
			return result;
		ACE_OS::sleep(SHORT_INTERVAL);
	}
}

bool AppProcess::onTimerTerminate()
{
	clearTimerId(m_timerTerminateId);
	terminate();
	return false;
}

void AppProcess::cleanResource()
{
	{
		std::lock_guard<std::recursive_mutex> guard(m_processMutex);
		if (m_stdoutStrategy)
			m_stdoutStrategy->teardown();
	}
	m_stdoutHandler.reset();
	m_stdinHandler.reset();
	Utility::removeFile(m_stdinFileName);
	cancelTimer(m_timerCheckStdoutId);
	cancelTimer(m_timerTerminateId);
}

void AppProcess::terminate()
{
	m_terminating.store(true, std::memory_order_release);
	terminateImpl();
}

void AppProcess::terminateImpl()
{
	const static char fname[] = "AppProcess::terminate() ";

	bool terminated = false;
	pid_t pid = m_pid.exchange(ACE_INVALID_PID);

	if (running(pid))
	{
		std::lock_guard<std::recursive_mutex> lock(m_processMutex);
		terminated = true;
		LOG_INF << fname << "kill process <" << pid << ">.";

		bool needWaitpid = false;
		{
			ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
#if defined(_WIN32)
			const bool killSuccess = os::kill_job(m_job);
#else
			// Kill the entire process group to include children.
			const bool killSuccess = (ACE_OS::kill(-pid, SIGKILL) == 0);
#endif

			if (killSuccess)
			{
				// PM::remove → remove_proc → ExitAdapter::handle_close releases the adapter.
				needWaitpid = (Process_Manager::instance()->remove(pid) == 0);
			}
			else
			{
				LOG_WAR << fname << "kill process group <" << pid << "> failed with error: " << last_error_msg();

				// Fallback: PM::terminate sends SIGTERM and reaps internally.
				if (Process_Manager::instance()->terminate(pid) == 0)
				{
					Process_Manager::instance()->wait(pid);
				}
				else if (Process_Manager::instance()->remove(pid) == 0)
				{
					ACE::terminate_process(pid);
					needWaitpid = true;
				}
			}
		}
		// Reap zombie outside PM lock to avoid blocking concurrent terminate() calls.
		// Reactor SIGCHLD may race and reap first; waitpid returns ECHILD harmlessly.
		if (needWaitpid)
		{
			AttachProcess(pid).wait();
		}

		LOG_DBG << fname << "process <" << pid << "> killed";
	}

	cleanResource();
	if (terminated && pid > 1)
	{
		// Synthetic exit notification — onExit CAS ensures no duplicate if natural exit raced.
		onExit(9);
	}
}

void AppProcess::setCgroup(const std::shared_ptr<ResourceLimitation> &limit)
{
	if (limit)
	{
		auto mbToBytes = [](long long mb) -> long long
		{ return mb > 0 ? mb * 1024LL * 1024LL : 0; };

		long long swapMb = (limit->m_memoryVirtMb > limit->m_memoryMb) ? (limit->m_memoryVirtMb - limit->m_memoryMb) : 0;
		m_cgroup = LinuxCgroup::create(
			mbToBytes(limit->m_memoryMb), mbToBytes(swapMb), limit->m_cpuShares, limit->m_memoryVirtSpecified);
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

	if (!isValidTimerId(m_timerTerminateId))
	{
		m_timerTerminateId = this->registerTimer(1000L * timeout, 0, from, std::bind(&AppProcess::onTimerTerminate, this));
	}
	else
	{
		LOG_WAR << fname << "kill already pending with timer ID <" << m_timerTerminateId << ">, ignoring duplicate request";
	}
}

void AppProcess::registerCheckStdoutTimer()
{
	const static char fname[] = "AppProcess::registerCheckStdoutTimer() ";

	if (!isValidTimerId(m_timerCheckStdoutId))
	{
		static const int TIMEOUT_SEC = STDOUT_FILE_SIZE_CHECK_INTERVAL;
		m_timerCheckStdoutId = this->registerTimer(1000L * TIMEOUT_SEC, TIMEOUT_SEC, fname, std::bind(&AppProcess::onTimerCheckStdout, this));
	}
	else
	{
		LOG_WAR << fname << "stdout check timer already registered with ID <" << m_timerCheckStdoutId << ">, ignoring duplicate request";
	}
}

bool AppProcess::onTimerCheckStdout()
{
	const static char fname[] = "AppProcess::onTimerCheckStdout() ";

	std::lock_guard<std::recursive_mutex> guard(m_processMutex);

	if (m_stdoutStrategy && m_stdoutStrategy->isActive())
		return isValidTimerId(m_timerCheckStdoutId);

	if (m_stdoutHandler.valid() && m_stdOutMaxSize)
	{
		ACE_stat stat;
		if (ACE_OS::fstat(m_stdoutHandler.get(), &stat) == 0)
		{
			if (stat.st_size > m_stdOutMaxSize)
			{
				ACE_File_Lock fileLock(m_stdoutHandler.get(), false);
				if (fileLock.acquire() == -1)
				{
					LOG_WAR << fname << "Failed to acquire exclusive lock on stdout file <" << m_stdoutFileName << ">: " << last_error_msg();
				}

				const auto backupFile = fs::path(m_stdoutFileName + STDOUT_BAK_POSTFIX);
				fs::copy_file(fs::path(m_stdoutFileName), backupFile, fs::copy_options::overwrite_existing);
				ACE_OS::ftruncate(m_stdoutHandler.get(), 0);
				fileLock.release();

				LOG_INF << fname << "stdout file <" << m_stdoutFileName << "> size <" << stat.st_size << "> reached limit <" << m_stdOutMaxSize << ">, backed up and truncated";
			}
		}
		else
		{
			LOG_WAR << fname << "fstat on stdout file <" << m_stdoutFileName << "> failed, reopening handle: " << last_error_msg();
#if !defined(_WIN32)
			const auto stdOut = Utility::stringFormat("/proc/%d/fd/1", getpid());
			m_stdoutHandler.reset(ACE_OS::open(stdOut.c_str(), O_RDWR));
#endif
		}
	}

	return isValidTimerId(m_timerCheckStdoutId);
}

int AppProcess::spawnProcess(std::string cmd, std::string user, std::string workDir,
							 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							 const std::string &stdoutFile, const nlohmann::json &stdinFileContent, int maxStdoutSize)
{
	const static char fname[] = "AppProcess::spawnProcess() ";

	std::lock_guard<std::recursive_mutex> guard(m_processMutex);

	if (validateCommand(cmd) != 0)
		return ACE_INVALID_PID;

	prepareEnvironment(envMap);

	std::size_t cmdLength = cmd.length() + ACE_Process_Options::DEFAULT_COMMAND_LINE_BUF_LEN;
	int totalEnvSize = 0, totalEnvArgs = 0;
	Utility::getEnvironmentSize(envMap, totalEnvSize, totalEnvArgs);

	ACE_Process_Options option(true, cmdLength, totalEnvSize, totalEnvArgs);
	option.command_line("%s", cmd.c_str());

#if !defined(_WIN32)
	if (!user.empty() && user != "root")
	{
		unsigned int gid, uid;
		if (os::getUidByName(user, uid, gid))
		{
			if (uid == 0)
			{
				startError(Utility::stringFormat("exec_user <%s> resolved to root (uid=0), which is not permitted", user.c_str()));
				return ACE_INVALID_PID;
			}
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
	option.setgroup(0);
	// ACE preserves redirected stdio and marks every other child fd close-on-exec.
	option.handle_inheritance(0);
#else
	// ACE requires inheritance for redirected standard handles on Windows.
	option.handle_inheritance(1);
#endif

	if (workDir.empty())
		workDir = (fs::path(Configuration::instance()->getWorkDir()) / APPMESH_WORK_TMP_DIR).string();

	if (fs::exists(workDir))
		option.working_directory(workDir.c_str());
	else
	{
		startError(Utility::stringFormat("working_directory <%s> does not exist", workDir.c_str()));
		LOG_WAR << fname << "working_directory <" << workDir << "> does not exist, using default";
	}

	for (const auto &pair : envMap)
		option.setenv(pair.first.c_str(), "%s", pair.second.c_str());

	option.release_handles();

	// Clean prior state
	m_stdoutHandler.reset();
	m_stdinHandler.reset();
	if (m_stdoutStrategy)
		m_stdoutStrategy->teardown();
	m_stdoutStrategy.reset();
	m_stdoutFileName = stdoutFile;

	ACE_HANDLE pipeWriteForChild = ACE_INVALID_HANDLE;
	ACE_HANDLE pipeReadForDaemon = ACE_INVALID_HANDLE;

	if (!m_stdoutFileName.empty() || stdinFileContent != EMPTY_STR_JSON)
	{
		if (!m_stdoutFileName.empty())
		{
			m_stdoutHandler.reset(ACE_OS::open(m_stdoutFileName.c_str(), O_CREAT | O_WRONLY | O_TRUNC));
			LOG_DBG << fname << "std_out: " << m_stdoutFileName << " m_stdoutHandler: " << m_stdoutHandler.get();

			if (!m_stdoutHandler.valid())
				LOG_ERR << fname << "Failed to open stdout file <" << m_stdoutFileName << ">: " << last_error_msg();

#if !defined(_WIN32)
			auto pipeFds = createStdoutPipe();
			pipeReadForDaemon = pipeFds.first;
			pipeWriteForChild = pipeFds.second;
#endif
		}
		else
		{
			m_stdoutHandler.reset(ACE_OS::open(DEV_NULL, O_RDWR));
		}

		if (stdinFileContent != EMPTY_STR_JSON)
		{
			const std::string content = stdinFileContent.is_string()
											? stdinFileContent.get<std::string>()
											: stdinFileContent.dump();
			m_stdinFileName = os::createTmpFile(m_stdinFileName, content, 0600);
			m_stdinHandler.reset(ACE_OS::open(m_stdinFileName.c_str(), O_RDONLY));

			if (!m_stdinHandler.valid())
				startError(Utility::stringFormat("Failed to reopen stdin file for reading <%s>", last_error_msg()));
			LOG_DBG << fname << "std_in <" << m_stdinFileName << "> handler=" << m_stdinHandler.get();
		}
		else
		{
			m_stdinHandler.reset(ACE_OS::open(DEV_NULL, O_RDONLY));
		}

		const ACE_HANDLE childOutHandle = (pipeWriteForChild != ACE_INVALID_HANDLE) ? pipeWriteForChild : m_stdoutHandler.get();
		option.set_handles(m_stdinHandler.get(), childOutHandle, childOutHandle);
	}

	bool spawnOk = (spawn(option, limit) >= 0);

	if (pipeWriteForChild != ACE_INVALID_HANDLE)
	{
		ACE_OS::close(pipeWriteForChild);
		pipeWriteForChild = ACE_INVALID_HANDLE;
	}

	if (spawnOk)
	{
		LOG_INF << fname << "Process <" << cmd << "> started with pid <" << m_pid.load() << ">.";

		if (m_stdoutHandler.valid() && maxStdoutSize)
			m_stdOutMaxSize = maxStdoutSize;

		auto owner = m_owner.lock();
		auto appName = owner ? owner->getName() : std::string();
		m_stdoutStrategy = StdoutStrategy::create(std::move(appName), pipeReadForDaemon, m_stdoutHandler.get(), m_outFileMutex, m_owner);
		// PipeStdoutStrategy owns the fd even when registration failed (pump dtor
		// closes it) — closing here too would double-close a recycled fd.
		if (dynamic_cast<PipeStdoutStrategy *>(m_stdoutStrategy.get()))
			pipeReadForDaemon = ACE_INVALID_HANDLE;
		if (auto *ts = dynamic_cast<TimerStdoutStrategy *>(m_stdoutStrategy.get()))
			ts->startTimer(*this, m_uuid);
	}
	else
	{
		if (startError().empty())
			startError(Utility::stringFormat("start failed with error <%s>", last_error_msg()));
		LOG_ERR << fname << "Process <" << cmd << "> " << startError();
	}

	if (pipeReadForDaemon != ACE_INVALID_HANDLE)
		ACE_OS::close(pipeReadForDaemon);

	return m_pid.load();
}

pid_t AppProcess::spawn(ACE_Process_Options &option, const std::shared_ptr<ResourceLimitation> &limit)
{
	const static char fname[] = "AppProcess::spawn() ";

	// Transfer one adapter reference to ProcessManager after a successful spawn.
	auto adapter = ACE::make_event_handler<ExitAdapter>(std::dynamic_pointer_cast<AppProcess>(shared_from_this()));
	ACE_Event_Handler_var processManagerRef(adapter);

	pid_t pid = ACE_INVALID_PID;
#if defined(__linux__)
	const bool limitsRequested = limit &&
		(limit->m_memoryMb > 0 || limit->m_memoryVirtSpecified || limit->m_cpuShares > 0);
	std::unique_ptr<CgroupStartBarrier> startBarrier;
	bool barrierReleased = true;
	bool startupUnregistered = false;
#endif
	{
		ACE_Guard<ACE_Recursive_Thread_Mutex> guard(Process_Manager::instance()->mutex());
#if defined(__linux__)
		if (limitsRequested)
		{
			startBarrier = std::make_unique<CgroupStartBarrier>([this, limit](pid_t childPid) {
				m_pid.store(childPid);
				m_lastPid.store(childPid);
				try
				{
					setCgroup(limit);
					return true;
				}
				catch (const std::exception &ex)
				{
					m_terminating.store(true, std::memory_order_release);
					startError(Utility::stringFormat("cgroup setup failed <%s>", ex.what()));
					return false;
				}
				catch (...)
				{
					m_terminating.store(true, std::memory_order_release);
					startError("cgroup setup failed");
					return false;
				}
			});
			pid = Process_Manager::instance()->spawn(startBarrier->managedProcess(), option, adapter.handler());
		}
		else
#endif
		{
			pid = Process_Manager::instance()->spawn(option, adapter.handler());
		}
		if (pid != ACE_INVALID_PID)
			processManagerRef.release();

#if defined(__linux__)
		if (pid != ACE_INVALID_PID)
		{
			// ACE owns the managed process after registration.
			barrierReleased = !startBarrier || startBarrier->releaseAfterRegistration();
			if (!barrierReleased)
			{
				m_terminating.store(true, std::memory_order_release);
				if (startError().empty())
					startError("cgroup startup barrier failed");
				startupUnregistered = Process_Manager::instance()->remove(pid) == 0;
				if (!startupUnregistered)
					LOG_ERR << fname << "failed to unregister process <" << pid << "> after startup failure";
			}
			if (!barrierReleased && startupUnregistered)
			{
				m_pid.store(ACE_INVALID_PID);
				m_lastPid.store(ACE_INVALID_PID);
			}
			else
			{
				m_pid.store(pid);
				m_lastPid.store(pid);
			}
		}
#else
		if (pid != ACE_INVALID_PID)
		{
			m_pid.store(pid);
			m_lastPid.store(pid);
		}
#endif
	}
	if (pid == ACE_INVALID_PID)
	{
		LOG_ERR << fname << "spawn failed: " << last_error_msg();
#if defined(__linux__)
		const pid_t forkedPid = m_pid.exchange(ACE_INVALID_PID);
		m_lastPid.store(ACE_INVALID_PID);
		if (startBarrier)
			startBarrier->abort();
		if (forkedPid != ACE_INVALID_PID)
			AttachProcess(forkedPid).wait();
#endif
		return pid;
	}

#if defined(__linux__)
	if (!barrierReleased)
	{
		if (startupUnregistered)
		{
			AttachProcess(pid).wait();
			return ACE_INVALID_PID;
		}
		LOG_ERR << fname << startError();
		return pid;
	}
#endif

#if defined(_WIN32)
	m_job = os::create_job(os::name_job(pid));
	os::assign_job(m_job, pid);
#endif

	return pid;
}

const std::string AppProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	std::lock_guard<std::recursive_mutex> guard(*m_outFileMutex);
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
	const auto currentEnv = Utility::getenvs();
	for (const auto &kv : currentEnv)
	{
		if (!envMap.count(kv.first))
			envMap[kv.first] = kv.second;
	}
#endif

	envMap[ENV_APPMESH_PROCESS_KEY] = m_key;
	envMap[ENV_APPMESH_LAUNCH_TIME] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());

	if (auto owner = m_owner.lock())
		envMap[ENV_APPMESH_APPLICATION_NAME] = owner->getName();
}

std::tuple<bool, uint64_t, float, uint64_t, std::string, pid_t> AppProcess::getProcessDetails(
	void *ptree, bool includeTreeString, bool metricsSample)
{
	const static char fname[] = "AppProcess::getProcessDetails() ";
	// Serialize CPU baseline updates.
	std::lock_guard<std::recursive_mutex> guard(m_cpuMutex);
	try
	{
		auto tree = os::pstree(getpid(), ptree);

		const auto totalMemory = tree ? tree->totalRssMemBytes() : 0;
		const auto totalFileDescriptors = tree ? tree->totalFileDescriptors() : 0;
		std::string pstreeStr;
		pid_t leafPid = ACE_INVALID_PID;

		if (tree)
		{
			if (includeTreeString)
			{
				std::stringstream ss;
				ss << *tree;
				pstreeStr = ss.str();
			}
			leafPid = tree->findLeafPid();
		}
		else
		{
			return std::make_tuple(false, static_cast<uint64_t>(0), 0.0f,
				static_cast<uint64_t>(0), std::string(), static_cast<pid_t>(ACE_INVALID_PID));
		}

		const auto curSampleTime = std::chrono::steady_clock::now();
		const auto curProcCpuTime = tree->totalCpuTime();
		double cpuTimeUnitsPerSecond = 1000.0; // Windows process times are stored as milliseconds.
#if defined(__APPLE__)
		cpuTimeUnitsPerSecond = 1000000000.0; // proc_taskinfo total times are nanoseconds.
#elif defined(__linux__)
		const auto clockTicks = ACE_OS::sysconf(_SC_CLK_TCK);
		cpuTimeUnitsPerSecond = clockTicks > 0 ? static_cast<double>(clockTicks) : 100.0;
#endif

		// Prometheus and runtime reads use independent deltas so API traffic cannot distort metrics.
		auto &lastProcCpuTime = metricsSample ? m_lastMetricProcCpuTime : m_lastProcCpuTime;
		auto &lastCpuSampleTime = metricsSample ? m_lastMetricCpuSampleTime : m_lastCpuSampleTime;
		float cpuUsage = 0.0f;
		if (lastCpuSampleTime.time_since_epoch().count() > 0 &&
			curProcCpuTime >= lastProcCpuTime && cpuTimeUnitsPerSecond > 0)
		{
			const auto elapsedSeconds = std::chrono::duration<double>(curSampleTime - lastCpuSampleTime).count();
			if (elapsedSeconds > 0)
				cpuUsage = static_cast<float>(100.0 *
					(static_cast<double>(curProcCpuTime - lastProcCpuTime) / cpuTimeUnitsPerSecond) /
					elapsedSeconds);
		}

		lastProcCpuTime = curProcCpuTime;
		lastCpuSampleTime = curSampleTime;

		return std::make_tuple(true, totalMemory, cpuUsage, totalFileDescriptors, pstreeStr, leafPid);
	}
	catch (const std::exception &e)
	{
		// A monitored child can exit mid-sweep, making a /proc read fail (e.g. ESRCH /
		// truncated read -> "basic_filebuf::underflow"). Same benign "process gone" race as
		// the null-tree case: report failure so get_app/enable/metrics skip runtime details
		// instead of surfacing a 412 to the client.
		LOG_WAR << fname << "proc-read race, skipping runtime details: " << e.what();
		return std::make_tuple(false, static_cast<uint64_t>(0), 0.0f, static_cast<uint64_t>(0), std::string(), static_cast<pid_t>(ACE_INVALID_PID));
	}
}

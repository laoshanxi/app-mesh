// src/daemon/process/AppProcess.cpp
#include "AppProcess.h"

#include <algorithm>
#include <cctype>
#include <condition_variable>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <filesystem>
#include <boost/process/v2/environment.hpp>
#include <boost/process/v2/process.hpp>
#include <boost/process/v2/start_dir.hpp>
#include <boost/process/v2/stdio.hpp>
#if !defined(_WIN32)
#include <boost/process/v2/posix/bind_fd.hpp>
#include <boost/process/v2/posix/vfork_launcher.hpp>
#endif

#include "../../common/Password.h"
#include "../../common/Utility.h"
#include "../../common/json.h"
#include "../../common/os/filesystem.h"
#if defined(_WIN32)
#include "../../common/os/jobobject.hpp"
#endif
#include "../../common/os/process.h"
#include "../../common/os/pstree.h"
#include "../../common/os/user.h"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../application/Application.h"
#include "LinuxCgroup.h"
#include "ProcessService.h"
#include "SpawnInitializers.h"
#include "StdoutStrategy.h"

namespace bp2 = boost::process::v2;

namespace
{
	constexpr const char *STDOUT_BAK_POSTFIX = ".bak";

#if !defined(_WIN32)
	// Create a pipe for child stdout redirection. Returns {readEnd, writeEnd}
	// or {-1, -1} on failure. Buffer sizing is Linux-only.
	std::pair<int, int> createStdoutPipe()
	{
		const static char fname[] = "createStdoutPipe() ";
		int pipeFds[2] = {-1, -1};
		if (::pipe(pipeFds) != 0)
		{
			LOG_ERR << fname << "pipe failed, errno=" << errno;
			return {-1, -1};
		}

#if defined(__linux__) && defined(F_SETPIPE_SZ)
		// Best effort; the default pipe size is fine.
		::fcntl(pipeFds[0], F_SETPIPE_SZ, 1 << 20);
#endif
		const int flags = ::fcntl(pipeFds[0], F_GETFL, 0);
		if (flags < 0 || ::fcntl(pipeFds[0], F_SETFL, flags | O_NONBLOCK) < 0)
			LOG_WAR << fname << "pipe O_NONBLOCK setup failed, errno=" << errno;

		return {pipeFds[0], pipeFds[1]};
	}
#endif

	// Resolve argv[0] the way the spawn API would: paths pass through, bare
	// names search the daemon's PATH. Returns "" when no candidate exists.
	std::string resolveExecutablePath(const std::string &command)
	{
		if (command.find('/') != std::string::npos
#if defined(_WIN32)
			|| command.find('\\') != std::string::npos
#endif
		)
			return command;

		const char *pathEnv = ::getenv("PATH");
		std::string search = (pathEnv && *pathEnv) ? pathEnv : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
		search +=
#if defined(_WIN32)
			';';
#else
			':';
#endif
		std::size_t pos = 0;
		while (pos < search.size())
		{
			const auto sep = search.find(search.back(), pos);
			const auto dir = search.substr(pos, sep == std::string::npos ? std::string::npos : sep - pos);
			pos = (sep == std::string::npos) ? search.size() : sep + 1;
			// An empty PATH element means the current directory.
			const auto candidate = dir.empty() ? ("./" + command) : (dir + "/" + command);
#if defined(_WIN32)
			// The CRT has no execute bit: existence is the check.
			if (Utility::isFileExist(candidate))
				return candidate;
#else
			if (::access(candidate.c_str(), X_OK) == 0)
				return candidate;
#endif
		}
		return {};
	}

	// Merge the daemon environment with the app overrides into "K=V" strings;
	// the BPv2 launcher replaces the child environment instead of inheriting.
#if defined(_WIN32)
	using EnvStrings = std::vector<std::wstring>;
#else
	using EnvStrings = std::vector<std::string>;
#endif
	EnvStrings buildChildEnvironment(const std::map<std::string, std::string> &envMap)
	{
		auto merged = Utility::getenvs();
		for (const auto &[key, value] : envMap)
			merged[key] = value;

		std::vector<std::string> env;
		env.reserve(merged.size());
		for (const auto &[key, value] : merged)
			env.push_back(key + "=" + value);
#if defined(_WIN32)
		EnvStrings envWide;
		envWide.reserve(env.size());
		for (const auto &kv : env)
			envWide.push_back(fs::path(kv).wstring());
		return envWide;
#else
		return env;
#endif
	}

// The handle guards store HANDLEs on Windows: open must return one there,
// not a CRT descriptor that CloseHandle would corrupt.
native_fd openStdioFile(const char *path, bool readOnly) {
#if defined(_WIN32)
    const DWORD access = readOnly ? GENERIC_READ : GENERIC_WRITE;
    const DWORD disposition = readOnly ? OPEN_EXISTING : CREATE_ALWAYS;
    const HANDLE handle = ::CreateFileW(fs::path(path).wstring().c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    return (handle == INVALID_HANDLE_VALUE) ? INVALID_FD : handle;
#else
    return readOnly ? ::open(path, O_RDONLY) : ::open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
#endif
}

#if !defined(_WIN32)
	// Wrap one command-line token so its value stays a single argv element.
	// The daemon spawns without a shell: str2argv strips quotes wherever they
	// appear and only quote-protected text survives tokenization, so the quotes
	// must enclose the whole token.
	std::string quoteArgvToken(const std::string &value)
	{
		return "'" + value + "'";
	}

	bool isValidEnvName(const std::string &name)
	{
		if (name.empty() || !(std::isalpha(static_cast<unsigned char>(name[0])) || name[0] == '_'))
			return false;
		return std::all_of(name.begin(), name.end(), [](unsigned char c) {
			return std::isalnum(c) || c == '_';
		});
	}

	// sudo --login runs the command through a login shell and sudo's env_reset
	// drops the daemon-provided environment; re-inject it via the env command so
	// the protocol keys (APPMESH_PROCESS_KEY, PSK_SHM_NAME, ...) and the app
	// environment survive the switch.
	std::string wrapSudoLoginCommand(const std::string &sudoUser, const std::map<std::string, std::string> &envMap, const std::string &cmd)
	{
		const static char fname[] = "wrapSudoLoginCommand() ";
		std::string envArgs;
		for (const auto &[name, value] : envMap)
		{
			if (!isValidEnvName(name))
			{
				LOG_WAR << fname << "Skipping invalid environment variable name <" << name << ">";
				continue;
			}
			envArgs += quoteArgvToken(name + "=" + value) + " ";
		}
		return Utility::stringFormat("/usr/bin/sudo --login %s env %s%s", quoteArgvToken("--user=" + sudoUser).c_str(), envArgs.c_str(), cmd.c_str());
	}
#endif
}

struct AppProcess::Lifecycle
{
	enum ExitPhase
	{
		Active,
		Observed,
		Finalized
	};
	enum class StartPhase
	{
		Pending,
		Publishing,
		Accepted
	};

	std::atomic<ExitPhase> exitPhase{ExitPhase::Active};
	std::atomic<bool> terminating{false};

	mutable std::mutex mutex;
	std::condition_variable completionCv;
	// Set together with the finalization hand-off; guards against a second
	// onExit posting finalizeExit twice.
	bool finalizeScheduled{false};
	StartPhase startPhase{StartPhase::Pending};
	std::string startError;
};

// ---------------------------------------------------------------------------
// AppProcess
// ---------------------------------------------------------------------------

AppProcess::AppProcess(std::weak_ptr<Application> owner)
	: m_owner(owner),
	  m_timerTerminateId(INVALID_TIMER_ID),
	  m_timerCheckStdoutId(INVALID_TIMER_ID),
	  m_stdOutMaxSize(0),
	  m_outFileMutex(std::make_shared<std::mutex>()),
#if defined(_WIN32)
	  m_job(nullptr, ::CloseHandle),
#endif
	  m_lastProcCpuTime(0),
	  m_lastCpuSampleTime(),
	  m_lastMetricProcCpuTime(0),
	  m_lastMetricCpuSampleTime(),
	  m_uuid(Utility::shortID()),
	  m_key(generatePassword(10, true, true, true, false)),
	  m_pid(INVALID_PID),
	  m_lastPid(INVALID_PID),
	  m_processStartToken(0),
	  m_recovered(false),
	  m_returnValue(-1),
	  m_lifecycle(std::make_unique<Lifecycle>())
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

	// No shared owner remains, so kill/reap directly instead of queuing an exit
	// callback that would require shared_from_this().
	if (running())
	{
		m_lifecycle->terminating.store(true, std::memory_order_release);
		terminateImpl();
	}

	// Idempotent — exit finalization may have cleaned resources already.
	cleanupResources();
	Utility::removeFile(m_stdoutFileName + STDOUT_BAK_POSTFIX);
}

void AppProcess::attach(int pid, const std::string &stdoutFile)
{
	std::lock_guard guard(m_processMutex);
	m_pid.store(pid);
	m_lastPid = pid;
	if (const auto status = os::status(pid))
		m_processStartToken = status->starttime;
	else
		m_processStartToken = 0;
	m_stdoutFileName = stdoutFile;

#if !defined(_WIN32)
	if (pid != INVALID_PID)
	{
		const std::string stdOut = Utility::stringFormat("/proc/%d/fd/1", pid);
		m_stdoutHandler.reset(::open(stdOut.c_str(), O_RDWR));
		if (m_stdoutHandler.valid())
		{
			m_stdOutMaxSize = APP_STD_OUT_MAX_FILE_SIZE;
		}
	}
#endif
}

void AppProcess::detach()
{
	std::lock_guard guard(m_processMutex);
	m_pid.store(INVALID_PID);
	m_processStartToken = 0;
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

void AppProcess::markRecovered()
{
	m_recovered = true;
}

bool AppProcess::isRecovered() const
{
	return m_recovered;
}

pid_t AppProcess::lastPid() const
{
	std::lock_guard guard(m_processMutex);
	return m_lastPid;
}

void AppProcess::onExit(int exitCode)
{
	const static char fname[] = "AppProcess::onExit() ";

	// Publish the result before Observed. The lifecycle lock prevents a duplicate
	// reporter or start publication from scheduling finalization with a stale code.
	bool shouldFinalize = false;
	{
		std::lock_guard guard(m_lifecycle->mutex);
		const auto phase = m_lifecycle->exitPhase.load(std::memory_order_relaxed);
		if (phase == Lifecycle::ExitPhase::Active)
		{
			m_returnValue.store(exitCode, std::memory_order_relaxed);
			m_pid.store(INVALID_PID, std::memory_order_relaxed);
			m_lifecycle->exitPhase.store(Lifecycle::ExitPhase::Observed, std::memory_order_release);
		}
		else if (phase != Lifecycle::ExitPhase::Observed)
		{
			LOG_DBG << fname << "duplicate onExit blocked by exit-phase guard";
			return;
		}
		if (m_lifecycle->startPhase == Lifecycle::StartPhase::Accepted && !m_lifecycle->finalizeScheduled)
		{
			m_lifecycle->finalizeScheduled = true;
			shouldFinalize = true;
		}
	}

	const int observedExitCode = m_returnValue.load(std::memory_order_acquire);
	LOG_DBG << fname << "exitCode=" << observedExitCode << " uuid=" << m_uuid;
	if (!shouldFinalize)
		return;

	// Hand off only after releasing the lifecycle lock: finalizeExit runs on
	// the ProcessService thread, serialized with every other finalization
	// source (terminate, maintainRuntime), and may cancel this process's
	// timers and block in application callbacks safely.
	auto self = std::dynamic_pointer_cast<AppProcess>(shared_from_this());
	PROCESS_SERVICE::instance()->post([self]()
									   { self->finalizeExit(); });
}

void AppProcess::resolveStart(bool accepted, pid_t pid)
{
	{
		std::lock_guard guard(m_lifecycle->mutex);
		if (m_lifecycle->startPhase != Lifecycle::StartPhase::Pending ||
			m_lifecycle->exitPhase.load(std::memory_order_relaxed) == Lifecycle::ExitPhase::Finalized)
			return;
		if (!accepted)
		{
			m_lifecycle->exitPhase.store(Lifecycle::ExitPhase::Finalized, std::memory_order_release);
			m_lifecycle->completionCv.notify_all();
			return;
		}
		m_lifecycle->startPhase = Lifecycle::StartPhase::Publishing;
	}

	if (auto owner = m_owner.lock())
	{
		try
		{
			owner->onStartAccepted(m_uuid, pid);
		}
		catch (...)
		{
			// The publication gate must still open or an already-exited process can wait forever.
			LOG_CRT << "AppProcess::resolveStart() FATAL: start publication failed for <" << m_uuid << ">";
		}
	}
	{
		std::lock_guard guard(m_processMutex);
		if (m_stdoutStrategy)
			m_stdoutStrategy->activate(*this, m_uuid);
	}

	{
		std::lock_guard guard(m_lifecycle->mutex);
		m_lifecycle->startPhase = Lifecycle::StartPhase::Accepted;
	}
	if (m_lifecycle->exitPhase.load(std::memory_order_acquire) == Lifecycle::ExitPhase::Observed)
		onExit(m_returnValue.load(std::memory_order_acquire));
}

bool AppProcess::isStartAccepted() const
{
	std::lock_guard guard(m_lifecycle->mutex);
	return m_lifecycle->startPhase == Lifecycle::StartPhase::Accepted;
}

void AppProcess::reportEarlyExit(int exitCode)
{
	resolveStart(true, INVALID_PID);
	onExit(exitCode);
}

void AppProcess::finalizeExit() noexcept
{
	const static char fname[] = "AppProcess::finalizeExit() ";
	// Engine part on the ProcessService io thread: drain the stdout pump and
	// release owned resources.
	const int exitCode = m_returnValue.load(std::memory_order_acquire);
	long stdoutDispatchedBytes = 0;
	try
	{
		LOG_DBG << fname << "uuid=" << m_uuid << " exitCode=" << exitCode;
		try
		{
			stdoutDispatchedBytes = cleanupResources();
		}
		catch (...)
		{
			LOG_CRT << fname << "FATAL: exit cleanup failed for <" << m_uuid << ">";
		}
	}
	catch (...)
	{
		// Swallow so finalization below still runs.
	}
	if (m_owner.expired())
	{
		// Helper runs (docker CLI, cleanup, health checks) have no application
		// callbacks. Finalize on the engine thread: their callers wait for
		// Finalized and may themselves run on the callback thread.
		{
			const std::lock_guard guard(m_lifecycle->mutex);
			m_lifecycle->exitPhase.store(Lifecycle::ExitPhase::Finalized, std::memory_order_release);
		}
		m_lifecycle->completionCv.notify_all();
		return;
	}
	// Application callbacks may block on docker backends: run them on the
	// callback thread so they cannot stall the engine.
	auto self = std::dynamic_pointer_cast<AppProcess>(shared_from_this());
	const bool naturalExit = !m_lifecycle->terminating.load();
	auto finalizeAppSide = [self, exitCode, naturalExit, stdoutDispatchedBytes]()
	{
		std::shared_ptr<Application> owner;
		try
		{
			owner = self->m_owner.lock();
			if (owner)
				owner->recordProcessExit(exitCode, naturalExit, self.get(), stdoutDispatchedBytes);
		}
		catch (...)
		{
			LOG_CRT << "AppProcess::finalizeExit() FATAL: exit update failed for <" << self->getuuid() << ">";
		}
		{
			const std::lock_guard guard(self->m_lifecycle->mutex);
			self->m_lifecycle->exitPhase.store(Lifecycle::ExitPhase::Finalized, std::memory_order_release);
		}
		self->m_lifecycle->completionCv.notify_all();
		if (owner)
		{
			try
			{
				owner->completeRun(self->getuuid());
			}
			catch (...)
			{
				LOG_CRT << "AppProcess::finalizeExit() FATAL: completion notification failed for <" << self->getuuid() << ">";
			}
		}
	};
	try
	{
		PROCESS_SERVICE::instance()->postCallback(finalizeAppSide);
	}
	catch (...)
	{
		// The callback queue is unavailable; finalize inline so waiters are released.
		LOG_CRT << fname << "FATAL: callback queue unavailable for <" << m_uuid << ">, finalizing inline";
		finalizeAppSide();
	}
}

bool AppProcess::running() const
{
	// attach()/startImpl()/terminateImpl() publish PID and start token while
	// holding this mutex. onExit() invalidates only the PID without it, which
	// just makes these checks fail sooner: a reader never pairs a live PID with
	// a token from another run.
	std::lock_guard guard(m_processMutex);
	return sameProcessRunning(m_pid.load(std::memory_order_relaxed), m_processStartToken);
}

bool AppProcess::sameProcessRunning(pid_t pid, std::uint64_t expectedStart)
{
	if (pid > 1 && expectedStart != 0)
	{
		const auto status = os::status(pid);
		return status && status->state != 'Z' && status->starttime == expectedStart;
	}
	return running(pid);
}

bool AppProcess::running(pid_t pid)
{
#if defined(_WIN32)
	// Process Manager semantics: any pid above 1 counts as possibly alive.
	return pid > 1;
#else
	return pid > 1 && (::kill(pid, 0) == 0 || errno != ESRCH);
#endif
}

pid_t AppProcess::wait(std::chrono::milliseconds timeout, int *status)
{
	if (timeout.count() == 0)
	{
		if (!isFinalized())
			return 0;
	}
	else
	{
		const auto deadline = std::chrono::steady_clock::now() + timeout;
		for (;;)
		{
			std::unique_lock lock(m_lifecycle->mutex);
			const auto phase = m_lifecycle->exitPhase.load(std::memory_order_relaxed);
			if (phase == Lifecycle::ExitPhase::Finalized)
				break;
			if (m_lifecycle->completionCv.wait_until(lock, deadline) == std::cv_status::timeout && !isFinalized())
				return 0;
		}
	}

	if (status)
		*status = returnValue();
	return lastPid();
}

bool AppProcess::isFinalized() const noexcept
{
	return m_lifecycle->exitPhase.load(std::memory_order_acquire) == Lifecycle::ExitPhase::Finalized;
}

bool AppProcess::canReportExit() const noexcept
{
	return m_lifecycle->exitPhase.load(std::memory_order_acquire) == Lifecycle::ExitPhase::Active;
}

bool AppProcess::onTimerTerminate()
{
	terminate();
	return false;
}

long AppProcess::cleanupResources()
{
	// Timer callbacks can take m_processMutex. Cancel first, then use the mutex
	// only to detach owned state; teardown may synchronously dispatch stdout.
	cancelTimer(m_timerCheckStdoutId);
	cancelTimer(m_timerTerminateId);

	std::unique_ptr<StdoutStrategy> stdoutStrategy;
	{
		std::lock_guard guard(m_processMutex);
		stdoutStrategy = std::move(m_stdoutStrategy);
		m_stdOutMaxSize = 0;
	}

	long dispatchedBytes = 0;
	if (stdoutStrategy)
	{
		stdoutStrategy->teardown();
		dispatchedBytes = stdoutStrategy->dispatchedBytes();
	}

	{
		std::lock_guard guard(m_processMutex);
		m_stdoutHandler.reset();
		m_stdinHandler.reset();
	}
	Utility::removeFile(m_stdinFileName);
	return dispatchedBytes;
}

void AppProcess::terminate()
{
	m_lifecycle->terminating.store(true, std::memory_order_release);
	terminateImpl();
	// Derived backends detach their host PID/container without a child-exit
	// callback. Centralizing the synthetic report also covers timer-driven buffer
	// termination; the exit-phase guard deduplicates native callbacks.
	if (isStartAccepted() && lastPid() > 1)
		onExit(FORCED_TERMINATION_EXIT_CODE);
}

void AppProcess::terminateImpl()
{
	const static char fname[] = "AppProcess::terminate() ";

	pid_t pid = INVALID_PID;
	{
		// Serialize with startImpl so terminate cannot miss a process between spawn and PID publication.
		std::lock_guard lock(m_processMutex);
		pid = m_pid.exchange(INVALID_PID);
		const auto expectedStart = m_processStartToken;
		m_processStartToken = 0;

		if (sameProcessRunning(pid, expectedStart))
		{
			LOG_INF << fname << "kill process <" << pid << ">.";

#if defined(_WIN32)
			if (!os::kill_job(m_job))
				LOG_WAR << fname << "kill job object <" << pid << "> failed with error: " << last_error_msg();
#else
			// Kill the entire process group to include children; the pending
			// async_wait reaps the exit. A direct kill is the fallback when the
			// group kill fails (for example a non-group leader attach).
			if (::kill(-pid, SIGKILL) != 0 && ::kill(pid, SIGKILL) != 0)
				LOG_WAR << fname << "kill process <" << pid << "> failed with error: " << last_error_msg();
#endif

			LOG_DBG << fname << "process <" << pid << "> killed";
		}
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

void AppProcess::scheduleTermination(std::size_t timeout, const std::string &from)
{
	const static char fname[] = "AppProcess::scheduleTermination() ";
	// Publish the timer ID before exit cleanup can cancel it. Timer callbacks run
	// without TimerManager's internal locks, so this lock order has no reverse edge.
	std::lock_guard guard(m_lifecycle->mutex);
	if (m_lifecycle->exitPhase.load(std::memory_order_relaxed) != Lifecycle::ExitPhase::Active)
		return;

	if (!isValidTimerId(m_timerTerminateId))
	{
		this->registerTimer(m_timerTerminateId, 1000L * timeout, 0, from, std::bind(&AppProcess::onTimerTerminate, this));
	}
	else
	{
		LOG_WAR << fname << "kill already pending with timer ID <" << m_timerTerminateId << ">, ignoring duplicate request";
	}
}

void AppProcess::startStdoutMonitoring()
{
	const static char fname[] = "AppProcess::startStdoutMonitoring() ";
	// An active pipe pump owns stdout: the size-check timer would only wake
	// and return at its isActive guard. Attached runs and Windows still register.
	{
		std::lock_guard guard(m_processMutex);
		if (m_stdoutStrategy && m_stdoutStrategy->isActive())
			return;
	}
	// Serialize registration with the Active -> Observed transition so cleanup
	// cannot miss a timer whose ID has not been published yet.
	std::lock_guard guard(m_lifecycle->mutex);
	if (m_lifecycle->exitPhase.load(std::memory_order_relaxed) != Lifecycle::ExitPhase::Active)
		return;

	if (!isValidTimerId(m_timerCheckStdoutId))
	{
		static const int TIMEOUT_SEC = STDOUT_FILE_SIZE_CHECK_INTERVAL;
		this->registerTimer(m_timerCheckStdoutId, 1000L * TIMEOUT_SEC, 1000L * TIMEOUT_SEC, fname, std::bind(&AppProcess::onTimerCheckStdout, this));
	}
	else
	{
		LOG_WAR << fname << "stdout check timer already registered with ID <" << m_timerCheckStdoutId << ">, ignoring duplicate request";
	}
}

bool AppProcess::onTimerCheckStdout()
{
	const static char fname[] = "AppProcess::onTimerCheckStdout() ";

	std::lock_guard guard(m_processMutex);

	if (m_stdoutStrategy && m_stdoutStrategy->isActive())
		return isValidTimerId(m_timerCheckStdoutId);

	if (m_stdoutHandler.valid() && m_stdOutMaxSize)
	{
#if defined(_WIN32)
		LARGE_INTEGER size{};
		const HANDLE handle = reinterpret_cast<HANDLE>(m_stdoutHandler.get());
		if (::GetFileSizeEx(handle, &size) && size.QuadPart > 0)
		{
			if (size.QuadPart > m_stdOutMaxSize)
			{
				OVERLAPPED overlapped{};
				if (!::LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped))
					LOG_WAR << fname << "Failed to acquire exclusive lock on stdout file <" << m_stdoutFileName << ">: " << last_error_msg();

				const auto backupFile = fs::path(m_stdoutFileName + STDOUT_BAK_POSTFIX);
				fs::copy_file(fs::path(m_stdoutFileName), backupFile, fs::copy_options::overwrite_existing);
				LARGE_INTEGER zero{};
				::SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN);
				::SetEndOfFile(handle);
				::UnlockFileEx(handle, 0, MAXDWORD, MAXDWORD, &overlapped);

				LOG_INF << fname << "stdout file <" << m_stdoutFileName << "> size <" << size.QuadPart << "> reached limit <" << m_stdOutMaxSize << ">, backed up and truncated";
			}
		}
		else
		{
			LOG_WAR << fname << "GetFileSizeEx on stdout file <" << m_stdoutFileName << "> failed";
		}
#else
		struct stat st;
		if (::fstat(m_stdoutHandler.get(), &st) == 0)
		{
			if (st.st_size > m_stdOutMaxSize)
			{
				// Lock a duplicate so the shared handle stays open.
				const int lockFd = ::dup(m_stdoutHandler.get());
				if (lockFd >= 0 && ::flock(lockFd, LOCK_EX) != 0)
					LOG_WAR << fname << "Failed to acquire exclusive lock on stdout file <" << m_stdoutFileName << ">: " << last_error_msg();

				const auto backupFile = fs::path(m_stdoutFileName + STDOUT_BAK_POSTFIX);
				fs::copy_file(fs::path(m_stdoutFileName), backupFile, fs::copy_options::overwrite_existing);
				::ftruncate(m_stdoutHandler.get(), 0);
				if (lockFd >= 0)
					::close(lockFd);

				LOG_INF << fname << "stdout file <" << m_stdoutFileName << "> size <" << st.st_size << "> reached limit <" << m_stdOutMaxSize << ">, backed up and truncated";
			}
		}
		else
		{
			LOG_WAR << fname << "fstat on stdout file <" << m_stdoutFileName << "> failed, reopening handle: " << last_error_msg();
			const auto stdOut = Utility::stringFormat("/proc/%d/fd/1", getpid());
			m_stdoutHandler.reset(::open(stdOut.c_str(), O_RDWR));
		}
#endif
	}

	return isValidTimerId(m_timerCheckStdoutId);
}

ProcessStartResult AppProcess::start(std::string cmd, std::string user, std::string workDir,
									 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
									 const std::string &stdoutFile, const nlohmann::json &stdinFileContent, int maxStdoutSize)
{
	const pid_t pid = startImpl(std::move(cmd), std::move(user), std::move(workDir), std::move(envMap),
								std::move(limit), stdoutFile, stdinFileContent, maxStdoutSize);
	resolveStart(pid > 1, pid);
	const bool accepted = isStartAccepted();
	if (!accepted)
		cleanupResources();
	// A stop request may win before the backend publishes its PID/container ID.
	// Once start is accepted, honor that request through the same idempotent entry point.
	if (accepted && m_lifecycle->terminating.load(std::memory_order_acquire))
		terminate();
	ProcessStartResult result;
	result.accepted = accepted;
	result.pid = pid;
	result.error = startError();
	return result;
}

pid_t AppProcess::startImpl(std::string cmd, std::string user, std::string workDir,
							std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							const std::string &stdoutFile, const nlohmann::json &stdinFileContent, int maxStdoutSize)
{
	const static char fname[] = "AppProcess::startImpl() ";

	std::lock_guard guard(m_processMutex);

	// Tokenize once; validateCommand and the launcher share the same argv.
	auto argv = Utility::str2argv(cmd);
	if (validateCommand(argv) != 0)
		return INVALID_PID;

	prepareEnvironment(envMap);

#if !defined(_WIN32)
	// A sudo login spawn resets the environment: rebuild the command so the
	// intended variables are re-injected after the reset.
	if (auto owner = m_owner.lock())
	{
		const auto sudoUser = owner->sudoLoginUser();
		if (!sudoUser.empty())
		{
			cmd = wrapSudoLoginCommand(sudoUser, envMap, cmd);
			// The wrapped command line is a different string: re-tokenize.
			argv = Utility::str2argv(cmd);
		}
	}
#endif

	// Exec user resolution happens parent-side so a bad name rejects the start.
	unsigned int uid = 0, gid = 0; // 0/0 keeps the daemon identity
#if !defined(_WIN32)
	if (!user.empty() && user != "root")
	{
		if (auto ids = os::getUidByName(user))
		{
			uid = ids->first;
			gid = ids->second;
		}
		else
		{
			setStartError(Utility::stringFormat("user <%s> does not exist", user.c_str()));
			return INVALID_PID;
		}
		if (uid == 0)
		{
			setStartError(Utility::stringFormat("exec_user <%s> resolved to root (uid=0), which is not permitted", user.c_str()));
			return INVALID_PID;
		}
	}
#endif

	const auto defaultWorkDir = (fs::path(Configuration::instance()->getWorkDir()) / APPMESH_WORK_TMP_DIR).string();
	if (workDir.empty())
		workDir = defaultWorkDir;
	else if (!Utility::isDirExist(workDir))
	{
		setStartError(Utility::stringFormat("working_directory <%s> does not exist", workDir.c_str()));
		LOG_WAR << fname << "working_directory <" << workDir << "> does not exist, using default";
		workDir = defaultWorkDir;
	}

	if (argv.empty())
	{
		setStartError("empty command");
		return INVALID_PID;
	}
	const auto exe = resolveExecutablePath(argv[0]);
	if (exe.empty())
	{
		setStartError(Utility::stringFormat("command <%s> not found in PATH", argv[0].c_str()));
		LOG_ERR << fname << "Process <" << cmd << "> " << startError();
		return INVALID_PID;
	}

	// AppProcess represents one run; completed instances are never restarted.
	m_stdoutFileName = stdoutFile;

	int pipeWriteForChild = -1;
	int pipeReadForDaemon = -1;

	if (!m_stdoutFileName.empty() || stdinFileContent != EMPTY_STR_JSON)
	{
		if (!m_stdoutFileName.empty())
		{
			m_stdoutHandler.reset(openStdioFile(m_stdoutFileName.c_str(), false));
			LOG_DBG << fname << "std_out: " << m_stdoutFileName << " m_stdoutHandler: " << m_stdoutHandler.get();

			if (!m_stdoutHandler.valid())
				LOG_ERR << fname << "Failed to open stdout file <" << m_stdoutFileName << ">: " << last_error_msg();

#if !defined(_WIN32)
			std::tie(pipeReadForDaemon, pipeWriteForChild) = createStdoutPipe();
#endif
		}
		else
		{
			m_stdoutHandler.reset(openStdioFile(DEV_NULL, false));
		}

		if (stdinFileContent != EMPTY_STR_JSON)
		{
			// JSON::dump never throws: a throw here would leave the app never started.
			const std::string content = stdinFileContent.is_string()
											? stdinFileContent.get<std::string>()
											: JSON::dump(stdinFileContent);
			m_stdinFileName = os::createTmpFile(m_stdinFileName, content, 0600);
			m_stdinHandler.reset(openStdioFile(m_stdinFileName.c_str(), true));

			if (!m_stdinHandler.valid())
				setStartError(Utility::stringFormat("Failed to reopen stdin file for reading <%s>", last_error_msg()));
			LOG_DBG << fname << "std_in <" << m_stdinFileName << "> handler=" << m_stdinHandler.get();
		}
		else
		{
			m_stdinHandler.reset(openStdioFile(DEV_NULL, true));
		}
	}

	const bool redirectStdio = m_stdinHandler.valid() && m_stdoutHandler.valid();
#if !defined(_WIN32)
	const int childOutFd = (pipeWriteForChild >= 0) ? pipeWriteForChild : static_cast<int>(m_stdoutHandler.get());
#endif

	// Cgroup leaves must exist before the fork: the child inherits the daemon
	// leaf and joins the application leaf itself while exec'ing.
	std::vector<std::string> cgroupProcsPaths;
#if defined(__linux__)
	if (limit && (limit->m_memoryMb > 0 || limit->m_memoryVirtSpecified || limit->m_cpuShares > 0))
	{
		auto mbToBytes = [](long long mb) -> long long
		{ return mb > 0 ? mb * 1024LL * 1024LL : 0; };
		const long long swapMb = (limit->m_memoryVirtMb > limit->m_memoryMb) ? (limit->m_memoryVirtMb - limit->m_memoryMb) : 0;
		try
		{
			m_cgroup = LinuxCgroup::create(
				mbToBytes(limit->m_memoryMb), mbToBytes(swapMb), limit->m_cpuShares, limit->m_memoryVirtSpecified);
			m_cgroup->prepareGroup(limit->m_name, ++(limit->m_index));
			cgroupProcsPaths = m_cgroup->procsFilePaths();
		}
		catch (const std::exception &ex)
		{
			m_cgroup.reset();
			setStartError(Utility::stringFormat("cgroup setup failed <%s>", ex.what()));
			LOG_ERR << fname << "Process <" << cmd << "> " << startError();
			if (pipeWriteForChild >= 0)
				::close(pipeWriteForChild);
			if (pipeReadForDaemon >= 0)
				::close(pipeReadForDaemon);
			return INVALID_PID;
		}
	}
#endif

	const auto childEnv = buildChildEnvironment(envMap);
	boost::system::error_code ec;

#if defined(_WIN32)
	std::vector<std::wstring> argsWide;
	argsWide.reserve(argv.size() - 1);
	for (std::size_t i = 1; i < argv.size(); ++i)
		argsWide.push_back(fs::path(argv[i]).wstring());

	bp2::windows::default_launcher launcher;
	bp2::process proc = launcher(PROCESS_SERVICE::instance()->io(), ec, exe, argsWide,
								 bp2::process_start_dir(workDir), bp2::process_environment(childEnv));
#else
	std::vector<std::string> args(argv.begin() + 1, argv.end());

	// vfork_launcher forks without notifying the io_context in the child. The
	// daemon creates services on this context from several threads, so a forked
	// child can inherit a service mutex held and deadlock before execve.
	bp2::posix::vfork_launcher launcher;
	const auto launch = [&](auto &&...inits)
	{
		// On error the launcher itself returns an empty process; the forked
		// child exited on the failed exec and must be reaped here.
		bp2::process proc = launcher(PROCESS_SERVICE::instance()->io(), ec, exe, args,
									 std::forward<decltype(inits)>(inits)...);
		if (ec && launcher.pid > 0)
		{
			int childStatus = 0;
			::waitpid(launcher.pid, &childStatus, 0);
		}
		return proc;
	};

	// The default constructor is unavailable on the signal-based handle, so
	// bind the result directly instead of declaring first.
	bp2::process proc = redirectStdio
		? launch(bp2::process_start_dir(workDir),
				 bp2::posix::bind_fd(STDIN_FILENO, static_cast<int>(m_stdinHandler.get())),
				 bp2::posix::bind_fd(STDOUT_FILENO, childOutFd),
				 bp2::posix::bind_fd(STDERR_FILENO, childOutFd),
				 bp2::process_environment(childEnv),
				 PosixProcessIdentity(uid, gid, cgroupProcsPaths))
		: launch(bp2::process_start_dir(workDir),
				 bp2::process_environment(childEnv),
				 PosixProcessIdentity(uid, gid, cgroupProcsPaths));
#endif

	if (pipeWriteForChild >= 0)
	{
		::close(pipeWriteForChild);
		pipeWriteForChild = -1;
	}

	if (ec)
	{
		if (startError().empty())
			setStartError(Utility::stringFormat("start failed with error <%s>", ec.message().c_str()));
		LOG_ERR << fname << "Process <" << cmd << "> " << startError();
		if (pipeReadForDaemon >= 0)
			::close(pipeReadForDaemon);
		return INVALID_PID;
	}

	const pid_t startedPid = static_cast<pid_t>(proc.id());
	LOG_INF << fname << "Process <" << cmd << "> started with pid <" << startedPid << ">.";

	m_pid.store(startedPid);
	m_lastPid = startedPid;
	if (const auto status = os::status(startedPid))
		m_processStartToken = status->starttime;

#if defined(_WIN32)
	m_job = os::create_job(os::name_job(startedPid));
	os::assign_job(m_job, startedPid);
#else
	// Belt and suspenders: the child joins the leaf itself before exec. The
	// start token proves the pid is still this child before the fallback
	// write, so a recycled pid cannot pull a foreign process into the leaf.
	if (m_cgroup && sameProcessRunning(startedPid, m_processStartToken) && !m_cgroup->attachPid(startedPid))
		LOG_DBG << fname << "parent-side cgroup attach skipped for <" << startedPid << ">";
#endif

	if (m_stdoutHandler.valid() && maxStdoutSize)
		m_stdOutMaxSize = maxStdoutSize;

	auto owner = m_owner.lock();
	auto appName = owner ? owner->getName() : std::string();
#if defined(_WIN32)
	const native_fd pipeReadForStrategy = INVALID_FD; // no stdout pipe on Windows
#else
	const native_fd pipeReadForStrategy = pipeReadForDaemon;
#endif
	m_stdoutStrategy = StdoutStrategy::create(std::move(appName), pipeReadForStrategy, m_stdoutHandler.get(), m_outFileMutex, m_owner);
	// A pipe strategy exists exactly when both fds were valid; its pump owns
	// the read fd from construction, so closing it here too would
	// double-close a recycled fd.
	if (pipeReadForDaemon >= 0 && m_stdoutHandler.valid())
		pipeReadForDaemon = -1;

	// Arm the exit watch on the process io thread. The completion handler
	// owns the process object; it reports the evaluated exit code
	// (WIFEXITED -> exit status, WIFSIGNALED -> signal number) and the
	// already-reaped child makes the late destructor a no-op.
	auto self = std::dynamic_pointer_cast<AppProcess>(shared_from_this());
	const auto held = std::make_shared<bp2::process>(std::move(proc));
	PROCESS_SERVICE::instance()->post([self, held]
									  {
		held->async_wait([self, held](const boost::system::error_code &waitEc, int exitCode)
						 {
			if (waitEc)
			{
				LOG_WAR << "AppProcess::startImpl() exit wait failed for <" << self->getuuid() << ">: " << waitEc.message();
				exitCode = FORCED_TERMINATION_EXIT_CODE;
			}
			LOG_INF << "AppProcess::startImpl() Process <" << self->lastPid() << "> exited with code <" << exitCode << ">";
			self->onExit(exitCode); });
	});

	if (pipeReadForDaemon >= 0)
		::close(pipeReadForDaemon);

	return startedPid;
}

const std::string AppProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	// m_stdoutFileName is guarded by m_processMutex, not m_outFileMutex.
	std::string stdoutFileName;
	{
		std::lock_guard guard(m_processMutex);
		stdoutFileName = m_stdoutFileName;
	}
	std::lock_guard guard(*m_outFileMutex);
	return Utility::readFileCpp(stdoutFileName, position, maxSize, readLine);
}

const std::string AppProcess::startError() const
{
	std::lock_guard guard(m_lifecycle->mutex);
	return m_lifecycle->startError;
}

void AppProcess::setStartError(const std::string &error)
{
	std::lock_guard guard(m_lifecycle->mutex);
	m_lifecycle->startError = error;
}

int AppProcess::validateCommand(const std::vector<std::string> &argv)
{
	const static char fname[] = "AppProcess::validateCommand() ";

	// An empty command line is rejected later in startImpl.
	if (argv.empty())
		return 0;
	const auto &cmdRoot = argv[0];
	const bool checkCmd = (cmdRoot.find('/') != std::string::npos || cmdRoot.find('\\') != std::string::npos);

	if (checkCmd && !Utility::isFileExist(cmdRoot))
	{
		LOG_WAR << fname << "command file <" << cmdRoot << "> does not exist";
		setStartError(Utility::stringFormat("command file <%s> does not exist", cmdRoot.c_str()));
		return INVALID_PID;
	}

#if !defined(_WIN32)
	if (checkCmd && ::access(cmdRoot.c_str(), X_OK) != 0)
#else
	if (false) // the CRT has no execute bit; existence was checked above
#endif
	{
		LOG_WAR << fname << "command file <" << cmdRoot << "> does not have execution permission";
		setStartError(Utility::stringFormat("command file <%s> does not have execution permission", cmdRoot.c_str()));
		return INVALID_PID;
	}

	return 0;
}

void AppProcess::prepareEnvironment(std::map<std::string, std::string> &envMap)
{
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
	std::lock_guard guard(m_cpuMutex);
	try
	{
		auto tree = os::pstree(getpid(), ptree);

		const auto totalMemory = tree ? tree->totalRssMemBytes() : 0;
		const auto totalFileDescriptors = tree ? tree->totalFileDescriptors() : 0;
		std::string pstreeStr;
		pid_t leafPid = INVALID_PID;

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
								   static_cast<uint64_t>(0), std::string(), static_cast<pid_t>(INVALID_PID));
		}

		const auto curSampleTime = std::chrono::steady_clock::now();
		const auto curProcCpuTime = tree->totalCpuTime();
		double cpuTimeUnitsPerSecond = 1000.0; // Windows process times are stored as milliseconds.
#if defined(__APPLE__)
		cpuTimeUnitsPerSecond = 1000000000.0; // proc_taskinfo total times are nanoseconds.
#elif defined(__linux__)
		const auto clockTicks = ::sysconf(_SC_CLK_TCK);
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
		return std::make_tuple(false, static_cast<uint64_t>(0), 0.0f, static_cast<uint64_t>(0), std::string(), static_cast<pid_t>(INVALID_PID));
	}
}

// src/daemon/application/AppUtils.h
#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

/// <summary>
/// Shell mode application manage (create/clean) shell script
/// </summary>
struct ShellAppFileGen
{
	explicit ShellAppFileGen(const std::string &name, const std::string &cmd, const std::string &execUser, bool sessionLogin, const std::string &workingDir);
	virtual ~ShellAppFileGen();
	const std::string &getShellStartCmd() const { return m_shellCmd; };
	const std::string &getShellFileName() const { return m_fileName; };
	const bool isUsingSudo() const { return m_usingSudo; };

private:
	std::string m_cmd;
	std::string m_shellCmd;
	std::string m_fileName;
	bool m_usingSudo;
};

/// <summary>
/// One application log file
/// </summary>
struct AppLogFile
{
public:
	explicit AppLogFile(const std::string &appName, int index = 0);
	virtual ~AppLogFile();
	void increaseIndex();
	int index();
	const std::string getFileName() const;

private:
	std::string m_fileName;
	int m_index;
};

/// <summary>
/// Manage stdout log files for an application
/// </summary>
class LogFileQueue
{
public:
	explicit LogFileQueue(const std::string &baseFileName, int queueSize);
	virtual ~LogFileQueue();
	void enqueue();
	int size();
	const std::string getFileName(int index);

private:
	// enqueue() (spawn, under the app's process lock) races with size()/getFileName()
	// (AsJson/getOutput, REST threads). Guard the vector so the queue is self-thread-safe.
	mutable std::mutex m_mutex;
	std::vector<std::shared_ptr<AppLogFile>> m_fileQueue;
	const std::string baseFileName;
	const int m_queueSize;
};

/// <summary>
/// Crash-loop restart backoff (k8s CrashLoopBackOff style): the delay before the next
/// start grows exponentially (base, 2x, 4x ... capped) across consecutive short-lived runs,
/// and resets to zero once a run survives the "stable" threshold. Not thread-safe; the
/// caller serializes (App invokes it under m_lifecycleMutex).
/// </summary>
class RestartBackoff
{
public:
	// Record a finished run by how long it lasted; returns the delay before the next start.
	std::chrono::seconds onExit(std::chrono::seconds ranFor);

private:
	int m_failures = 0; // consecutive short-lived runs
};

/// <summary>
/// Application status
/// </summary>
enum class STATUS : int
{
	DISABLED = 0,
	ENABLED,
	NOTAVAILABLE // used for temp app from RestHandler::parseAndRegRunApp and destroyed app
};

/// <summary>
/// Application permissions for group user and other group users
/// </summary>
enum class PERMISSION : int
{
	GROUP_DENY = 1,
	GROUP_READ = 2,
	GROUP_WRITE = 3,
	OTHER_DENY = 10,
	OTHER_READ = 20,
	OTHER_WRITE = 30
};
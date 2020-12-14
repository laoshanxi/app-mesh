#pragma once

#include <memory>
#include <string>
#include <vector>

/// <summary>
/// Shell mode application manage (create/clean) shell script
/// </summary>
struct ShellAppFileGen
{
	explicit ShellAppFileGen(const std::string &name, const std::string &cmd, const std::string &workDir);
	virtual ~ShellAppFileGen();
	const std::string &getShellStartCmd() const { return m_shellCmd; };
	const std::string &getShellFileName() const { return m_fileName; };

private:
	std::string m_cmd;
	std::string m_shellCmd;
	std::string m_fileName;
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
	std::vector<std::shared_ptr<AppLogFile>> m_fileQueue;
	const std::string baseFileName;
	const int m_queueSize;
};

/// <summary>
/// Application status
/// </summary>
enum class STATUS : int
{
	DISABLED,
	ENABLED,
	NOTAVIALABLE, // used for temp app from RestHandler::apiRunParseApp and destroyed app
	INITIALIZING,
	UNINITIALIZED
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
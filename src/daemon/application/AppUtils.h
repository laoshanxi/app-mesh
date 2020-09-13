#pragma once
#include <string>
#include <vector>
#include <memory>

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

struct AppLogFile
{
public:
	explicit AppLogFile(const std::string &appName, int index);
	~AppLogFile();
	void increaseIndex();
	int index();
	const std::string getFileName() const;

private:
	std::string m_fileName;
	int m_index;
};

class LogFileQueue
{
public:
	explicit LogFileQueue(std::string baseFileName, int queueSize);
	virtual ~LogFileQueue();
	void enqueue();
	int size();
	const std::string getFileName(int index);

private:
	std::vector<std::shared_ptr<AppLogFile>> m_fileQueue;
	const std::string baseFileName;
	const int m_ququeSize;
};

enum class STATUS : int
{
	DISABLED,
	ENABLED,
	NOTAVIALABLE, // used for temp app from RestHandler::apiRunParseApp and destroyed app
	INITIALIZING,
	UNINITIALIZING
};

enum class PERMISSION : int
{
	GROUP_DENY = 1,
	GROUP_READ = 2,
	GROUP_WRITE = 3,
	OTHER_DENY = 10,
	OTHER_READ = 20,
	OTHER_WRITE = 30
};
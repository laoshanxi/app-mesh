// src/daemon/application/AppStdoutLog.h
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

/// <summary>
/// One application log file
/// </summary>
struct AppLogFile
{
public:
	explicit AppLogFile(const std::string &appName, int index = 0);
	virtual ~AppLogFile();
	void increaseIndex();
	const std::string getFileName() const;
	/// A same-name successor instance owns the file; stop deleting it on destruction.
	void detachFile();

private:
	std::string m_fileName;
	int m_index;
	bool m_ownsFile = true;
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
	/// Stop deleting the name-derived files; a same-name successor instance owns them.
	void detachFiles();

private:
	// enqueue() (spawn, under the app's process lock) races with size()/getFileName()
	// (AsJson/getOutput, REST threads). Guard the vector so the queue is self-thread-safe.
	mutable std::mutex m_mutex;
	std::vector<std::shared_ptr<AppLogFile>> m_fileQueue;
	const std::string m_baseFileName;
	const int m_queueSize;
	bool m_sweepFiles = true;
};


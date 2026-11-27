// src/daemon/application/AppStdoutLog.cpp
#include "AppStdoutLog.h"

#include "../../common/Utility.h"

AppLogFile::AppLogFile(const std::string &appName, int index) : m_fileName(appName), m_index(index) {}

AppLogFile::~AppLogFile()
{
	if (m_ownsFile)
		Utility::removeFile(getFileName());
}

void AppLogFile::detachFile() { m_ownsFile = false; }

void AppLogFile::increaseIndex()
{
	const static char fname[] = "AppLogFile::increaseIndex() ";

	auto oldFile = getFileName();
	m_index++;
	auto newFile = getFileName();
	if (Utility::isFileExist(newFile))
		Utility::removeFile(newFile);
	std::error_code renameError;
	fs::rename(oldFile, newFile, renameError);
	if (Utility::isFileExist(oldFile) && renameError)
	{
		LOG_ERR << fname << "Failed to rename file <" << oldFile << "> to <" << newFile << ">: " << renameError.message();
	}
	else
	{
		LOG_DBG << fname << "File <" << newFile << "> created";
	}
}

const std::string AppLogFile::getFileName() const
{
	if (m_index)
	{
		return Utility::stringFormat("%s.%d", m_fileName.c_str(), m_index);
	}
	else
	{
		return m_fileName;
	}
}

LogFileQueue::LogFileQueue(const std::string &baseFileName, int queueSize)
	: m_baseFileName(baseFileName), m_queueSize(queueSize + 1)
{
}

LogFileQueue::~LogFileQueue()
{
	if (!m_sweepFiles)
		return;
	// double check and remove file
	for (int i = 0; i < m_queueSize; i++)
	{
		AppLogFile autoDeleteFile(m_baseFileName, i);
	}
}

void LogFileQueue::detachFiles()
{
	std::lock_guard guard(m_mutex);
	for (auto &file : m_fileQueue)
		file->detachFile();
	m_sweepFiles = false;
}

void LogFileQueue::enqueue()
{
	std::lock_guard guard(m_mutex);
	// pop last
	if (static_cast<int>(m_fileQueue.size()) >= m_queueSize)
	{
		m_fileQueue.pop_back();
	}
	// rename all with reverse order
	for (auto it = m_fileQueue.rbegin(); it != m_fileQueue.rend(); it++)
	{
		(*it)->increaseIndex();
	}
	// insert top
	auto file = std::make_shared<AppLogFile>(m_baseFileName);
	m_fileQueue.insert(m_fileQueue.begin(), file);
}

int LogFileQueue::size()
{
	std::lock_guard guard(m_mutex);
	return static_cast<int>(m_fileQueue.size());
}

const std::string LogFileQueue::getFileName(int index)
{
	std::lock_guard guard(m_mutex);
	if (index >= 0 && index < static_cast<int>(m_fileQueue.size()))
	{
		return m_fileQueue[index]->getFileName();
	}
	throw NotFoundException(
		Utility::stringFormat("no such index <%d> of stdout log file for <%s>", index, m_baseFileName.c_str()));
}


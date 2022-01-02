#include "AppUtils.h"
#include <ace/OS.h>
#include <fstream>
#include <memory>

#include "../../common/Utility.h"
#include "../../common/os/linux.hpp"
#include "../Configuration.h"

ShellAppFileGen::ShellAppFileGen(const std::string &name, const std::string &cmd)
{
	const static char fname[] = "ShellAppFileGen::ShellAppFileGen() ";

	auto fileName = Utility::stringFormat("%s/appmesh.%s.sh", Configuration::instance()->getWorkDir().c_str(), name.c_str());
	std::ofstream shellFile(fileName, std::ios::out | std::ios::trunc);
	if (shellFile.is_open() && shellFile.good())
	{
		shellFile << "#!/bin/sh" << std::endl;
		shellFile << "# App Mesh app: <" << name << ">" << std::endl;
		shellFile << "set -e" << std::endl;
		shellFile << cmd << std::endl;
		shellFile.close();
		// only read permission
		os::chmod(fileName, 444);
		m_fileName = fileName;
		m_shellCmd = Utility::stringFormat("/bin/sh '%s'", m_fileName.c_str());

		LOG_DBG << fname << "file  <" << fileName << "> generated for app <" << name << "> run in shell mode";
	}
	else
	{
		m_shellCmd = cmd;
		LOG_WAR << fname << "create shell file <" << fileName << "> failed with error: " << std::strerror(errno);
		throw std::runtime_error(Utility::stringFormat("failed to create file: ", fileName.c_str()));
	}
}

ShellAppFileGen::~ShellAppFileGen()
{
	Utility::removeFile(m_fileName);
}

AppLogFile::AppLogFile(const std::string &appName, int index)
	: m_fileName(appName), m_index(index)
{
}

AppLogFile::~AppLogFile()
{
	Utility::removeFile(getFileName());
}

void AppLogFile::increaseIndex()
{
	const static char fname[] = "AppLogFile::increaseIndex() ";

	auto oldFile = getFileName();
	m_index++;
	auto newFile = getFileName();
	if (Utility::isFileExist(newFile))
		Utility::removeFile(newFile);
	if (Utility::isFileExist(oldFile) && 0 != ACE_OS::rename(oldFile.c_str(), newFile.c_str()))
	{
		LOG_ERR << fname << "Rename file <" << oldFile << "> failed with error: " << std::strerror(errno);
	}
	else
	{
		LOG_DBG << fname << "file <" << newFile << "> created";
	}
}

int AppLogFile::index()
{
	return m_index;
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
	: baseFileName(baseFileName), m_queueSize(queueSize + 1)
{
}

LogFileQueue::~LogFileQueue()
{
	// double check and remove file
	for (int i = 0; i < m_queueSize; i++)
	{
		AppLogFile autoDeleteFile(baseFileName, i);
	}
}

void LogFileQueue::enqueue()
{
	// pop last
	if (this->size() >= m_queueSize)
	{
		m_fileQueue.pop_back();
	}
	// rename all with reverse order
	for (auto it = m_fileQueue.rbegin(); it != m_fileQueue.rend(); it++)
	{
		(*it)->increaseIndex();
	}
	// insert top
	auto file = std::make_shared<AppLogFile>(baseFileName);
	m_fileQueue.insert(m_fileQueue.begin(), file);
}

int LogFileQueue::size()
{
	return m_fileQueue.size();
}

const std::string LogFileQueue::getFileName(int index)
{
	if (index <= size() - 1)
	{
		return m_fileQueue[index]->getFileName();
	}
	throw std::invalid_argument(Utility::stringFormat("no such index <%d> of stdout file exist", index));
}

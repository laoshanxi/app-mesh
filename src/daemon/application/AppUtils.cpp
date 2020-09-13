#include <fstream>
#include <memory>
#include <ace/OS.h>
#include "AppUtils.h"
#include "../../common/Utility.h"
#include "../Configuration.h"

ShellAppFileGen::ShellAppFileGen(const std::string &name, const std::string &cmd, const std::string &workDir)
{
	const static char fname[] = "ShellAppFileGen::ShellAppFileGen() ";

	auto fileName = Utility::stringFormat("%s/appmesh.%s.sh", Configuration::instance()->getDefaultWorkDir().c_str(), name.c_str());
	std::ofstream shellFile(fileName, std::ios::out | std::ios::trunc);
	if (shellFile.is_open() && shellFile.good())
	{
		shellFile << "#!/bin/sh" << std::endl;
		shellFile << "#application <" << name << ">" << std::endl;
		//if (workDir.length()) shellFile << "cd " << workDir << std::endl;
		shellFile << cmd << std::endl;
		shellFile.close();
		m_fileName = fileName;
		m_shellCmd = Utility::stringFormat("sh %s", m_fileName.c_str());

		LOG_DBG << fname << "file  <" << fileName << "> generated for app <" << name << "> run in shell mode";
	}
	else
	{
		m_shellCmd = cmd;
		LOG_WAR << fname << "create shell file <" << fileName << "> failed with error: " << std::strerror(errno);
	}
}

ShellAppFileGen::~ShellAppFileGen()
{
	Utility::removeFile(m_fileName);
}

AppLogFile::AppLogFile(const std::string &appName, int index = 0)
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
		std::string file = m_fileName;
		if (m_index)
			file = Utility::stringFormat("%s.%d", m_fileName.c_str(), m_index);
		return file;
	}
	else
	{
		return m_fileName;
	}
}

LogFileQueue::LogFileQueue(std::string baseFileName, int queueSize)
	: baseFileName(baseFileName), m_ququeSize(queueSize)
{
}

LogFileQueue::~LogFileQueue()
{
	// double check and remove file
	for (int i = 0; i < m_ququeSize; i++)
	{
		AppLogFile autoDeleteFile(baseFileName, i);
	}
}

void LogFileQueue::enqueue()
{
	if (0 == m_ququeSize)
		return;
	// rename all with reverse order
	for (auto it = m_fileQueue.rbegin(); it != m_fileQueue.rend(); it++)
	{
		(*it)->increaseIndex();
	}
	// pop last
	if (this->size() >= m_ququeSize)
	{
		m_fileQueue.pop_back();
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

#include "AppUtils.h"
#include <ace/OS.h>
#include <fstream>
#include <memory>

#include "../../common/Utility.h"
#if !defined(WIN32)
#include "../../common/os/chown.hpp"
#include "../../common/os/linux.hpp"
#endif
#include "../Configuration.h"

ShellAppFileGen::ShellAppFileGen(const std::string &name, const std::string &cmd, const std::string &execUser, bool sessionLogin, const std::string &workingDir)
	: m_usingSudo(false)
{
	const static char fname[] = "ShellAppFileGen::ShellAppFileGen() ";
#if defined(WIN32)
	// TODO: For Windows, implement bat solution
	m_shellCmd = cmd;
#else
	const static std::string shellDir = (fs::path(Configuration::instance()->getWorkDir()) / "shell").string();
	const static std::string defaultWorkDir = (fs::path(Configuration::instance()->getWorkDir()) / APPMESH_WORK_TMP_DIR).string();
	const auto fileName = Utility::stringFormat("%s/appmesh.%s.sh", shellDir.c_str(), name.c_str());

	// Open shell file for writing
	std::ofstream shellFile(fileName, std::ios::out | std::ios::trunc);
	if (!shellFile.is_open())
	{
		LOG_WAR << fname << "Failed to open shell file for writing: " << fileName;
		throw std::runtime_error("Failed to create shell script file.");
	}

	// Write the shell script content
	shellFile << "#!/bin/bash" << std::endl;
	shellFile << "# App Mesh app: <" << name << ">" << std::endl;
	shellFile << "set -e" << std::endl;
	shellFile << "cd " << (workingDir.empty() ? defaultWorkDir : workingDir) << std::endl;
	shellFile << cmd << std::endl;
	shellFile.close();

	// Set the file permission to read and execute (owner only)
	if (!os::chmod(fileName, 500))
	{
		LOG_WAR << fname << "Failed to set permissions for file: " << fileName;
		throw std::runtime_error("Failed to set file permissions.");
	}

	// Get current user
	static const auto osUser = Utility::getUsernameByUid();

	// Change file ownership if necessary
	if (!execUser.empty() && osUser != execUser)
	{
		if (!os::chown(fileName, execUser))
		{
			LOG_WAR << fname << "Failed to change ownership of file: " << fileName;
			throw std::runtime_error("Failed to change file ownership.");
		}
	}

	// Prepare the shell command
	m_fileName = Utility::escapeCommandLine(fileName);
	m_shellCmd = Utility::stringFormat("bash '%s'", m_fileName.c_str());

	// Check if we need to switch user and handle sudo with session login
	if (!execUser.empty() && execUser != osUser && sessionLogin)
	{
		if (getuid() == 0)
		{
			m_usingSudo = true;
			// If we are root and sessionLogin is true, use sudo with login option
			m_shellCmd = Utility::stringFormat("/usr/bin/sudo --login --user=%s bash '%s'", execUser.c_str(), m_fileName.c_str());
			LOG_DBG << fname << "Generated shell command with sudo for user <" << execUser << "> : " << m_shellCmd;
		}
		else if (getuid() != 0)
		{
			m_usingSudo = true;
			// If not root, attempt to execute as the specified user directly
			m_shellCmd = Utility::stringFormat("/usr/bin/sudo --login --user=%s bash '%s'", execUser.c_str(), m_fileName.c_str());
			LOG_DBG << fname << "Generated shell command with sudo login for non-root user <" << execUser << "> : " << m_shellCmd;
		}
	}

	LOG_DBG << fname << "Shell file <" << fileName << "> generated for app <" << name << "> with owner <" << execUser << "> and command <" << m_shellCmd << ">";
#endif
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
	throw NotFoundException(Utility::stringFormat("no such index <%d> of stdout log file for <%s>", index, baseFileName.c_str()));
}

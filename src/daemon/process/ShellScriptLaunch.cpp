// src/daemon/process/ShellScriptLaunch.cpp
#include "ShellScriptLaunch.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>

#include "../../common/Utility.h"
#include "../../common/os/chown.h"
#include "../../common/os/linux.h"
#include "../Configuration.h"

ShellAppFileGen::ShellAppFileGen(const std::string &name, const std::string &cmd, const std::string &execUser,
								 bool sessionLogin, const std::string &workingDir)
	: m_workingDir(workingDir), m_usingSudo(false)
{
	const static char fname[] = "ShellAppFileGen::ShellAppFileGen() ";
#if defined(_WIN32)
	// Windows Implementation
	const static std::string shellDir = (fs::path(Configuration::instance()->getRuntimeDir()) / "shell").string();

	// The script file name carries a per-instance suffix: a re-registered app of the
	// same name must not collide with the previous instance's script. The old script
	// stays mode 0500 until the previous Application object is destroyed (pending
	// request references can delay that past the new registration), so reusing the
	// name made every new run fail to open the file for writing. Stale scripts left
	// by an unclean shutdown block the name the same way.
	// Create a batch file name: workdir/shell/appmesh.<app_name>.<instance>.bat
	const auto fileName =
		Utility::stringFormat("%s\\appmesh.%s.%s.bat", shellDir.c_str(), name.c_str(), Utility::shortID().c_str());

	// Open batch file for writing
	std::ofstream shellFile(fileName, std::ios::out | std::ios::trunc);
	if (!shellFile.is_open())
	{
		LOG_ERR << fname << "Failed to open batch file <" << fileName << "> for writing for app <" << name
				<< ">: " << last_error_msg();
		throw std::runtime_error("Failed to create shell script file.");
	}

	// Write the batch script content
	shellFile << "@echo off" << std::endl;

	// 1. Handle Working Directory
	// Use /d to ensure drive changes are handled (e.g., C: to D:)
	if (!workingDir.empty())
	{
		shellFile << "cd /d \"" << workingDir << "\"" << std::endl;
	}

	// 2. Write the user command
	shellFile << cmd << std::endl;

	shellFile.close();

	// 3. Prepare the command line for the child process
	// cmd.exe /C executes the command (file) and then terminates
	m_fileName = fileName;
	m_shellCmd = Utility::stringFormat("cmd.exe /C \"%s\"", m_fileName.c_str());

	LOG_DBG << fname << "Generated batch file <" << fileName << "> for app <" << name << "> with command <" << m_shellCmd
			<< ">";

#else
	const static std::string shellDir = (fs::path(Configuration::instance()->getRuntimeDir()) / "shell").string();
	const static std::string defaultWorkDir = Configuration::instance()->getWorkShareDir();
	// Per-instance suffix: see the Windows branch for why same-name script reuse is unsafe.
	const auto fileName =
		Utility::stringFormat("%s/appmesh.%s.%s.sh", shellDir.c_str(), name.c_str(), Utility::shortID().c_str());

	// Open shell file for writing
	std::ofstream shellFile(fileName, std::ios::out | std::ios::trunc);
	if (!shellFile.is_open())
	{
		LOG_ERR << fname << "Failed to open shell file <" << fileName << "> for writing for app <" << name
				<< ">: " << last_error_msg();
		throw std::runtime_error("Failed to create shell script file.");
	}

	// Write the shell script content
	shellFile << "#!/bin/bash" << std::endl;
	shellFile << "# App Mesh app: <" << name << ">" << std::endl;
	shellFile << "set -e" << std::endl;
	auto effectiveWorkingDir = workingDir;
	std::error_code dirError;
	if (!workingDir.empty() && !fs::exists(workingDir, dirError))
	{
		// The client cwd may not exist on this host (a macOS physical path against
		// a container); fall back instead of failing the whole script at the cd.
		LOG_WAR << fname << "Working directory <" << workingDir << "> of app <" << name
				<< "> does not exist, falling back to <" << defaultWorkDir << ">";
		effectiveWorkingDir = defaultWorkDir;
	}
	shellFile << "cd " << (effectiveWorkingDir.empty() ? defaultWorkDir : effectiveWorkingDir) << std::endl;
	shellFile << cmd << std::endl;
	shellFile.close();

	// Set the file permission to read and execute (owner only)
	if (!os::chmod(fileName, 500))
	{
		LOG_ERR << fname << "Failed to set permissions for file <" << fileName << ">: " << last_error_msg();
		throw std::runtime_error("Failed to set file permissions.");
	}

	// Get current user
	static const auto osUser = os::getUsernameByUid();

	// Change file ownership if necessary
	if (!execUser.empty() && osUser != execUser)
	{
		if (!os::chown(fileName, execUser))
		{
			LOG_ERR << fname << "Failed to change ownership of file <" << fileName << "> to user <" << execUser
					<< ">: " << last_error_msg();
			throw std::runtime_error("Failed to change file ownership.");
		}
		// The script cds into the working directory after the user switch: hand the
		// configured directory to the exec user or the cd fails with permission denied.
		if (!workingDir.empty() && Utility::isDirExist(workingDir) && !os::chown(workingDir, execUser, "", true))
			LOG_WAR << fname << "Failed to change ownership of working directory <" << workingDir << "> to user <"
					<< execUser << ">: " << last_error_msg();
	}

	// The command line escapes the path; the stored name stays usable as a path.
	m_fileName = fileName;
	m_shellCmd = Utility::stringFormat("bash '%s'", Utility::escapeCommandLine(fileName).c_str());

	// Record the sudo login target; the wrapper is composed at spawn time so
	// per-run environment values survive the login shell's environment reset.
	if (!execUser.empty() && execUser != osUser && sessionLogin)
	{
		m_usingSudo = true;
		m_sudoUser = execUser;
	}

	LOG_DBG << fname << "Shell file <" << fileName << "> generated for app <" << name << "> with owner <" << execUser
			<< "> and command <" << m_shellCmd << ">";
#endif
}

ShellAppFileGen::~ShellAppFileGen() { Utility::removeFile(m_fileName); }

void inlineShellScriptCmd(Json::Value &createBody)
{
	// Presence checks first: operator[] would insert null members and pollute
	// the create body of an ENTRYPOINT-only image.
	if (!HAS_JSON_FIELD(createBody, "Cmd") || !HAS_JSON_FIELD(createBody, "HostConfig"))
		return;
	const auto &cmd = createBody["Cmd"];
	// The exact shape Application::getCmdLine() produces for shell mode: `bash <script>`.
	if (!cmd.isArray() || cmd.size() != 2 || !cmd[0].isString() || cmd[0].asString() != "bash" || !cmd[1].isString())
		return;
	const auto script = cmd[1].asString();

	// Only inline when this very script is the compile step's same-path read-only bind.
	auto &hostConfig = createBody["HostConfig"];
	if (!hostConfig.isObject() || !hostConfig["Binds"].isArray())
		return;
	const auto bindSpec = script + ":" + script + ":ro";
	bool bound = false;
	for (const auto &bind : hostConfig["Binds"])
		if (bind.isString() && bind.asString() == bindSpec)
			bound = true;
	if (!bound)
		return;

	std::ifstream in(script, std::ios::binary);
	if (!in.is_open())
		return; // unreadable here would be unreadable in the container; keep the old shape
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

	// The generated header's cd (its 4th line) targets a daemon-host path; a
	// generic image lacks it and set -e would kill the script before the user
	// command. appmesh-based images still cd successfully, keeping the
	// working-dir behavior unchanged; user lines are never touched.
	{
		const auto cdPrefix = std::string("cd ");
		auto lineStart = content.find("set -e");
		if (lineStart != std::string::npos)
		{
			lineStart = content.find('\n', lineStart);
			if (lineStart != std::string::npos)
			{
				++lineStart;
				const auto lineEnd = content.find('\n', lineStart);
				if (lineEnd != std::string::npos && content.compare(lineStart, cdPrefix.length(), cdPrefix) == 0)
				{
					const auto dir = content.substr(lineStart + cdPrefix.length(), lineEnd - lineStart - cdPrefix.length());
					content.replace(lineStart, lineEnd - lineStart,
						cdPrefix + dir + " 2>/dev/null || echo 'App Mesh: working dir <" + dir +
							"> not present in this container, using the image default' >&2");
				}
			}
		}
	}

	Json::Value inlined(Json::arrayValue);
	inlined.append("bash");
	inlined.append("-c");
	inlined.append(std::move(content));
	createBody["Cmd"] = std::move(inlined);

	Json::Value kept(Json::arrayValue);
	for (const auto &bind : hostConfig["Binds"])
		if (!bind.isString() || bind.asString() != bindSpec)
			kept.append(bind);
	hostConfig["Binds"] = std::move(kept);
}

// src/daemon/process/ShellScriptLaunch.h
#pragma once

#include <string>

#include <json/json.h>

/// <summary>
/// Shell mode application manage (create/clean) shell script
/// </summary>
struct ShellAppFileGen
{
	explicit ShellAppFileGen(const std::string &name, const std::string &cmd, const std::string &execUser, bool sessionLogin,
							 const std::string &workingDir);
	virtual ~ShellAppFileGen();
	const std::string &getShellStartCmd() const { return m_shellCmd; };
	const std::string &getShellFileName() const { return m_fileName; };
	// The directory the generated script changes into.
	const std::string &workingDir() const { return m_workingDir; };
	const bool isUsingSudo() const { return m_usingSudo; };
	// Target user of the sudo login wrapper, empty when sudo is not used. The
	// caller composes the wrapper at spawn time so per-run environment values
	// can be injected after the login shell's environment reset.
	const std::string &sudoUser() const { return m_sudoUser; };

private:
	std::string m_cmd;
	std::string m_shellCmd;
	std::string m_fileName;
	std::string m_sudoUser;
	std::string m_workingDir;
	bool m_usingSudo{false};
};

// Docker images that lack the daemon-host working directory cannot run the generated
// script as written: replace the `bash <script>` command with the script text, and
// make its cd tolerant. The script's read-only bind is dropped from the create body.
void inlineShellScriptCmd(Json::Value &createBody);

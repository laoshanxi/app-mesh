// src/daemon/process/DockerProcess.h
#pragma once

#include <atomic>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "AppProcess.h"

// Exit code marker for docker CLI/API failures that never produced a container exit code
constexpr int DOCKER_COMMAND_ERROR = -200;

// Ownership labels stamped on every App Mesh container: cleanup deletes only
// containers it owns, never a foreign one that merely shares a name.
constexpr const char *const DOCKER_LABEL_MANAGED = "appmesh.managed";
constexpr const char *const DOCKER_LABEL_APP = "appmesh.app";

// High-risk host-facing settings the Docker.HostSecurityPolicy gate looks for
// in a container definition (shared by both backends).
std::vector<std::string> dockerHostSecurityFindings(const Json::Value &createBody);

// Docker command line process object
class DockerProcess : public AppProcess
{
public:
	DockerProcess(std::weak_ptr<Application> owner, const std::string &containerName, const std::string &dockerImage);
	~DockerProcess() override;

	// Returns docker container PID from inspect
	pid_t getpid() const override;

	// Get container ID
	std::string containerId() const override;

	// Get process exit code from container inspect
	int returnValue() const override;

	// Get stdout content from docker logs
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE,
								   bool readLine = false) override;

	// Health probe inside the container via docker exec
	std::optional<int> execHealthProbe(const std::string &cmd) override;

	// Image HEALTHCHECK verdict from docker inspect (empty when the image defines none)
	std::optional<int> containerHealthVerdict() override;

	// "appmesh-<app>": namespaced so an App Mesh container can never collide
	// with (or be mistaken for) an operator-created container of the same name.
	static std::string namespacedContainerName(const std::string &appName);

protected:
	pid_t startImpl(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap,
					std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile,
					const Json::Value &stdinFileContent, int maxStdoutSize) override;
	void terminateImpl() override;

	// A pull is its own managed run, with this AppProcess owning its PID and exit callback.
	pid_t startImagePull(const std::map<std::string, std::string> &envMap, const std::string &dockerImage,
						 std::string workDir, const std::string &stdoutFile);
	void setContainerId(const std::string &containerId);
	std::string takeContainerId();
	// Immutable container identity shared with the API implementation.
	const std::string m_containerName;
	const std::string m_dockerImage;

	// The pre-namespacing container name (== app name), kept only to clean up
	// containers created by an older App Mesh version at migration.
	const std::string &legacyContainerName() const { return m_legacyContainerName; }
	// SIGTERM grace before SIGKILL: the owner's stop_grace_period, docker's own
	// 10s default when unset.
	int stopGraceSeconds() const;
	// Persist the container's final logs into the application stdout file
	// before the container is deleted, so output survives removal. Best effort.
	virtual void archiveContainerLogs(const std::string &containerId);
	// Where the exit archive lands; empty when the run had no stdout file.
	std::string m_stdoutFile;

	// Liveness without a visible host PID (daemon in a container): Docker is
	// the authority, polled through the backend every scheduler tick.
	bool needsAlwaysExitPoll() const override;
	void reportBackendExit() override;
	bool running() const override;
	// Set right after attach(): true when the host PID is observable in this
	// process namespace (classic host deployment).
	bool m_hostPidVisible = false;
	mutable std::atomic_bool m_containerRunning{false};

protected:
	// API pulls are detached threads; CLI pulls are real children. Both keep
	// the run alive through this flag and cancel through the other.
	std::atomic_bool m_pullInFlight{false};
	std::atomic_bool m_pullCancelled{false};
	std::string m_containerId;
	std::string m_containerEngine; // docker or podman
	const std::string m_legacyContainerName;

	// Guards container id and engine selection.
	mutable std::mutex m_dockerMutex;

private:
	pid_t startContainer(const std::string &cmd, const std::string &execUser, const std::string &workDir,
						 const std::map<std::string, std::string> &envMap, const std::shared_ptr<ResourceLimitation> &limit,
						 const std::string &stdoutFile, const Json::Value &createBody);
};

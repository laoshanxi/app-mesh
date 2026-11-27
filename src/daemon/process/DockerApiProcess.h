// src/daemon/process/DockerApiProcess.h
#pragma once

#include <atomic>
#include <map>
#include <optional>
#include <string>

#include <json/json.h>

#include "AppProcess.h"

struct HttpResponse;

// Exit code marker for container-channel failures that never produced an exit code.
constexpr int DOCKER_COMMAND_ERROR = -200;

// Ownership labels stamped at create by the agent; cleanup only deletes owned containers.
constexpr const char *const DOCKER_LABEL_MANAGED = "appmesh.managed";
constexpr const char *const DOCKER_LABEL_APP = "appmesh.app";
// Which node owns the container: nodes sharing one Docker engine (sibling
// containers, a common docker.sock) must never judge or delete each other's.
constexpr const char *const DOCKER_LABEL_NODE = "appmesh.node";

// The node identity stamped into ownership labels (the OS hostname; both the
// daemon and the embedded agent derive the same value on the same host).
std::string dockerNodeIdentity();

// High-risk host-facing settings the Docker.HostSecurityPolicy gate looks for
// in a container definition.
std::vector<std::string> dockerHostSecurityFindings(const Json::Value &createBody);

// Docker container process object: the daemon owns the run-state machine and
// drives the agent's container lifecycle service (docker_service.go) over the
// loopback REST listener with PSK-signed requests. Blocking calls on the
// dedicated ProcessService threads, exactly like before.
class DockerApiProcess : public AppProcess
{
public:
	DockerApiProcess(std::weak_ptr<Application> owner, const std::string &appName, const std::string &dockerImage);
	~DockerApiProcess() override;

	// Signed ping through the container service at boot; noop without Docker.
	static void selfCheckDockerAgent();

	// Log (or with APPMESH_DOCKER_ORPHAN_SWEEP=delete remove) labeled
	// containers whose application no longer exists.
	static void sweepOrphanContainers();

	// Liveness of the agent's event pushes: fresh markers demote the scheduler poll.
	static void noteContainerEventsAlive();
	static bool containerEventsFresh();

	// "appmesh-<node>-<app>": namespaced by node and app so an App Mesh container
	// can never collide with an operator container, nor with the same-named
	// application of another node sharing the Docker engine.
	static std::string namespacedContainerName(const std::string &appName);

	// Returns the docker container PID from the inspect projection.
	pid_t getpid() const override;

	// Get container ID
	std::string containerId() const override;

	// Get process exit code from the inspect projection
	int returnValue() const override;

	// Get stdout content from the agent's demultiplexed log projection; once the
	// container is gone, from this run's stdout slot (the terminate-time archive).
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE,
								   bool readLine = false) override;

	// Health probe inside the container via the exec operation
	std::optional<int> execHealthProbe(const std::string &cmd) override;

	// Docker-authoritative exit verdict (inspect Running/ExitCode)
	void reportBackendExit() override;

	// Re-bind a recovered run to its container by name + ownership labels
	// (inspect), refreshing the container ID and running cache.
	void adoptRecoveredContainer() override;

	// Image HEALTHCHECK verdict from the inspect projection (Health status)
	std::optional<int> containerHealthVerdict() override;

	// An image pull is a detached activity without a PID; the run stays
	// alive until the pull thread reports its exit.
	bool running() const override;

protected:
	// stdinPipe is rejected at registration; unused, satisfies the backend contract.
	pid_t startImpl(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap,
					std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile,
					const Json::Value &stdinFileContent, int maxStdoutSize, bool stdinPipe,
					const SandboxSpec &sandbox) override;
	void terminateImpl() override;

private:
	// Request the agent's container service; timeoutSeconds 0 keeps the default.
	const std::shared_ptr<HttpResponse> requestContainer(const web::http::method &mtd, const std::string &path,
														 std::map<std::string, std::string> query, Json::Value *body,
														 long timeoutSeconds = 0) const;

	// POST /image/ensure on a worker thread; progress lands in the stdout file.
	void startApiImagePull(std::map<std::string, std::string> envMap, int pullTimeoutSeconds,
						   const std::string &stdoutFile);

	// Persist the container's final logs before deletion, so output survives
	// removal. Best effort.
	void archiveContainerLogs(const std::string &containerId);

	// The agent's inspect projection; nullopt on any failure, never a fabricated state.
	std::optional<Json::Value> inspectState(const std::string &idOrName) const;

	// The agent's log projection joined back into plain text (timestamps dropped).
	static std::string joinLogLines(const Json::Value &logs);

	// This run's own stdout slot (where terminateImpl archives the container
	// logs); guarded by m_dockerMutex. Empty until the run starts.
	std::string stdoutArchiveFile() const;

	// SIGTERM grace before SIGKILL: stop_grace_period, docker's 10s default.
	int stopGraceSeconds() const;

	void setContainerId(const std::string &containerId);
	std::string takeContainerId();
	// The pre-namespacing name, kept to clean up containers of older versions.
	const std::string &legacyContainerName() const { return m_legacyContainerName; }

	// Immutable container identity.
	const std::string m_containerName;
	const std::string m_dockerImage;
	const std::string m_legacyContainerName;
	// Where the exit archive lands; empty without a stdout file.
	std::string m_stdoutFile;

	// Liveness without a visible host PID: Docker is the authority.
	bool needsAlwaysExitPoll() const override;
	// True when a backstop inspect is due even while the markers stay fresh.
	bool backendLivenessPollDue() const override;
	// Set right after attach(): the host PID is observable (classic host deployment).
	std::atomic_bool m_hostPidVisible{false};
	mutable std::atomic_bool m_containerRunning{false};
	// Last time reportBackendExit consulted Docker for this run (steady ms):
	// bounds how long fresh event markers can suppress the authoritative poll.
	mutable std::atomic<int64_t> m_lastBackendPollMs{0};

	// A pull is a detached thread kept alive through the in-flight flag.
	std::atomic_bool m_pullInFlight{false};
	std::atomic_bool m_pullCancelled{false};
	std::string m_containerId;

	// Guards the container id.
	mutable std::mutex m_dockerMutex;
};

// src/daemon/process/DockerApiProcess.h
#pragma once

#include <atomic>
#include <optional>
#include <string>

#include <json/json.h>

#include "DockerProcess.h"

#define DOCKER_REQUEST_ID_HEADER "X-Request-ID"
// Docker Engine API registry auth header (base64 JSON credentials)
#define DOCKER_REGISTRY_AUTH_HEADER "X-Registry-Auth"

struct HttpResponse;

// Docker API Object using Docker REST API
class DockerApiProcess : public DockerProcess
{
public:
	DockerApiProcess(std::weak_ptr<Application> owner, const std::string &appName, const std::string &dockerImage);
	~DockerApiProcess() override;

	// Startup self-check after the agent read its PSK: a signed /_ping through
	// the agent's docker proxy. Noop without /var/run/docker.sock; a failure is
	// logged loudly so a broken channel surfaces at boot, not as a runtime 407.
	static void selfCheckDockerAgent();

	// Startup reconciliation: App Mesh labeled containers whose app no longer
	// exists are orphans. They are logged; APPMESH_DOCKER_ORPHAN_SWEEP=delete
	// in the daemon environment also removes them.
	static void sweepOrphanContainers();

	// Get stdout content from docker logs API
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE,
								   bool readLine = false) override;

	// Get process exit code from container inspect API
	int returnValue() const override;

	// Health probe inside the container via the exec API
	std::optional<int> execHealthProbe(const std::string &cmd) override;

	// Docker-authoritative exit verdict (inspect State.Running/ExitCode)
	void reportBackendExit() override;

	// Re-bind a recovered run to its container by name + ownership labels
	// (inspect), refreshing the container ID and running cache.
	void adoptRecoveredContainer() override;

	// Image HEALTHCHECK verdict from container inspect (State.Health.Status)
	std::optional<int> containerHealthVerdict() override;

	// Persist the container's final logs before deletion (Engine API fetch)
	void archiveContainerLogs(const std::string &containerId) override;

	// An API image pull is a detached activity without a PID; the run stays
	// alive until the pull thread reports its exit.
	bool running() const override;

protected:
	// stdinPipe is rejected at registration (Application::FromJson) before a
	// container run can be created; the parameter exists to satisfy the backend
	// contract and stays unused here.
	pid_t startImpl(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap,
					std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile,
					const Json::Value &stdinFileContent, int maxStdoutSize, bool stdinPipe) override;
	void terminateImpl() override;

private:
	// Request Docker HTTP REST API. timeoutSeconds 0 keeps the per-call default;
	// the pull passes its own bounded window. Idempotent GETs retry once on a
	// transport failure (agent restart window).
	const std::shared_ptr<HttpResponse> requestDocker(const web::http::method &mtd, const std::string &path,
													  std::map<std::string, std::string> query,
													  std::map<std::string, std::string> header, Json::Value *body,
													  long timeoutSeconds = 0) const;

	// Delete a container by name only when App Mesh owns it (ownership label;
	// an unlabeled container is a pre-labeling leftover). False blocks start.
	bool deleteOwnedContainer(const std::string &containerName);

	// POST /images/create on a worker thread: no docker CLI, no socket mount.
	// Progress lines land in the app stdout file when the pull completes.
	void startApiImagePull(std::map<std::string, std::string> envMap, int pullTimeoutSeconds,
						   const std::string &stdoutFile);

};

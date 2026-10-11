// src/daemon/PersistManager.h
#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <string>

#include <json/json.h>

#include "../common/os/models.h" // pid_t

/// <summary>
/// App Process Recover object
/// </summary>
struct AppSnap
{
	explicit AppSnap(pid_t pid, int64_t starttime);
	bool operator==(const AppSnap &snapshort) const;
	pid_t m_pid;
	int64_t m_startTime;
};

/// <summary>
/// App Mesh HA snapshot
/// </summary>
struct Snapshot
{
	bool operator==(const Snapshot &snapshort) const;
	Json::Value AsJson() const;
	static std::shared_ptr<Snapshot> FromJson(const Json::Value &obj);
	/// Absolute snapshot path shared by the writer and the startup recovery
	/// reader, which runs before the daemon changes its working directory.
	static const std::string &filePath();
	void persist();

	std::map<std::string, AppSnap> m_apps;
};

/// <summary>
/// App Mesh HA manager
/// </summary>
class PersistManager
{
public:
	PersistManager();
	virtual ~PersistManager();

	void persistSnapshot();
	static std::unique_ptr<PersistManager> &instance();

private:
	std::shared_ptr<Snapshot> captureSnapshot();

private:
	std::shared_ptr<Snapshot> m_persistedSnapshot;
};

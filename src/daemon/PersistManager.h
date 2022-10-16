#pragma once

#include <map>
#include <memory>
#include <string>


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
	nlohmann::json AsJson() const;
	static std::shared_ptr<Snapshot> FromJson(const nlohmann::json &obj);
	void persist();

	std::map<std::string, AppSnap> m_apps;
	std::string m_consulSessionId;
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

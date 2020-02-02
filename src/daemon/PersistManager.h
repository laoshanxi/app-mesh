#pragma once

#include <memory>
#include <map>
#include <string>
#include "cpprest/json.h"

//////////////////////////////////////////////////////////////////////////
/// HA for app process recover
//////////////////////////////////////////////////////////////////////////
struct AppSnap
{
	explicit AppSnap(pid_t pid, int64_t starttime);
	bool operator==(const AppSnap& snapshort) const;
	pid_t m_pid;
	int64_t m_startTime;
};

struct Snapshot
{
	bool operator==(const Snapshot& snapshort) const;
	web::json::value AsJson();
	static std::shared_ptr<Snapshot> FromJson(const web::json::value& obj);
	void persist();

	std::map<std::string, AppSnap> m_apps;
	std::string m_consulSessionId;
};
class PersistManager
{
public:
	PersistManager();
	virtual ~PersistManager();

	void persistSnapshot();
	static std::unique_ptr<PersistManager>& instance();

private:
	std::shared_ptr<Snapshot> captureSnapshot();

private:
	std::shared_ptr<Snapshot> m_persistedSnapshot;
};


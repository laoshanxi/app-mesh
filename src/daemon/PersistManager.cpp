#include <chrono>
#include <fstream>

#include "../common/os/linux.h"
#include "Configuration.h"
#include "PersistManager.h"
#include "application/Application.h"
#include "process/AppProcess.h"
#include "security/TokenBlacklist.h"

#define SNAPSHOT_JSON_KEY_pid "pid"
#define SNAPSHOT_JSON_KEY_starttime "starttime"

//////////////////////////////////////////////////////////////////////////
/// HA for app process recover
//////////////////////////////////////////////////////////////////////////
PersistManager::PersistManager()
	: m_persistedSnapshot(std::make_shared<Snapshot>())
{
}

PersistManager::~PersistManager()
{
}

std::shared_ptr<Snapshot> PersistManager::captureSnapshot()
{
	auto snap = std::make_shared<Snapshot>();
	auto apps = Configuration::instance()->getApps();
	for (auto &app : apps)
	{
		if (!app->isEnabled() || !app->isPersistAble() || app->getName() == SEPARATE_AGENT_APP_NAME)
			continue;

		auto pid = app->getpid();
		auto snapAppIter = m_persistedSnapshot->m_apps.find(app->getName());
		if (snapAppIter != m_persistedSnapshot->m_apps.end() && snapAppIter->second.m_pid == pid)
		{
			// if application does not changed pid, do not need call stat
			snap->m_apps.insert(std::pair<std::string, AppSnap>(
				app->getName(),
				AppSnap(snapAppIter->second.m_pid, snapAppIter->second.m_startTime)));
		}
		else
		{
			// application pid changed
			auto stat = os::status(pid);
			if (stat)
			{
				snap->m_apps.insert(std::pair<std::string, AppSnap>(
					app->getName(),
					AppSnap(pid, std::chrono::system_clock::to_time_t(stat->get_starttime()))));
			}
		}
	}
	snap->m_tokenBlackList = TOKEN_BLACK_LIST::instance()->getTokens();
	return snap;
}

void PersistManager::persistSnapshot()
{
	const static char fname[] = "HealthCheckTask::persistSnapshot() ";

	// only do this every minute.
	static std::chrono::system_clock::time_point lastExecuteTime = std::chrono::system_clock::now();
	auto now = std::chrono::system_clock::now();
	if (std::chrono::duration_cast<std::chrono::seconds>(now - lastExecuteTime).count() < 60)
		return;
	lastExecuteTime = now;

	try
	{
		auto snapshot = this->captureSnapshot();
		if (snapshot->operator==(*m_persistedSnapshot))
		{
			return;
		}
		else
		{
			m_persistedSnapshot = std::move(snapshot);
			m_persistedSnapshot->persist();
		}
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << "exception";
	}
}

std::unique_ptr<PersistManager> &PersistManager::instance()
{
	static auto singleton = std::make_unique<PersistManager>();
	return singleton;
}

bool Snapshot::operator==(const Snapshot &snap) const
{
	if (snap.m_apps.size() != m_apps.size())
		return false;
	for (const auto &app : m_apps)
	{
		if (0 == snap.m_apps.count(app.first))
			return false;
		if (app.second == snap.m_apps.find(app.first)->second)
		{
			// continue;
		}
		else
		{
			return false;
		}
	}
	if (snap.m_tokenBlackList.size() != m_tokenBlackList.size())
		return false;
	else
		for (const auto &token : m_tokenBlackList)
		{
			if (snap.m_tokenBlackList.count(token.first) == 0)
				return false;
		}

	return true;
}

nlohmann::json Snapshot::AsJson() const
{
	nlohmann::json result = nlohmann::json::object();

	// Applications
	nlohmann::json apps = nlohmann::json::object();
	for (const auto &app : m_apps)
	{
		auto json = nlohmann::json::object();
		json[SNAPSHOT_JSON_KEY_pid] = (app.second.m_pid);
		json[SNAPSHOT_JSON_KEY_starttime] = (app.second.m_startTime);
		apps[app.first] = std::move(json);
	}
	result["Applications"] = std::move(apps);

	// TODO: use seperate persist file or move to 3rd storage
	// TokenBlackList
	nlohmann::json tokens = nlohmann::json::object();
	for (const auto &token : m_tokenBlackList)
		tokens[token.first] = std::chrono::system_clock::to_time_t(token.second);
	result["TokenBlackList"] = std::move(tokens);
	return result;
}

std::shared_ptr<Snapshot> Snapshot::FromJson(const nlohmann::json &obj)
{
	auto snap = std::make_shared<Snapshot>();
	if (!obj.is_null() && obj.is_object())
	{
		if (obj.contains("Applications"))
			for (auto &app : obj.at("Applications").items())
			{
				if (HAS_JSON_FIELD(app.value(), SNAPSHOT_JSON_KEY_pid) && HAS_JSON_FIELD(app.value(), SNAPSHOT_JSON_KEY_starttime) &&
					app.value().contains(SNAPSHOT_JSON_KEY_pid) && app.value().contains(SNAPSHOT_JSON_KEY_starttime))
				{
					snap->m_apps.insert(std::pair<std::string, AppSnap>(
						app.key(),
						AppSnap(
							GET_JSON_INT_VALUE(app.value(), SNAPSHOT_JSON_KEY_pid),
							GET_JSON_INT64_VALUE(app.value(), SNAPSHOT_JSON_KEY_starttime))));
				}
			}
		if (obj.contains("TokenBlackList"))
			for (auto &token : obj.at("TokenBlackList").items())
			{
				snap->m_tokenBlackList.insert(std::make_pair(token.key(), std::chrono::system_clock::from_time_t(token.value().get<int64_t>())));
			}
	}
	return snap;
}

void Snapshot::persist()
{
	const static char fname[] = "Snapshot::persist() ";

	static auto tmpFile = std::string(SNAPSHOT_FILE_NAME) + "." + std::to_string(Utility::getThreadId());
	std::ofstream ofs(tmpFile, std::ios::trunc);
	if (ofs.is_open())
	{
		ofs << this->AsJson().dump();
		ofs.close();
		if (ACE_OS::rename(tmpFile.c_str(), SNAPSHOT_FILE_NAME) == 0)
		{
			LOG_DBG << fname << "write snapshot success";
		}
		else
		{
			LOG_ERR << fname << "Failed to create snapshot file <" << SNAPSHOT_FILE_NAME << ">, error :" << last_error_msg();
		}
	}
	else
	{
		LOG_WAR << fname << "Failed to open snapshot file";
	}
}

AppSnap::AppSnap(pid_t pid, int64_t starttime)
	: m_pid(pid), m_startTime(starttime)
{
}

bool AppSnap::operator==(const AppSnap &snapshort) const
{
	return (m_startTime == snapshort.m_startTime && m_pid == snapshort.m_pid);
}

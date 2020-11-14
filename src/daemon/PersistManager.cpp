#include "PersistManager.h"
#include "Configuration.h"
#include "process/AppProcess.h"
#include <fstream>
#include "application/Application.h"
#include "rest/ConsulConnection.h"
#include "../common/os/linux.hpp"

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
		if (!app->isEnabled())
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
					AppSnap(pid, (int64_t)stat->starttime)));
			}
		}
	}
	snap->m_consulSessionId = ConsulConnection::instance()->consulSessionId();
	return snap;
}

void PersistManager::persistSnapshot()
{
	const static char fname[] = "HealthCheckTask::persistSnapshot() ";

	try
	{
		auto snapshot = this->captureSnapshot();
		if (snapshot->operator==(*m_persistedSnapshot))
		{
			return;
		}
		else
		{
			m_persistedSnapshot = snapshot;
			m_persistedSnapshot->persist();
		}
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << " exception";
	}
}

std::unique_ptr<PersistManager> &PersistManager::instance()
{
	static auto singleton = std::make_unique<PersistManager>();
	return singleton;
}

bool Snapshot::operator==(const Snapshot &snapshort) const
{
	if (snapshort.m_apps.size() != m_apps.size())
		return false;
	for (const auto &app : m_apps)
	{
		if (0 == snapshort.m_apps.count(app.first))
			return false;
		if (app.second == snapshort.m_apps.find(app.first)->second)
		{
			// continue;
		}
		else
		{
			return false;
		}
	}
	return snapshort.m_consulSessionId == m_consulSessionId;
}

web::json::value Snapshot::AsJson() const
{
	web::json::value result = web::json::value::object();
	// Applications
	web::json::value apps = web::json::value::object();
	for (const auto &app : m_apps)
	{
		auto json = web::json::value::object();
		json[SNAPSHOT_JSON_KEY_pid] = web::json::value::number(app.second.m_pid);
		json[SNAPSHOT_JSON_KEY_starttime] = web::json::value::number(app.second.m_startTime);
		apps[app.first] = json;
	}
	result["Applications"] = apps;
	result["ConsulSessionId"] = web::json::value::string(m_consulSessionId);
	return result;
}

std::shared_ptr<Snapshot> Snapshot::FromJson(const web::json::value &obj)
{
	auto snap = std::make_shared<Snapshot>();
	if (!obj.is_null() && obj.is_object())
	{
		if (obj.has_object_field("Applications"))
			for (auto app : obj.at("Applications").as_object())
			{
				if (HAS_JSON_FIELD(app.second, SNAPSHOT_JSON_KEY_pid) && HAS_JSON_FIELD(app.second, SNAPSHOT_JSON_KEY_starttime) &&
					app.second.has_number_field(SNAPSHOT_JSON_KEY_pid) && app.second.has_number_field(SNAPSHOT_JSON_KEY_starttime))
				{
					snap->m_apps.insert(std::pair<std::string, AppSnap>(
						app.first,
						AppSnap(
							GET_JSON_INT_VALUE(app.second, SNAPSHOT_JSON_KEY_pid),
							GET_JSON_NUMBER_VALUE(app.second, SNAPSHOT_JSON_KEY_starttime))));
				}
			}
		snap->m_consulSessionId = GET_JSON_STR_VALUE(obj, "ConsulSessionId");
	}
	return snap;
}

void Snapshot::persist()
{
	const static char fname[] = "Snapshot::persist() ";

	std::ofstream ofs(SNAPSHOT_FILE_NAME, std::ios::trunc);
	if (ofs.is_open())
	{
		ofs << this->AsJson().serialize();
		ofs.close();
		LOG_DBG << fname << "write snapshot";
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

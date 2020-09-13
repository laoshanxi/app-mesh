#pragma once

#include <memory>
#include <string>
#include <map>
#include <mutex>
#include "Application.h"

//////////////////////////////////////////////////////////////////////////
/// An Short Running Application will start periodly.
//////////////////////////////////////////////////////////////////////////
class ApplicationShortRun : public Application
{
public:
	ApplicationShortRun();
	virtual ~ApplicationShortRun();

	static void FromJson(std::shared_ptr<ApplicationShortRun>& app, const web::json::value& jobj) noexcept(false);
	virtual web::json::value AsJson(bool returnRuntimeInfo) override;
	virtual void dump() override;

	virtual void invoke() override;
	virtual void enable() override;
	virtual void disable() override;
	virtual bool avialable() override;
	void initTimer();

protected:
	virtual void invokeNow(int timerId) override;
	virtual void refreshPid() override;
	virtual void checkAndUpdateHealth() override;
	int getStartInterval();
	std::chrono::system_clock::time_point getStartTime();

protected:
	std::unique_ptr<std::chrono::system_clock::time_point> m_nextLaunchTime;
	std::string m_startIntervalValue;
	int m_startInterval;
	int m_bufferTime;
	int m_timerId;
	std::shared_ptr<AppProcess> m_bufferProcess;
};

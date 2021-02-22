#include <algorithm>

#include "../../common/DateTime.h"
#include "../../common/DurationParse.h"
#include "../../common/Utility.h"
#include "../../common/croncpp.h"
#include "ApplicationCron.h"

ApplicationCron::ApplicationCron()
{
	const static char fname[] = "ApplicationCron::ApplicationCron() ";
	LOG_DBG << fname << "Entered.";
}

ApplicationCron::~ApplicationCron()
{
	const static char fname[] = "ApplicationCron::~ApplicationCron() ";
	LOG_DBG << fname << "Entered.";
}

void ApplicationCron::FromJson(const std::shared_ptr<ApplicationCron> &app, const web::json::value &jsonObj)
{
	DurationParse duration;
	std::shared_ptr<Application> fatherApp = app;
	Application::FromJson(fatherApp, jsonObj);
	app->m_startIntervalValue = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds);
	app->m_bufferTimeValue = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_interval_timeout);
	app->m_bufferTime = duration.parse(app->m_bufferTimeValue);

	app->m_cron = cron::make_cron(app->m_startIntervalValue);
	cron::cron_next(app->m_cron, ACE_OS::time()); // used to throw exception for invalid format
}

web::json::value ApplicationCron::AsJson(bool returnRuntimeInfo)
{
	const static char fname[] = "ApplicationCron::AsJson() ";
	LOG_DBG << fname << "Entered.";
	web::json::value result = ApplicationShortRun::AsJson(returnRuntimeInfo);
	result[JSON_KEY_SHORT_APP_cron_interval] = web::json::value::boolean(true);
	return result;
}

void ApplicationCron::initTimer()
{
	const static char fname[] = "ApplicationCron::initTimer() ";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// 1. clean old timer
	this->cancelTimer(m_timerId);

	// 2. reg new timer
	auto beginTime = std::max(std::chrono::system_clock::now(), this->getStartTime());
	// beginTime = std::chrono::time_point_cast<std::chrono::minutes>(beginTime);

	auto nextTime = cron::cron_next(m_cron, std::chrono::system_clock::to_time_t(beginTime));
	auto diffSeconds = std::abs(nextTime - ACE_OS::time());
	if (diffSeconds == 1)
	{
		beginTime += std::chrono::minutes(1);
		nextTime = cron::cron_next(m_cron, std::chrono::system_clock::to_time_t(beginTime));
		diffSeconds = std::abs(nextTime - ACE_OS::time());
	}
	assert(nextTime > ACE_OS::time());

	int64_t sleepMilliseconds = 1000L * diffSeconds; // convert to milliseconds
	sleepMilliseconds += 2;							 // add 2 miliseconds buffer to avoid 59:59
	m_timerId = this->registerTimer(sleepMilliseconds, 0, std::bind(&ApplicationCron::invokeNow, this, std::placeholders::_1), __FUNCTION__);

	m_nextLaunchTime = std::make_unique<std::chrono::system_clock::time_point>(std::chrono::system_clock::from_time_t(nextTime));
	LOG_DBG << fname << this->getName() << "cron beginTime=" << DateTime::formatISO8601Time(beginTime) << " m_nextLaunchTime=" << DateTime::formatISO8601Time(*m_nextLaunchTime) << ", will sleep " << diffSeconds << " seconds ";
}

void ApplicationCron::invokeNow(int timerId)
{
	ApplicationShortRun::invokeNow(timerId);
	initTimer();
}

void ApplicationCron::dump()
{
	const static char fname[] = "ApplicationCron::dump() ";

	ApplicationShortRun::dump();
	LOG_DBG << fname << "m_cron:" << cron::to_string(m_cron);
}

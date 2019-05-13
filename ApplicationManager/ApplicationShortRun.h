#ifndef APPLICATION_DEFINITION_SOHORT_RUN_H
#define APPLICATION_DEFINITION_SOHORT_RUN_H

#include <memory>
#include <string>
#include <map>
#include <mutex>
#include "Application.h"

/**
* @class Application
*
* @brief An Short Running Application will start periodly.
*
*/
class ApplicationShortRun : public Application
{
public:
	ApplicationShortRun();
	virtual ~ApplicationShortRun();

	static void FromJson(std::shared_ptr<ApplicationShortRun>& app, const web::json::object& jobj);

	virtual void invoke() override;
	virtual void invokeNow(int timerId) override;
	virtual void start() override;
	virtual void stop() override;
	virtual web::json::value AsJson(bool returnRuntimeInfo) override;
	void initTimer();
	virtual void refreshPid() override;
	int getStartInterval();
	std::chrono::system_clock::time_point getStartTime();
	virtual bool avialable() override;
	virtual void dump() override;
protected:
	std::chrono::system_clock::time_point m_startTime;
	int m_startInterval;
	int m_bufferTime;
	int m_timerId;
	std::shared_ptr<Process> m_bufferProcess;
};

#endif 
#pragma once

#include "../../common/croncpp.h"
#include "ApplicationShortRun.h"

//////////////////////////////////////////////////////////////////////////
/// An Short Running Application will start based on Cron expr.
//////////////////////////////////////////////////////////////////////////
class ApplicationCron : public ApplicationShortRun
{
public:
	ApplicationCron();
	virtual ~ApplicationCron();

	static void FromJson(const std::shared_ptr<ApplicationCron> &app, const web::json::value &jsonObj) noexcept(false);
	virtual web::json::value AsJson(bool returnRuntimeInfo) override;
	virtual void dump() override;

	virtual void initTimer() override;

protected:
	virtual void invokeNow(int timerId) override;

protected:
	cron::cronexpr m_cron;
};

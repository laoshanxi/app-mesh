#pragma once

#include "ApplicationShortRun.h"

//////////////////////////////////////////////////////////////////////////
/// An Period Application will start periodly but keep running all the time.
//////////////////////////////////////////////////////////////////////////
class ApplicationPeriodRun :public ApplicationShortRun
{
public:
	ApplicationPeriodRun();
	virtual ~ApplicationPeriodRun();

	static void FromJson(std::shared_ptr<ApplicationPeriodRun>& app, const web::json::value& jobj) noexcept(false);
	virtual web::json::value AsJson(bool returnRuntimeInfo) override;

	virtual void refreshPid() override;

	virtual void dump() override;
};

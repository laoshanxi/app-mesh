#pragma once

#include <memory>
#include <string>
#include "Application.h"

//////////////////////////////////////////////////////////////////////////
/// An Initialize Application is pre-start cmd
///  and change to normal app when finished.
//////////////////////////////////////////////////////////////////////////
class ApplicationInitialize : public Application
{
public:
	ApplicationInitialize();
	virtual ~ApplicationInitialize();

	static void FromJson(std::shared_ptr<ApplicationInitialize> &app, const web::json::value &jobj) noexcept(false);
	virtual web::json::value AsJson(bool returnRuntimeInfo) override;
	virtual void dump() override;

	virtual void enable() override;
	virtual void disable() override;
	virtual bool avialable() override;
	virtual void invoke() override;

protected:
	web::json::value m_application;
	bool m_executed;
};

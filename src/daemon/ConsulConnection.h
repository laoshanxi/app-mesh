#pragma once

#include <memory>
#include <map>
#include <string>
#include <thread>
#include <cpprest/http_msg.h>
#include "TimerHandler.h"

class ConsulConnection :public TimerHandler
{
public:
	ConsulConnection();
	virtual ~ConsulConnection();
	static std::shared_ptr<ConsulConnection>& instance();
	void initTimer();

private:
	virtual void reportStatus(int timerId = 0);
	virtual void refreshSession(int timerId = 0);

	web::http::http_response requestHttp(const web::http::method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body);
	std::string requestSessionId();
	std::string renewSessionId();

private:
	std::recursive_mutex m_mutex;
	std::string m_consulUrl;
	std::string m_sessionId;
	int m_ssnRenewTimerId;
	int m_reportStatusTimerId;
};


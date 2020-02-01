#pragma once

#include <memory>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <cpprest/http_msg.h>
#include <cpprest/json.h>
#include "TimerHandler.h"

class ConsulConnection :public TimerHandler
{
	struct ConsulStatus {
		static std::shared_ptr<ConsulStatus> FromJson(const web::json::value& json);
		web::json::value AsJson();

		web::json::value m_resource;
		std::map<std::string, web::json::value> m_apps;
	};
	struct ConsulTask {
		static std::shared_ptr<ConsulTask> FromJson(const web::json::value& jobj);
		web::json::value AsJson();

		std::map<std::string, int> m_replications;
		std::map<std::string, web::json::value> m_apps;
	};
	//struct ConsulWorker {
	//	static std::shared_ptr<ConsulWorker> FromJson(const web::json::value& jobj);
	//	web::json::value AsJson();
	//};
	struct ConsulTopology {
		static std::shared_ptr<ConsulTopology> FromJson(const web::json::value& jobj);
		web::json::value AsJson();

		std::set<std::string> m_apps;
	};
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
	std::map<std::string, web::json::value> retrieveTopology();

private:
	std::recursive_mutex m_mutex;
	std::string m_consulUrl;
	std::string m_sessionId;
	int m_ssnRenewTimerId;
	int m_reportStatusTimerId;
};


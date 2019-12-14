#ifndef REST_HANDLER_H
#define REST_HANDLER_H

#include <cpprest/http_client.h>
#include <cpprest/http_listener.h> // HTTP server 
#include "TimerHandler.h"
#include "../common/HttpRequest.h"
#include "../prom_exporter/counter.h"
#include "../prom_exporter/registry.h"

using namespace web;
using namespace http;
using namespace utility;
using namespace http::experimental::listener;

class Application;
//////////////////////////////////////////////////////////////////////////
// REST service
//////////////////////////////////////////////////////////////////////////
class RestHandler : public TimerHandler
{
public:
	explicit RestHandler(std::string ipaddress, int port);
	virtual ~RestHandler();

protected:
	void open();
	void close();

private:
	void handleRest(const http_request& message, std::map<utility::string_t, std::function<void(const HttpRequest&)>>& restFunctions);
	void bindRestMethod(web::http::method method, std::string path, std::function< void(const HttpRequest&)> func);
	void handle_get(const HttpRequest& message);
	void handle_put(const HttpRequest& message);
	void handle_post(const HttpRequest& message);
	void handle_delete(const HttpRequest& message);
	void handle_options(const HttpRequest& message);
	void handle_error(pplx::task<void>& t);

	std::string verifyToken(const HttpRequest& message);
	std::string getTokenUser(const HttpRequest& message);
	bool permissionCheck(const HttpRequest& message, const std::string& permission);
	std::string getTokenStr(const HttpRequest& message);
	std::string createToken(const std::string& uname, const std::string& passwd, int timeoutSeconds);
	void cleanTempApp(int timerId = 0);
	void cleanTempAppByName(std::string appNameStr);

	void apiLogin(const HttpRequest& message);
	void apiAuth(const HttpRequest& message);
	void apiGetApp(const HttpRequest& message);
	std::shared_ptr<Application> apiRunParseApp(const HttpRequest& message, int& timeout);
	void apiRunAsync(const HttpRequest& message);
	void apiRunSync(const HttpRequest& message);
	void apiRunAsyncOut(const HttpRequest& message);
	void apiGetAppOutput(const HttpRequest& message);
	void apiGetApps(const HttpRequest& message);
	void apiGetResources(const HttpRequest& message);
	void apiRegApp(const HttpRequest& message);
	void apiEnableApp(const HttpRequest& message);
	void apiDisableApp(const HttpRequest& message);
	void apiDeleteApp(const HttpRequest& message);
	void apiFileDownload(const HttpRequest& message);
	void apiFileUpload(const HttpRequest& message);
	void apiGetTags(const HttpRequest& message);
	void apiSetTags(const HttpRequest& message);
	void apiTagSet(const HttpRequest& message);
	void apiTagDel(const HttpRequest& message);
	void apiGetPermissions(const HttpRequest& message);
	void apiGetBasicConfig(const HttpRequest& message);
	void apiSetBasicConfig(const HttpRequest& message);
	void apiChangePassword(const HttpRequest& message);
	void apiLockUser(const HttpRequest& message);
	void apiUnLockUser(const HttpRequest& message);

	http_response requestHttp(const method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body, const std::string& token);

private:
	std::shared_ptr<http_listener> m_listener;
	// API functions
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restGetFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restPutFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restPstFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restDelFunctions;

	std::recursive_mutex m_mutex;
	// key: timerId, value: appName
	std::map<int, std::string> m_tempAppsForClean;

	// prometheus
	prometheus::Counter* m_promScrapeCounter;
	prometheus::Counter* m_restGetCounter;
	prometheus::Counter* m_restPutCounter;
	prometheus::Counter* m_restDelCounter;
	prometheus::Counter* m_restPostCounter;
};

#endif

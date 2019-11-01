#ifndef REST_HANDLER_H
#define REST_HANDLER_H

#include <cpprest/http_client.h>
#include <cpprest/http_listener.h> // HTTP server 
#include "../common/HttpRequest.h"

using namespace web;
using namespace http;
using namespace utility;
using namespace http::experimental::listener;

//////////////////////////////////////////////////////////////////////////
// REST service
//////////////////////////////////////////////////////////////////////////
class RestHandler
{
public:
	explicit RestHandler(std::string ipaddress, int port);
	virtual ~RestHandler();

protected:
	void open();
	void close();

private:
	void handleRest(const http_request& message, std::map<utility::string_t, std::function<void(const HttpRequest&)>>& restFunctions);
	void bindRest(web::http::method method, std::string path, std::function< void(const HttpRequest&)> func);
	void handle_get(const HttpRequest& message);
	void handle_put(const HttpRequest& message);
	void handle_post(const HttpRequest& message);
	void handle_delete(const HttpRequest& message);
	void handle_options(const HttpRequest& message);
	void handle_error(pplx::task<void>& t);

	std::string tokenCheck(const HttpRequest& message);
	std::string getTokenUser(const HttpRequest& message);
	bool permissionCheck(const HttpRequest& message, const std::string& permission);
	std::string getToken(const HttpRequest& message);
	std::string createToken(const std::string& uname, const std::string& passwd, int timeoutSeconds);

	void apiLogin(const HttpRequest& message);
	void apiAuth(const HttpRequest& message);
	void apiGetApp(const HttpRequest& message);
	void apiAsyncRun(const HttpRequest& message);
	void apiSyncRun(const HttpRequest& message);
	void apiAsyncRunOut(const HttpRequest& message);
	void apiGetAppOutput(const HttpRequest& message);
	void apiGetApps(const HttpRequest& message);
	void apiGetResources(const HttpRequest& message);
	void apiRegApp(const HttpRequest& message);
	void apiRegShellApp(const HttpRequest& message);
	void apiControlApp(const HttpRequest& message);
	void apiDeleteApp(const HttpRequest& message);
	void apiFileDownload(const HttpRequest& message);
	void apiFileUpload(const HttpRequest& message);
	void apiGetTags(const HttpRequest& message);
	void apiSetTags(const HttpRequest& message);
	void apiTagSet(const HttpRequest& message);
	void apiTagDel(const HttpRequest& message);
	void apiLoglevel(const HttpRequest& message);
	void apiGetPermissions(const HttpRequest& message);

	http_response requestHttp(const method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body, const std::string& token);

private:
	std::shared_ptr<http_listener> m_listener;
	// API functions
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restGetFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restPutFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restPstFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restDelFunctions;

};

#endif

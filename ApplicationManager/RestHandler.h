#ifndef REST_HANDLER_H
#define REST_HANDLER_H

#include <cpprest/http_client.h>
#include <cpprest/http_listener.h> // HTTP server 

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
	void handleRest(http_request& message, std::map<utility::string_t, std::function<void(http_request&)>>& restFunctions);
	void bindRest(web::http::method method, std::string path, std::function< void(http_request&)> func);
	void handle_get(http_request message);
	void handle_put(http_request message);
	void handle_post(http_request message);
	void handle_delete(http_request message);
	void handle_error(pplx::task<void>& t);

	bool permissionCheck(const http_request& message, const std::string& permission);
	std::string getToken(const http_request& message);
	std::string createToken(const std::string& uname, const std::string& passwd, int timeoutSeconds);

	void apiLogin(const http_request& message);
	void apiAuth(const http_request& message);
	void apiGetApp(const http_request& message);
	void apiRunApp(const http_request& message);
	void apiWaitRunApp(const http_request& message);
	void apiRunOutput(const http_request& message);
	void apiAppOutput(const http_request& message);
	void apiGetApps(const http_request& message);
	void apiGetResources(const http_request& message);
	void apiRegApp(const http_request& message);
	void apiRegShellApp(const http_request& message);
	void apiControlApp(const http_request& message);
	void apiDeleteApp(const http_request& message);
	void apiDownloadFile(const http_request& message);
	void apiUploadFile(const http_request& message);
	void apiGetTags(const http_request& message);
	void apiSetTags(const http_request& message);
	void apiLoglevel(const http_request& message);

private:
	std::shared_ptr<http_listener> m_listener;
	// API functions
	std::map<utility::string_t, std::function<void(http_request&)>> m_restGetFunctions;
	std::map<utility::string_t, std::function<void(http_request&)>> m_restPutFunctions;
	std::map<utility::string_t, std::function<void(http_request&)>> m_restPstFunctions;
	std::map<utility::string_t, std::function<void(http_request&)>> m_restDelFunctions;

};
#endif

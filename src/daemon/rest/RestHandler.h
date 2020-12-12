#pragma once
#include <functional>

#include <cpprest/http_listener.h> // HTTP server

#include "PrometheusRest.h"

class Application;
/// <summary>
/// REST service handle class, all REST request entrypoint
/// </summary>
class RestHandler : public PrometheusRest
{
public:
	explicit RestHandler(bool forward2TcpServer);
	virtual ~RestHandler();

protected:
	virtual void open();
	void close();

	void checkAppAccessPermission(const HttpRequest &message, const std::string &appName, bool requestWrite);
	int getHttpQueryValue(const HttpRequest &message, const std::string &key, int defaultValue, int min, int max) const;

	void apiLogin(const HttpRequest &message);
	void apiAuth(const HttpRequest &message);
	void apiGetApp(const HttpRequest &message);
	std::shared_ptr<Application> apiRunParseApp(const HttpRequest &message);
	void apiRunAsync(const HttpRequest &message);
	void apiRunSync(const HttpRequest &message);
	void apiRunAsyncOut(const HttpRequest &message);
	void apiGetAppOutput(const HttpRequest &message);
	void apiGetApps(const HttpRequest &message);
	void apiGetResources(const HttpRequest &message);
	void apiRegApp(const HttpRequest &message);
	void apiEnableApp(const HttpRequest &message);
	void apiDisableApp(const HttpRequest &message);
	void apiDeleteApp(const HttpRequest &message);
	void apiFileDownload(const HttpRequest &message);
	void apiFileUpload(const HttpRequest &message);
	void apiGetLabels(const HttpRequest &message);
	void apiAddLabel(const HttpRequest &message);
	void apiDeleteLabel(const HttpRequest &message);
	void apiGetUserPermissions(const HttpRequest &message);
	void apiGetBasicConfig(const HttpRequest &message);
	void apiSetBasicConfig(const HttpRequest &message);
	void apiUserChangePwd(const HttpRequest &message);
	void apiUserLock(const HttpRequest &message);
	void apiUserUnlock(const HttpRequest &message);
	void apiUserAdd(const HttpRequest &message);
	void apiUserDel(const HttpRequest &message);
	void apiUserList(const HttpRequest &message);
	void apiRoleView(const HttpRequest &message);
	void apiRoleUpdate(const HttpRequest &message);
	void apiRoleDelete(const HttpRequest &message);
	void apiUserGroupsView(const HttpRequest &message);
	void apiListPermissions(const HttpRequest &message);
	void apiHealth(const HttpRequest &message);
	void apiRestMetrics(const HttpRequest &message); // not for Prometheus

protected:
	std::unique_ptr<web::http::experimental::listener::http_listener> m_listener;
};

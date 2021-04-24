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
	virtual void open() override;
	void close();

	void checkAppAccessPermission(const HttpRequest &message, const std::string &appName, bool requestWrite);
	int getHttpQueryValue(const HttpRequest &message, const std::string &key, int defaultValue, int min, int max) const;

	void apiUserLogin(const HttpRequest &message);
	void apiUserAuth(const HttpRequest &message);
	void apiAppView(const HttpRequest &message);
	void apiAppOutputView(const HttpRequest &message);
	void apiAppsView(const HttpRequest &message);

	std::shared_ptr<Application> parseAndRegRunApp(const HttpRequest &message);
	void apiRunAsync(const HttpRequest &message);
	void apiRunSync(const HttpRequest &message);
	void apiRunAsyncOut(const HttpRequest &message);

	void apiCloudAppsView(const HttpRequest &message);
	void apiCloudAppAdd(const HttpRequest &message);
	void apiCloudAppDel(const HttpRequest &message);
	void apiCloudHostView(const HttpRequest &message);

	void apiResourceView(const HttpRequest &message);

	void apiAppAdd(const HttpRequest &message);
	void apiAppEnable(const HttpRequest &message);
	void apiAppDisable(const HttpRequest &message);
	void apiAppDelete(const HttpRequest &message);

	void apiFileDownload(const HttpRequest &message);
	void apiFileUpload(const HttpRequest &message);

	void apiLabelsView(const HttpRequest &message);
	void apiLabelAdd(const HttpRequest &message);
	void apiLabelDel(const HttpRequest &message);

	void apiBasicConfigView(const HttpRequest &message);
	void apiBasicConfigSet(const HttpRequest &message);

	void apiPermissionsView(const HttpRequest &message);
	void apiUserPermissionsView(const HttpRequest &message);
	void apiUserChangePwd(const HttpRequest &message);
	void apiUserLock(const HttpRequest &message);
	void apiUserUnlock(const HttpRequest &message);
	void apiUserAdd(const HttpRequest &message);
	void apiUserDel(const HttpRequest &message);
	void apiUsersView(const HttpRequest &message);
	void apiUserGroupsView(const HttpRequest &message);

	void apiRolesView(const HttpRequest &message);
	void apiRoleUpdate(const HttpRequest &message);
	void apiRoleDelete(const HttpRequest &message);

	void apiHealth(const HttpRequest &message);
	void apiRestMetrics(const HttpRequest &message); // not for Prometheus

protected:
	std::unique_ptr<web::http::experimental::listener::http_listener> m_listener;
};

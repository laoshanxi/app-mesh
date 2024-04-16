#pragma once

#include <functional>

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>

#include "PrometheusRest.h"

class Application;
/// <summary>
/// REST service handle class, all REST request entrypoint
/// </summary>
class RestHandler : public PrometheusRest
{
public:
	explicit RestHandler();
	virtual ~RestHandler();

protected:
	void checkAppAccessPermission(const HttpRequest &message, const std::string &appName, bool requestWrite);
	long getHttpQueryValue(const HttpRequest &message, const std::string &key, long defaultValue, long min, long max) const;
	std::string getHttpQueryString(const HttpRequest &message, const std::string &key) const;
	std::string regexSearch(const std::string &value, const char *regex);
	std::tuple<std::string, std::string> regexSearch2(const std::string &value, const char *regex);

	nlohmann::json createJwtResponse(const HttpRequest &message, const std::string &uname, int timeoutSeconds, const std::string &ugroup, const std::string *token = nullptr);
	void apiUserLogin(const HttpRequest &message);
	void apiUserLogoff(const HttpRequest &message);
	void apiUserTokenRenew(const HttpRequest &message);
	void apiUserAuth(const HttpRequest &message);
	void apiUserTotpSecret(const HttpRequest &message);
	void apiUserTotpSetup(const HttpRequest &message);
	void apiUserTotpValidate(const HttpRequest &message);
	void apiUserTotpDisable(const HttpRequest &message);

	void apiAppView(const HttpRequest &message);
	void apiAppOutputView(const HttpRequest &message);
	void apiAppsView(const HttpRequest &message);

	std::shared_ptr<Application> parseAndRegRunApp(const HttpRequest &message);
	void apiRunAsync(const HttpRequest &message);
	void apiRunSync(const HttpRequest &message);

	void apiCloudAppsView(const HttpRequest &message);
	void apiCloudAppView(const HttpRequest &message);
	void apiCloudAppOutputView(const HttpRequest &message);
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
	void apiUserView(const HttpRequest &message);
	void apiUserAdd(const HttpRequest &message);
	void apiUserDel(const HttpRequest &message);
	void apiUsersView(const HttpRequest &message);
	void apiUserGroupsView(const HttpRequest &message);

	void apiRolesView(const HttpRequest &message);
	void apiRoleUpdate(const HttpRequest &message);
	void apiRoleDelete(const HttpRequest &message);

	void apiHealth(const HttpRequest &message);
	void apiRestMetrics(const HttpRequest &message); // not for Prometheus
};

typedef ACE_Singleton<RestHandler, ACE_Null_Mutex> RESTHANDLER;

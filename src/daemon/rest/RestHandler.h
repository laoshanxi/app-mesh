// src/daemon/rest/RestHandler.h
#pragma once

#include <functional>

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>

#include "EventDispatcher.h"
#include "PrometheusRest.h"
#include "RestBase.h"

class Application;
/// <summary>
/// REST service handle class, all REST request entrypoint
/// </summary>
class RestHandler : public RestBase
{
public:
	explicit RestHandler();
	virtual ~RestHandler();

	static long getHttpQueryValue(const HttpRequest &message, const std::string &key, long defaultValue, long min, long max);
	static std::string getHttpQueryString(const HttpRequest &message, const std::string &key);

	// Static content serving utilities
	static const std::string &getOpenApiContent();
	static const std::string &getIndexHtmlContent();

	// Prometheus metrics, forwarded to the owned exporter so that callers keep using RESTHANDLER
	std::shared_ptr<CounterMetric> createPromCounter(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels);
	std::shared_ptr<GaugeMetric> createPromGauge(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels);
	bool collected();

protected:
	/// <summary>
	/// override RestBase::handleRest() to count REST request metrics
	/// </summary>
	/// <param name="message"></param>
	/// <param name="restFunctions"></param>
	virtual void handleRest(const std::shared_ptr<HttpRequest> &message, const std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> &restFunctions) override;

	void checkAppAccessPermission(const std::shared_ptr<HttpRequest> &message, const std::string &appName, bool requestWrite);
	std::string regexSearch(const std::string &value, const char *regex);
	std::tuple<std::string, std::string> regexSearch2(const std::string &value, const char *regex);

	nlohmann::json createJwtResponse(const std::shared_ptr<HttpRequest> &message, const std::string &uname, int timeoutSeconds, const std::string &ugroup, const std::string &audience, const std::string *token = nullptr, const std::string *refreshToken = nullptr);
	void apiUserLogin(const std::shared_ptr<HttpRequest> &message);
	void apiUserLogoff(const std::shared_ptr<HttpRequest> &message);
	void apiUserTokenRenew(const std::shared_ptr<HttpRequest> &message);
	void apiUserAuth(const std::shared_ptr<HttpRequest> &message);
	void apiUserTotpSecret(const std::shared_ptr<HttpRequest> &message);
	void apiUserTotpSetup(const std::shared_ptr<HttpRequest> &message);
	void apiUserTotpValidate(const std::shared_ptr<HttpRequest> &message);
	void apiUserTotpDisable(const std::shared_ptr<HttpRequest> &message);

	void apiAppView(const std::shared_ptr<HttpRequest> &message);
	void apiAppOutputView(const std::shared_ptr<HttpRequest> &message);
	void apiAppsView(const std::shared_ptr<HttpRequest> &message);

	std::shared_ptr<Application> parseAndRegRunApp(const std::shared_ptr<HttpRequest> &message);
	void apiRunAsync(const std::shared_ptr<HttpRequest> &message);
	void apiRunSync(const std::shared_ptr<HttpRequest> &message);

	void apiSendMessage(const std::shared_ptr<HttpRequest> &message);		  // client send message and wait for response with async REST call
	void apiRemoveMessage(const std::shared_ptr<HttpRequest> &message);		  // client remove message
	void apiGetMessage(const std::shared_ptr<HttpRequest> &message);		  // server get message with block and iterator REST call
	void apiSendMessageResponse(const std::shared_ptr<HttpRequest> &message); // server send response (then server response to client apiSendMessage)

	void apiCloudResourceView(const std::shared_ptr<HttpRequest> &message);

	void apiResourceView(const std::shared_ptr<HttpRequest> &message);

	void apiAppAdd(const std::shared_ptr<HttpRequest> &message);
	void apiAppEnable(const std::shared_ptr<HttpRequest> &message);
	void apiAppDisable(const std::shared_ptr<HttpRequest> &message);
	void apiAppDelete(const std::shared_ptr<HttpRequest> &message);

	void apiFileDownload(const std::shared_ptr<HttpRequest> &message);
	void apiFileUpload(const std::shared_ptr<HttpRequest> &message);

	void apiLabelsView(const std::shared_ptr<HttpRequest> &message);
	void apiLabelAdd(const std::shared_ptr<HttpRequest> &message);
	void apiLabelDel(const std::shared_ptr<HttpRequest> &message);

	void apiBasicConfigView(const std::shared_ptr<HttpRequest> &message);
	void apiBasicConfigSet(const std::shared_ptr<HttpRequest> &message);

	void apiPermissionsView(const std::shared_ptr<HttpRequest> &message);
	void apiUserPermissionsView(const std::shared_ptr<HttpRequest> &message);
	void apiUserChangePwd(const std::shared_ptr<HttpRequest> &message);
	void apiUserLock(const std::shared_ptr<HttpRequest> &message);
	void apiUserUnlock(const std::shared_ptr<HttpRequest> &message);
	void apiUserView(const std::shared_ptr<HttpRequest> &message);
	void apiUserAdd(const std::shared_ptr<HttpRequest> &message);
	void apiUserDel(const std::shared_ptr<HttpRequest> &message);
	void apiUsersView(const std::shared_ptr<HttpRequest> &message);
	void apiUserGroupsView(const std::shared_ptr<HttpRequest> &message);

	void apiRolesView(const std::shared_ptr<HttpRequest> &message);
	void apiRoleUpdate(const std::shared_ptr<HttpRequest> &message);
	void apiRoleDelete(const std::shared_ptr<HttpRequest> &message);

	void apiHealth(const std::shared_ptr<HttpRequest> &message);
	void apiRestMetrics(const std::shared_ptr<HttpRequest> &message);

	void apiAppSubscribe(const std::shared_ptr<HttpRequest> &message);
	void apiAppUnsubscribe(const std::shared_ptr<HttpRequest> &message);

	static bool buildDeliveryCallback(const std::shared_ptr<HttpRequest> &message, ConnectionKey &connKey, DeliveryCallback &deliveryCb);

	// Static content handlers
	void apiOpenApi(const std::shared_ptr<HttpRequest> &message);
	void apiSwagger(const std::shared_ptr<HttpRequest> &message);
	void apiIndex(const std::shared_ptr<HttpRequest> &message);

private:
	// Prometheus metrics exporter (composition, was a base class before)
	std::shared_ptr<PrometheusRest> m_metrics;
};

typedef ACE_Singleton<RestHandler, ACE_Null_Mutex> RESTHANDLER;

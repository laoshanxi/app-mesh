#include <chrono>

#include <boost/algorithm/string_regex.hpp>
#include <cpr/cpr.h>

#include "../../common/DurationParse.h"
#include "../../common/Utility.h"
#include "../../common/os/chown.hpp"
#include "../../common/os/linux.hpp"
#include "../Configuration.h"
#include "../Label.h"
#include "../ResourceCollection.h"
#include "../application/Application.h"
#include "../consul/ConsulConnection.h"
#include "../security/Security.h"
#include "../security/User.h"
#include "HttpRequest.h"
#include "PrometheusRest.h"
#include "RestHandler.h"

// 1. Authentication
constexpr auto REST_PATH_LOGIN = "/appmesh/login";
constexpr auto REST_PATH_AUTH = "/appmesh/auth";

// 2. View Application
constexpr auto REST_PATH_APP_VIEW = R"(/appmesh/app/([^/\*]+))";
constexpr auto REST_PATH_APP_OUT_VIEW = R"(/appmesh/app/([^/\*]+)/output)";
constexpr auto REST_PATH_APP_ALL_VIEW = "/appmesh/applications";
constexpr auto REST_PATH_APP_HEALTH = R"(/appmesh/app/([^/\*]+)/health)";

// 3. Cloud Application
constexpr auto REST_PATH_CLOUD_APP_ALL_VIEW = "/appmesh/cloud/applications";
constexpr auto REST_PATH_CLOUD_APP_VIEW = R"(/appmesh/cloud/app/([^/\*]+))";
constexpr auto REST_PATH_CLOUD_APP_OUT_VIEW = R"(/appmesh/cloud/app/([^/\*]+)/output/([^/\*]+))";
constexpr auto REST_PATH_CLOUD_APP_ADD = R"(/appmesh/cloud/app/([^/\*]+))";
constexpr auto REST_PATH_CLOUD_APP_DELETE = R"(/appmesh/cloud/app/([^/\*]+))";
constexpr auto REST_PATH_CLOUD_NODES_VIEW = "/appmesh/cloud/nodes";

// 4. Manage Application
constexpr auto REST_PATH_APP_ADD = R"(/appmesh/app/([^/\*]+))";
constexpr auto REST_PATH_APP_ENABLE = R"(/appmesh/app/([^/\*]+)/enable)";
constexpr auto REST_PATH_APP_DISABLE = R"(/appmesh/app/([^/\*]+)/disable)";
constexpr auto REST_PATH_APP_DELETE = R"(/appmesh/app/([^/\*]+))";

// 5. Operate Application
constexpr auto REST_PATH_APP_RUN_ASYNC = "/appmesh/app/run";
constexpr auto REST_PATH_APP_RUN_SYNC = "/appmesh/app/syncrun";

// 6. File Management
constexpr auto REST_PATH_FILE_DOWNLOAD = "/appmesh/file/download";
constexpr auto REST_PATH_FILE_UPLOAD = "/appmesh/file/upload";

// 7. Label Management
constexpr auto REST_PATH_LABEL_VIEW_ALL = "/appmesh/labels";
constexpr auto REST_PATH_LABEL_ADD = R"(/appmesh/label/([^/\*]+))";
constexpr auto REST_PATH_LABEL_DELETE = R"(/appmesh/label/([^/\*]+))";

// 8. Config
constexpr auto REST_PATH_CONFIG_VIEW = "/appmesh/config";
constexpr auto REST_PATH_CONFIG_SET = "/appmesh/config";

// 9. Security
constexpr auto REST_PATH_SEC_USER_CHANGE_PWD = R"(/appmesh/user/([^/\*]+)/passwd)";
constexpr auto REST_PATH_SEC_USER_LOCK = R"(/appmesh/user/([^/\*]+)/lock)";
constexpr auto REST_PATH_SEC_USER_UNLOCK = R"(/appmesh/user/([^/\*]+)/unlock)";
constexpr auto REST_PATH_SEC_USER_ADD = R"(/appmesh/user/([^/\*]+))";
constexpr auto REST_PATH_SEC_USER_VIEW = "/appmesh/user/self";
constexpr auto REST_PATH_SEC_USER_DELETE = R"(/appmesh/user/([^/\*]+))";
constexpr auto REST_PATH_SEC_USER_MFA = "/appmesh/user/self/mfa";
constexpr auto REST_PATH_SEC_USER_MFA_DEL = R"(/appmesh/user/([^/\*]+)/mfa)";
constexpr auto REST_PATH_SEC_USER_VIEW_ALL = "/appmesh/users";
constexpr auto REST_PATH_SEC_ROLE_VIEW_ALL = "/appmesh/roles";
constexpr auto REST_PATH_SEC_ROLE_UPDATE = R"(/appmesh/role/([^/\*]+))";
constexpr auto REST_PATH_SEC_ROLE_DELETE = R"(/appmesh/role/([^/\*]+))";
constexpr auto REST_PATH_SEC_USER_PERM_VIEW = "/appmesh/user/permissions";
constexpr auto REST_PATH_SEC_PERM_VIEW_ALL = "/appmesh/permissions";
constexpr auto REST_PATH_SEC_USER_GROUPS_VIEW = "/appmesh/user/groups";

// 10. metrics
constexpr auto REST_PATH_PROMETHEUS_METRICS = "/appmesh/metrics";
constexpr auto REST_PATH_RESOURCE_VIEW = "/appmesh/resources";

RestHandler::RestHandler() : PrometheusRest()
{
	// 1. Authentication
	bindRestMethod(web::http::methods::POST, REST_PATH_LOGIN, std::bind(&RestHandler::apiUserLogin, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_AUTH, std::bind(&RestHandler::apiUserAuth, this, std::placeholders::_1));

	// 2. View Application
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_VIEW, std::bind(&RestHandler::apiAppView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_OUT_VIEW, std::bind(&RestHandler::apiAppOutputView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_ALL_VIEW, std::bind(&RestHandler::apiAppsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_HEALTH, std::bind(&RestHandler::apiHealth, this, std::placeholders::_1));

	// 3. Cloud Application
	bindRestMethod(web::http::methods::GET, REST_PATH_CLOUD_APP_ALL_VIEW, std::bind(&RestHandler::apiCloudAppsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_CLOUD_APP_VIEW, std::bind(&RestHandler::apiCloudAppView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, REST_PATH_CLOUD_APP_ADD, std::bind(&RestHandler::apiCloudAppAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_CLOUD_APP_DELETE, std::bind(&RestHandler::apiCloudAppDel, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_CLOUD_NODES_VIEW, std::bind(&RestHandler::apiCloudHostView, this, std::placeholders::_1));

	// 4. Manage Application
	bindRestMethod(web::http::methods::PUT, REST_PATH_APP_ADD, std::bind(&RestHandler::apiAppAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_ENABLE, std::bind(&RestHandler::apiAppEnable, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_DISABLE, std::bind(&RestHandler::apiAppDisable, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_DELETE, std::bind(&RestHandler::apiAppDelete, this, std::placeholders::_1));

	// 5. Operate Application
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_RUN_ASYNC, std::bind(&RestHandler::apiRunAsync, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_RUN_SYNC, std::bind(&RestHandler::apiRunSync, this, std::placeholders::_1));

	// 6. File Management
	bindRestMethod(web::http::methods::GET, REST_PATH_FILE_DOWNLOAD, std::bind(&RestHandler::apiFileDownload, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_FILE_UPLOAD, std::bind(&RestHandler::apiFileUpload, this, std::placeholders::_1));

	// 7. Label Management
	bindRestMethod(web::http::methods::GET, REST_PATH_LABEL_VIEW_ALL, std::bind(&RestHandler::apiLabelsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, REST_PATH_LABEL_ADD, std::bind(&RestHandler::apiLabelAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_LABEL_DELETE, std::bind(&RestHandler::apiLabelDel, this, std::placeholders::_1));

	// 8. Config
	bindRestMethod(web::http::methods::GET, REST_PATH_CONFIG_VIEW, std::bind(&RestHandler::apiBasicConfigView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_CONFIG_SET, std::bind(&RestHandler::apiBasicConfigSet, this, std::placeholders::_1));

	// 9. Security
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_USER_CHANGE_PWD, std::bind(&RestHandler::apiUserChangePwd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_USER_LOCK, std::bind(&RestHandler::apiUserLock, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_USER_UNLOCK, std::bind(&RestHandler::apiUserUnlock, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, REST_PATH_SEC_USER_ADD, std::bind(&RestHandler::apiUserAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_USER_VIEW, std::bind(&RestHandler::apiUserView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_SEC_USER_DELETE, std::bind(&RestHandler::apiUserDel, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_USER_MFA, std::bind(&RestHandler::apiUserActiveMFA, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_SEC_USER_MFA_DEL, std::bind(&RestHandler::apiUserDeActiveMFA, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_USER_VIEW_ALL, std::bind(&RestHandler::apiUsersView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_ROLE_VIEW_ALL, std::bind(&RestHandler::apiRolesView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_ROLE_UPDATE, std::bind(&RestHandler::apiRoleUpdate, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_SEC_ROLE_DELETE, std::bind(&RestHandler::apiRoleDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_USER_PERM_VIEW, std::bind(&RestHandler::apiUserPermissionsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_PERM_VIEW_ALL, std::bind(&RestHandler::apiPermissionsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_USER_GROUPS_VIEW, std::bind(&RestHandler::apiUserGroupsView, this, std::placeholders::_1));

	// 10. metrics
	bindRestMethod(web::http::methods::GET, REST_PATH_PROMETHEUS_METRICS, std::bind(&RestHandler::apiRestMetrics, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_RESOURCE_VIEW, std::bind(&RestHandler::apiResourceView, this, std::placeholders::_1));
}

RestHandler::~RestHandler()
{
	const static char fname[] = "RestHandler::~RestHandler() ";
	LOG_INF << fname << "Entered";
}

void RestHandler::checkAppAccessPermission(const HttpRequest &message, const std::string &appName, bool requestWrite)
{
	auto tokenUserName = getJwtUserName(message);
	auto app = Configuration::instance()->getApp(appName);
	if (!Configuration::instance()->checkOwnerPermission(tokenUserName, app->getOwner(), app->getOwnerPermission(), requestWrite))
	{
		throw std::invalid_argument(Utility::stringFormat("User <%s> is not allowed to <%s> app <%s>", tokenUserName.c_str(), (requestWrite ? "EDIT" : "VIEW"), appName.c_str()));
	}
	if (requestWrite && appName == SEPARATE_REST_APP_NAME)
	{
		throw std::invalid_argument("REST service application is not allowed to <EDIT>");
	}
}

long RestHandler::getHttpQueryValue(const HttpRequest &message, const std::string &key, long defaultValue, long min, long max) const
{
	const static char fname[] = "RestHandler::getHttpQueryValue() ";

	auto querymap = message.m_querys;
	long rt = defaultValue;
	if (querymap.find((key)) != querymap.end())
	{
		auto value = querymap.find((key))->second;
		rt = DurationParse::parse(value);
		if (rt > 0)
		{
			if (min < max && (rt < min || rt > max))
				rt = defaultValue;
		}
		// if rt less than zero, do not update here.
	}
	LOG_DBG << fname << key << "=" << rt;
	return rt;
}

std::string RestHandler::getHttpQueryString(const HttpRequest &message, const std::string &key) const
{
	const static char fname[] = "RestHandler::getHttpQueryString() ";

	auto querymap = message.m_querys;
	std::string rt;
	if (querymap.find((key)) != querymap.end())
	{
		rt = (querymap.find((key))->second);
	}
	LOG_DBG << fname << key << "=" << rt;
	return rt;
}

std::string RestHandler::regexSearch(const std::string &value, const char *expr)
{
	const static char fname[] = "RestHandler::regexSearch() ";

	std::string result;
	boost::regex expression(expr);
	boost::smatch what;
	if (boost::regex_search(value, what, expression) && what.size() > 1)
	{
		// NOTE: start from position 1, skip the REST patch prefix
		for (size_t i = 1; i < what.size(); ++i)
		{
			if (what[i].matched)
			{
				result = Utility::stdStringTrim(what[i].str());
				if (result.length())
				{
					return result;
				}
				LOG_WAR << fname << "no data from path :" << value << " for regex expression: " << expr;
				throw std::invalid_argument("no data from path for regex search");
			}
		}
	}
	LOG_WAR << fname << "failed parse data from path :" << value << " for regex expression: " << expr;
	throw std::invalid_argument("failed to search data from regex expression");
}

std::tuple<std::string, std::string> RestHandler::regexSearch2(const std::string &value, const char *expr)
{
	const static char fname[] = "RestHandler::regexSearch2() ";

	std::string first, second;
	boost::regex expression(expr);
	boost::smatch what;
	if (boost::regex_search(value, what, expression) && what.size() > 1)
	{
		// NOTE: start from position 1, skip the REST patch prefix
		for (size_t i = 1; i < what.size(); ++i)
		{
			if (what[i].matched)
			{
				if (first.empty())
				{
					first = Utility::stdStringTrim(what[i].str());
				}
				else if (second.empty())
				{
					second = Utility::stdStringTrim(what[i].str());
					return std::make_tuple(first, second);
				}
			}
		}
	}
	LOG_WAR << fname << "failed parse data from path :" << value << " for regex expression: " << expr;
	throw std::invalid_argument("failed to search data from regex expression");
}

void RestHandler::apiAppEnable(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_ENABLE);

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->enableApp(appName);
	message.reply(web::http::status_codes::OK, convertText2Json(std::string("Enable <") + appName + "> success."));
}

void RestHandler::apiAppDisable(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_DISABLE);

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->disableApp(appName);
	message.reply(web::http::status_codes::OK, convertText2Json(std::string("Disable <") + appName + "> success."));
}

void RestHandler::apiAppDelete(const HttpRequest &message)
{
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_DELETE);
	if (Configuration::instance()->getApp(appName)->isCloudApp())
		throw std::invalid_argument("not allowed for cloud application");

	if (!(Configuration::instance()->getApp(appName)->getOwner() &&
		  Configuration::instance()->getApp(appName)->getOwner()->getName() == getJwtUserName(message)))
	{
		// only check delete permission for none-self app
		permissionCheck(message, PERMISSION_KEY_app_delete);
	}

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->removeApp(appName);
	message.reply(web::http::status_codes::OK, convertText2Json(Utility::stringFormat("Application <%s> removed.", appName.c_str())));
}

void RestHandler::apiFileDownload(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiFileDownload() ";

	permissionCheck(message, PERMISSION_KEY_file_download);
	if (0 == message.m_headers.count(HTTP_HEADER_KEY_file_path))
	{
		message.reply(web::http::status_codes::BadRequest, convertText2Json("header 'File-Path' not found"));
		return;
	}
	auto file = (message.m_headers.find(HTTP_HEADER_KEY_file_path)->second);
	if (!Utility::isFileExist(file))
	{
		message.reply(web::http::status_codes::NotAcceptable, convertText2Json("file not found"));
		return;
	}

	LOG_DBG << fname << "Downloading file <" << file << ">";

	auto fileInfo = os::fileStat(file);
	std::map<std::string, std::string> headers;
	headers[HTTP_HEADER_KEY_file_mode] = std::to_string(std::get<0>(fileInfo));
	headers[HTTP_HEADER_KEY_file_user] = std::to_string(std::get<1>(fileInfo));
	headers[HTTP_HEADER_KEY_file_group] = std::to_string(std::get<2>(fileInfo));
	std::string body = HttpRequest::emptyJson().dump();
	if (!(message.m_headers.count(web::http::header_names::user_agent) && message.m_headers.find(web::http::header_names::user_agent)->second == HTTP_USER_AGENT))
	{
		LOG_DBG << fname << "Downloading file not from App Mesh agent";
		auto wrapper = convertText2Json("download from TCP stream");
		wrapper[TCP_JSON_MSG_FILE] = file;
		body = wrapper.dump();
	}
	message.reply(web::http::status_codes::OK, body, headers, web::http::mime_types::application_octetstream);
}

void RestHandler::apiFileUpload(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiFileUpload() ";
	permissionCheck(message, PERMISSION_KEY_file_upload);
	if (0 == message.m_headers.count(HTTP_HEADER_KEY_file_path))
	{
		message.reply(web::http::status_codes::BadRequest, convertText2Json("header 'File-Path' not found"));
		return;
	}
	auto file = message.m_headers.find(HTTP_HEADER_KEY_file_path)->second;
	if (Utility::isFileExist(file))
	{
		message.reply(web::http::status_codes::Forbidden, convertText2Json("file already exist"));
		return;
	}

	LOG_DBG << fname << "Uploading file <" << file << ">";

	std::string body = HttpRequest::emptyJson().dump();
	if (!(message.m_headers.count(web::http::header_names::user_agent) && message.m_headers.find(web::http::header_names::user_agent)->second == HTTP_USER_AGENT))
	{
		LOG_DBG << fname << "Upload file not from App Mesh agent";
		auto wrapper = convertText2Json("upload from TCP stream");
		wrapper[TCP_JSON_MSG_FILE] = file;
		body = wrapper.dump();
	}
	message.reply(web::http::status_codes::OK, body, {}, web::http::mime_types::application_octetstream);
	// set permission
	if (Utility::isFileExist(file))
	{
		if (message.m_headers.count(HTTP_HEADER_KEY_file_mode))
			os::fileChmod(file, std::stoi(message.m_headers.find(HTTP_HEADER_KEY_file_mode)->second));
		if (message.m_headers.count(HTTP_HEADER_KEY_file_user) && message.m_headers.count(HTTP_HEADER_KEY_file_group))
			os::chown(std::stoi(message.m_headers.find(HTTP_HEADER_KEY_file_user)->second),
					  std::stoi(message.m_headers.find(HTTP_HEADER_KEY_file_group)->second),
					  file, false);
	}
}

void RestHandler::apiLabelsView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_view);
	message.reply(web::http::status_codes::OK, Configuration::instance()->getLabel()->AsJson());
}

void RestHandler::apiLabelAdd(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_set);

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto labelKey = regexSearch(path, REST_PATH_LABEL_ADD);

	auto querymap = message.m_querys;
	if (querymap.find((HTTP_QUERY_KEY_label_value)) != querymap.end())
	{
		auto value = (querymap.find((HTTP_QUERY_KEY_label_value))->second);

		Configuration::instance()->getLabel()->addLabel(labelKey, value);
		Configuration::instance()->saveConfigToDisk();

		message.reply(web::http::status_codes::OK, convertText2Json("Add label success"));
	}
	else
	{
		message.reply(web::http::status_codes::BadRequest, convertText2Json("query value required"));
	}
}

void RestHandler::apiLabelDel(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_delete);

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto labelKey = regexSearch(path, REST_PATH_LABEL_DELETE);

	Configuration::instance()->getLabel()->delLabel(labelKey);
	Configuration::instance()->saveConfigToDisk();

	message.reply(web::http::status_codes::OK, convertText2Json("Label delete success"));
}

void RestHandler::apiUserPermissionsView(const HttpRequest &message)
{
	const auto result = verifyToken(message);
	const auto userName = std::get<0>(result);
	const auto groupName = std::get<1>(result);
	const auto permissions = Security::instance()->getUserPermissions(userName, groupName);
	auto json = nlohmann::json::array();
	for (auto &perm : permissions)
	{
		json.push_back(std::string(perm));
	}
	message.reply(web::http::status_codes::OK, json);
}

void RestHandler::apiBasicConfigView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_config_view);

	auto config = Configuration::instance()->AsJson(false, getJwtUserName(message));
	message.reply(web::http::status_codes::OK, config);
}

void RestHandler::apiBasicConfigSet(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_config_set);

	auto json = message.extractJson();
	Configuration::instance()->hotUpdate(json);

	Configuration::instance()->saveConfigToDisk();

	apiBasicConfigView(message);
}

void RestHandler::apiUserChangePwd(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserChangePwd() ";

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_change_passwd);

	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_CHANGE_PWD);
	auto tokenUserName = getJwtUserName(message);
	if (pathUserName == "self")
	{
		pathUserName = tokenUserName;
	}
	if (!(message.m_headers.count(HTTP_HEADER_JWT_new_password)))
	{
		throw std::invalid_argument("can not find new password from header");
	}
	auto newPasswd = Utility::stdStringTrim(Utility::decode64((message.m_headers.find(HTTP_HEADER_JWT_new_password)->second)));

	if (newPasswd.length() < APPMESH_PASSWD_MIN_LENGTH)
	{
		throw std::invalid_argument("password length should be greater than 3");
	}

	Security::instance()->changeUserPasswd(tokenUserName, newPasswd);
	Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << tokenUserName << "> changed password";
	message.reply(web::http::status_codes::OK, convertText2Json("password changed success"));
}

void RestHandler::apiUserLock(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserLock() ";

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_lock_user);
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_LOCK);
	auto tokenUserName = getJwtUserName(message);

	if (pathUserName == JWT_ADMIN_NAME)
	{
		throw std::invalid_argument("User admin can not be locked");
	}

	Security::instance()->getUserInfo(pathUserName)->lock();
	Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> locked by " << tokenUserName;
	message.reply(web::http::status_codes::OK, convertText2Json("Lock user success"));
}

void RestHandler::apiUserUnlock(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserUnlock() ";

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_unlock_user);
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_UNLOCK);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->getUserInfo(pathUserName)->unlock();
	Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> unlocked by " << tokenUserName;
	message.reply(web::http::status_codes::OK, convertText2Json("Unlock user success"));
}

void RestHandler::apiUserAdd(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserAdd() ";

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_add_user);
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_ADD);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->addUser(pathUserName, message.extractJson());
	Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << pathUserName << "> added by " << tokenUserName;
	message.reply(web::http::status_codes::OK, convertText2Json("User add success"));
}

void RestHandler::apiUserView(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserView() ";

	auto tokenUserName = getJwtUserName(message);
	auto user = Security::instance()->getUserInfo(tokenUserName);
	if (user != nullptr)
	{
		auto userJson = user->AsJson();
		message.reply(web::http::status_codes::OK, User::clearConfidentialInfo(userJson));
	}
	else
	{
		LOG_WAR << fname << "no such user: " << tokenUserName;
		throw std::invalid_argument("no such user");
	}
}

void RestHandler::apiUserDel(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserDel() ";

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_delete_user);
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_DELETE);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->delUser(pathUserName);
	Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << pathUserName << "> deleted by " << tokenUserName;
	message.reply(web::http::status_codes::OK, convertText2Json("User delete success"));
}

void RestHandler::apiUserActiveMFA(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_user_mfa_active);
	auto userName = getJwtUserName(message);

	const auto user = Security::instance()->getUserInfo(userName);
	const auto mfaSecret = user->generateMfaKey();
	// otpauth://totp/{label}?secret={secret}&issuer={issuer}
	const auto totpUri = Utility::stringFormat("otpauth://totp/%s?secret=%s&issuer=%s",
											   userName.c_str(), mfaSecret.c_str(), "AppMesh");

	auto result = nlohmann::json();
	result[HTTP_BODY_KEY_MFA_URI] = nlohmann::json(Utility::encode64(totpUri));
	message.reply(web::http::status_codes::OK, result);

	Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
	ConsulConnection::instance()->saveSecurity();
}

void RestHandler::apiUserDeActiveMFA(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserDeActiveMFA() ";

	permissionCheck(message, PERMISSION_KEY_user_mfa_delete);
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_MFA_DEL);
	auto tokenUserName = getJwtUserName(message);
	auto userName = (pathUserName == "self") ? tokenUserName : pathUserName;

	auto user = Security::instance()->getUserInfo(userName);
	if (user != nullptr)
	{
		if (user->getName() != JWT_ADMIN_NAME && (pathUserName != "self" || pathUserName != tokenUserName))
		{
			throw std::invalid_argument("Only administrator have permission to deactive MFA for others");
		}
		user->deactiveMfa();
		message.reply(web::http::status_codes::OK, convertText2Json("2FA deactive success"));

		Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
		ConsulConnection::instance()->saveSecurity();
	}
	else
	{
		LOG_WAR << fname << "No such user exist: " << userName;
		throw std::invalid_argument("No such user exist");
	}
}

void RestHandler::apiUsersView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_get_users);

	auto users = Security::instance()->getUsersJson();
	for (auto &user : users.items())
	{
		User::clearConfidentialInfo(user.value());
	}

	message.reply(web::http::status_codes::OK, users);
}

void RestHandler::apiRolesView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_role_view);

	message.reply(web::http::status_codes::OK, Security::instance()->getRolesJson());
}

void RestHandler::apiRoleUpdate(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiRoleUpdate() ";

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_role_update);
	auto pathRoleName = regexSearch(path, REST_PATH_SEC_ROLE_UPDATE);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->addRole(message.extractJson(), pathRoleName);
	Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "Role <" << pathRoleName << "> updated by " << tokenUserName;
	message.reply(web::http::status_codes::OK, convertText2Json("Role update success"));
}

void RestHandler::apiRoleDelete(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiRoleDelete() ";

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_role_delete);

	auto pathRoleName = regexSearch(path, REST_PATH_SEC_ROLE_DELETE);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->delRole(pathRoleName);
	Security::instance()->save(Configuration::instance()->getJwt()->getJwtInterface());
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "Role <" << pathRoleName << "> deleted by " << tokenUserName;
	message.reply(web::http::status_codes::OK, convertText2Json("Role delete success"));
}

void RestHandler::apiUserGroupsView(const HttpRequest &message)
{
	auto groups = Security::instance()->getAllUserGroups();
	auto json = nlohmann::json::array();
	for (const auto &grp : groups)
	{
		json.push_back(std::string(grp));
	}
	message.reply(web::http::status_codes::OK, json);
}

void RestHandler::apiPermissionsView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_permission_list);

	auto permissions = Security::instance()->getAllPermissions();
	auto json = nlohmann::json::array();
	for (auto &perm : permissions)
	{
		json.push_back(std::string(perm));
	}
	message.reply(web::http::status_codes::OK, json);
}

void RestHandler::apiHealth(const HttpRequest &message)
{
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_HEALTH);
	auto health = Configuration::instance()->getApp(appName)->health();
	auto body = std::to_string(health);
	message.reply(web::http::status_codes::OK, body);
}

void RestHandler::apiRestMetrics(const HttpRequest &message)
{
	if (Configuration::instance()->prometheusEnabled())
	{
		auto body = this->collectData();
		message.reply(web::http::status_codes::OK, body, "text/plain; version=0.0.4");
	}
	else
	{
		throw std::invalid_argument("Prometheus export not enabled or configured correctly");
	}
}

void RestHandler::apiUserLogin(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserLogin() ";
	if (message.m_headers.count(HTTP_HEADER_JWT_username) && message.m_headers.count(HTTP_HEADER_JWT_password))
	{
		std::string uname = Utility::decode64(GET_HTTP_HEADER(message, HTTP_HEADER_JWT_username));
		std::string passwd = Utility::decode64(GET_HTTP_HEADER(message, HTTP_HEADER_JWT_password));
		std::string totp = Utility::decode64(GET_HTTP_HEADER(message, HTTP_HEADER_JWT_totp));
		std::string userGroup;
		if (!Security::instance()->verifyUserKey(uname, passwd, totp, userGroup))
		{
			message.reply(web::http::status_codes::Unauthorized, convertText2Json("Incorrect user password"));
		}
		else
		{
			int timeoutSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS; // default timeout is 7 days
			if (message.m_headers.count(HTTP_HEADER_JWT_expire_seconds))
			{
				auto timeout = message.m_headers.find(HTTP_HEADER_JWT_expire_seconds)->second;
				timeoutSeconds = std::stoi(timeout);
			}

			auto token = createJwtToken(uname, userGroup, timeoutSeconds);

			nlohmann::json result = nlohmann::json::object();
			nlohmann::json profile = nlohmann::json::object();
			profile[("name")] = std::string(uname);
			profile[("auth_time")] = (std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
			result[("profile")] = profile;
			result[("token_type")] = std::string(HTTP_HEADER_JWT_Bearer);
			result[HTTP_HEADER_JWT_access_token] = std::string((token));
			result[("expire_time")] = (std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) + timeoutSeconds);
			result[("expire_seconds")] = (timeoutSeconds);

			message.reply(web::http::status_codes::OK, result);
			LOG_DBG << fname << "User <" << uname << "> login success";
		}
	}
	else
	{
		message.reply(web::http::status_codes::NetworkAuthenticationRequired, convertText2Json("Username or Password missing"));
	}
}

void RestHandler::apiUserAuth(const HttpRequest &message)
{
	std::string permission = GET_HTTP_HEADER(message, HTTP_HEADER_JWT_auth_permission);

	if (permissionCheck(message, permission))
	{
		auto result = nlohmann::json::object();
		result["user"] = std::string(getJwtUserName(message));
		result["success"] = (true);
		result["permission"] = std::string(permission);
		message.reply(web::http::status_codes::OK, result);
	}
	else
	{
		message.reply(web::http::status_codes::Unauthorized, convertText2Json("Incorrect authentication info"));
	}
}

void RestHandler::apiAppView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_app);
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_VIEW);

	checkAppAccessPermission(message, appName, false);

	message.reply(web::http::status_codes::OK, Configuration::instance()->getApp(appName)->AsJson(true));
}

std::shared_ptr<Application> RestHandler::parseAndRegRunApp(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::parseAndRegRunApp() ";

	auto jsonApp = message.extractJson();
	auto clientProvideAppName = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name);
	std::shared_ptr<Application> fromApp;
	if (clientProvideAppName.length())
	{
		if (Configuration::instance()->isAppExist(clientProvideAppName))
		{
			// COPY from existing application
			// require app read permission
			checkAppAccessPermission(message, clientProvideAppName, false);
			// get application profile
			fromApp = Configuration::instance()->getApp(clientProvideAppName);
			auto existApp = fromApp->AsJson(false);
			// CASE: copy existing application and run
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_command))
			{
				throw std::invalid_argument(Utility::stringFormat("Should not specify command for an existing application <%s>", clientProvideAppName.c_str()));
			}
			// for run an existing app, only support re-define metadata and env
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_metadata))
			{
				existApp[JSON_KEY_APP_metadata] = jsonApp[JSON_KEY_APP_metadata];
			}
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_env))
			{
				existApp[JSON_KEY_APP_env] = jsonApp[JSON_KEY_APP_env];
			}
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_sec_env))
			{
				existApp[JSON_KEY_APP_sec_env] = jsonApp[JSON_KEY_APP_sec_env];
			}
			existApp[JSON_KEY_APP_name] = std::string(Utility::createUUID()); // specify a UUID app name
			existApp[JSON_KEY_APP_owner] = std::string(getJwtUserName(message));
			jsonApp = existApp;
		}
		else
		{
			// CASE: new a application and run, client provide command
			if (!HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_command) && !HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_docker_image))
			{
				LOG_WAR << fname << "Should specify command to run application: " << clientProvideAppName;
				throw std::invalid_argument("Should specify command to run application");
			}
		}
	}
	else
	{
		// CASE: new a application and run, client did not provide app name
		jsonApp[JSON_KEY_APP_name] = std::string(Utility::createUUID()); // specify a UUID app name
		if (!HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_command))
		{
			throw std::invalid_argument("Should specify command run application");
		}
	}

	jsonApp[JSON_KEY_APP_status] = (static_cast<int>(STATUS::NOTAVIALABLE));
	jsonApp[JSON_KEY_APP_owner] = std::string(getJwtUserName(message));
	auto app = Configuration::instance()->addApp(jsonApp, fromApp, false);
	if (fromApp)
		LOG_INF << fname << "Run application <" << app->getName() << "> from " << fromApp->getName();
	else
		LOG_INF << fname << "Run application <" << app->getName() << ">";
	int lifecycle = getHttpQueryValue(message, HTTP_QUERY_KEY_lifecycle, DEFAULT_RUN_APP_LIFECYCLE_SECONDS, 3, MAX_RUN_APP_TIMEOUT_SECONDS);
	app->regSuicideTimer(lifecycle);
	return app;
}

void RestHandler::apiRunAsync(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_async);

	int timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 1, MAX_RUN_APP_TIMEOUT_SECONDS);
	auto appObj = parseAndRegRunApp(message);

	auto processUuid = appObj->runAsyncrize(timeout);
	auto result = nlohmann::json::object();
	result[JSON_KEY_APP_name] = std::string(appObj->getName());
	result[HTTP_QUERY_KEY_process_uuid] = std::string(processUuid);
	message.reply(web::http::status_codes::OK, result);
}

void RestHandler::apiRunSync(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_sync);

	int timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 3, MAX_RUN_APP_TIMEOUT_SECONDS);
	auto appObj = parseAndRegRunApp(message);

	// Use async reply here
	HttpRequest *asyncRequest = new HttpRequestWithAppRef(message, appObj);
	appObj->runSyncrize(timeout, asyncRequest);
}

void RestHandler::apiAppOutputView(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiAppOutputView() ";
	permissionCheck(message, PERMISSION_KEY_view_app_output);
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_OUT_VIEW);

	long pos = getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_position, 0, 0, 0);
	int index = getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_index, 0, 0, 0);
	long maxSize = getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_maxsize, APP_STD_OUT_VIEW_DEFAULT_SIZE, 1024, APP_STD_OUT_VIEW_DEFAULT_SIZE);
	size_t timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_timeout, 0, 0, 0);
	std::string processUuid = getHttpQueryString(message, HTTP_QUERY_KEY_process_uuid);
	bool outputHtml = getHttpQueryString(message, HTTP_QUERY_KEY_html).length();
	bool outputJson = getHttpQueryString(message, HTTP_QUERY_KEY_json).length();

	checkAppAccessPermission(message, appName, false);

	auto appObj = Configuration::instance()->getApp(appName);
	auto result = appObj->getOutput(pos, maxSize, processUuid, index, timeout);
	auto output = std::get<0>(result);
	auto finished = std::get<1>(result);
	auto exitCode = std::get<2>(result);
	LOG_DBG << fname; // << output;
	std::map<std::string, std::string> headers;
	if (pos)
		headers[HTTP_HEADER_KEY_output_pos] = std::to_string(pos);
	if (finished)
		headers[HTTP_HEADER_KEY_exit_code] = std::to_string(exitCode);
	if (outputHtml)
	{
		// https://github.com/yesoreyeram/grafana-infinity-datasource/blob/main/testdata/users.html
		// https://sriramajeyam.com/grafana-infinity-datasource/wiki/html
		static const auto html = Utility::readFileCpp("/opt/appmesh/script/grafana_infinity.html");
		auto lines = Utility::splitString(output, "\n");
		std::stringstream ss;
		for (const auto &line : lines)
		{
			ss << line << "</pre>\n<pre>";
		}
		output = Utility::stringFormat(html, appName.c_str(), ss.str().c_str());
	}
	else if (outputJson)
	{
		auto lines = Utility::splitString(output, "\n");
		auto jsonArray = nlohmann::json::array();
		// Build Json
		for (std::size_t i = 0; i < lines.size(); ++i)
		{
			jsonArray[i] = nlohmann::json{{"index", i + 1}, {"stdout", lines[i]}};
		}
		output = jsonArray.dump();
	}
	message.reply(web::http::status_codes::OK, output, headers);
}

void RestHandler::apiAppsView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_all_app);
	auto tokenUserName = getJwtUserName(message);
	message.reply(web::http::status_codes::OK, Configuration::instance()->serializeApplication(true, tokenUserName, true));
}

void RestHandler::apiCloudAppsView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_view);
	message.reply(web::http::status_codes::OK, ConsulConnection::instance()->viewCloudApps());
}

void RestHandler::apiCloudAppView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_view);
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_CLOUD_APP_VIEW);

	message.reply(web::http::status_codes::OK, ConsulConnection::instance()->viewCloudApp(appName));
}

void RestHandler::apiCloudAppOutputView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_out_view);
	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto tp = regexSearch2(path, REST_PATH_CLOUD_APP_OUT_VIEW);
	auto appName = std::get<0>(tp);
	auto hostName = std::get<1>(tp);

	auto querymap = message.m_querys;
	auto resp = ConsulConnection::instance()->viewCloudAppOutput(appName, hostName, querymap, message.m_headers);
	message.reply(resp->status_code, resp->text);
}

void RestHandler::apiCloudAppAdd(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_reg);

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_CLOUD_APP_ADD);

	auto jsonApp = message.extractJson();
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("Empty json input");
	}
	message.reply(web::http::status_codes::OK, ConsulConnection::instance()->addCloudApp(appName, jsonApp));
}

void RestHandler::apiCloudAppDel(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_delete);

	auto path = (cpr::util::urlDecode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_CLOUD_APP_DELETE);

	ConsulConnection::instance()->deleteCloudApp(appName);
	message.reply(web::http::status_codes::OK, convertText2Json("Delete cloud application success"));
}

void RestHandler::apiCloudHostView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_host_view);
	message.reply(web::http::status_codes::OK, ConsulConnection::instance()->getCloudNodes());
}

void RestHandler::apiResourceView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_host_resource);
	message.reply(web::http::status_codes::OK, ResourceCollection::instance()->AsJson());
}

void RestHandler::apiAppAdd(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiAppAdd() ";

	permissionCheck(message, PERMISSION_KEY_app_reg);
	auto jsonApp = message.extractJson();
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("Empty json input");
	}
	LOG_DBG << fname << jsonApp;

	auto appName = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name);
	if (Configuration::instance()->isAppExist(appName) && Configuration::instance()->getApp(appName)->isCloudApp())
	{
		throw std::invalid_argument("Cloud Application is not allowed to override");
	}
	if (Configuration::instance()->isAppExist(appName))
	{
		checkAppAccessPermission(message, appName, true);
	}
	jsonApp[JSON_KEY_APP_owner] = std::string(getJwtUserName(message));
	auto app = Configuration::instance()->addApp(jsonApp);
	message.reply(web::http::status_codes::OK, app->AsJson(false));
}

#include <chrono>

#include <boost/algorithm/string_regex.hpp>
#include <cpprest/filestream.h>
#include <cpprest/http_listener.h> // HTTP server

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
constexpr auto REST_PATH_SEC_USER_DELETE = R"(/appmesh/user/([^/\*]+))";
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

RestHandler::RestHandler(bool forward2TcpServer) : PrometheusRest(forward2TcpServer)
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
	bindRestMethod(web::http::methods::DEL, REST_PATH_SEC_USER_DELETE, std::bind(&RestHandler::apiUserDel, this, std::placeholders::_1));
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
	try
	{
		this->close();
	}
	catch (...)
	{
		LOG_WAR << fname << "failed";
	}
}

void RestHandler::open()
{
	const static char fname[] = "RestHandler::open() ";

	PrometheusRest::open();

	const std::string ipaddress = Configuration::instance()->getRestListenAddress();
	const int port = Configuration::instance()->getRestListenPort();
	auto listenAddress = ipaddress.empty() ? std::string("0.0.0.0") : ipaddress;
	// Construct URI
	web::uri_builder uri;
	uri.set_host(listenAddress);
	uri.set_port(port);
	uri.set_path("/");
	if (Configuration::instance()->getSslEnabled())
	{
		if (!Utility::isFileExist(Configuration::instance()->getSSLCertificateFile()) ||
			!Utility::isFileExist(Configuration::instance()->getSSLCertificateKeyFile()))
		{
			LOG_ERR << fname << "server.crt and server.key not exist";
		}
		// Support SSL
		uri.set_scheme("https");
		static bool sslContextCreated = false;
		static auto server_config = new web::http::experimental::listener::http_listener_config();
		if (!sslContextCreated)
		{
			sslContextCreated = true;
			server_config->set_ssl_context_callback(
				[&](boost::asio::ssl::context &ctx)
				{
					boost::system::error_code ec;
					// https://github.com/zaphoyd/websocketpp/blob/c5510d6de04917812b910a8dd44735c1f17061d9/examples/echo_server_tls/echo_server_tls.cpp
					ctx.set_options(boost::asio::ssl::context::default_workarounds |
										boost::asio::ssl::context::no_sslv2 |	// disable SSL v2
										boost::asio::ssl::context::no_sslv3 |	// disable SSL v3
										boost::asio::ssl::context::no_tlsv1 |	// disable TLS v1.0
										boost::asio::ssl::context::no_tlsv1_1 | // disable TLS v1.1
										boost::asio::ssl::context::single_dh_use |
										SSL_OP_CIPHER_SERVER_PREFERENCE,
									ec);
					// LOG_DBG << "lambda::set_options " << ec.value() << " " << ec.message();

					ec = ctx.use_certificate_chain_file(Configuration::instance()->getSSLCertificateFile(), ec);
					if (ec.failed())
					{
						LOG_WAR << "ssl::context::use_certificate_chain_file failed: " << ec.message();
					}
					ec = ctx.use_private_key_file(Configuration::instance()->getSSLCertificateKeyFile(), boost::asio::ssl::context::pem, ec);
					if (ec.failed())
					{
						LOG_WAR << "ssl::context::use_private_key_file failed: " << ec.message();
					}

					// Enable ECDH cipher
					if (!SSL_CTX_set_ecdh_auto(ctx.native_handle(), 1))
					{
						LOG_WAR << "::SSL_CTX_set_ecdh_auto failed: " << std::strerror(errno);
					}
					// auto ciphers = "ALL:!RC4:!SSLv2:+HIGH:!MEDIUM:!LOW";
					auto ciphers = "HIGH:!aNULL:!eNULL:!kECDH:!aDH:!RC4:!3DES:!CAMELLIA:!MD5:!PSK:!SRP:!KRB5:@STRENGTH";
					if (!SSL_CTX_set_cipher_list(ctx.native_handle(), ciphers))
					{
						LOG_WAR << "::SSL_CTX_set_cipher_list failed: " << std::strerror(errno);
					}
					SSL_CTX_clear_options(ctx.native_handle(), SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
				});
		}
		m_listener = std::make_unique<web::http::experimental::listener::http_listener>(uri.to_uri(), *server_config);
	}
	else
	{
		uri.set_scheme("http");
		m_listener = std::make_unique<web::http::experimental::listener::http_listener>(uri.to_uri());
	}

	m_listener->support(methods::GET, std::bind(&RestHandler::handle_get, this, std::placeholders::_1));
	m_listener->support(methods::PUT, std::bind(&RestHandler::handle_put, this, std::placeholders::_1));
	m_listener->support(methods::POST, std::bind(&RestHandler::handle_post, this, std::placeholders::_1));
	m_listener->support(methods::DEL, std::bind(&RestHandler::handle_delete, this, std::placeholders::_1));
	m_listener->support(methods::OPTIONS, std::bind(&RestHandler::handle_options, this, std::placeholders::_1));

	m_listener->open().wait();
	LOG_INF << fname << "Listening for requests at: " << uri.to_string();
}

void RestHandler::close()
{
	m_listener->close(); // .wait();
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

	auto querymap = web::uri::split_query(web::http::uri::decode(message.m_query));
	long rt = defaultValue;
	if (querymap.find(U(key)) != querymap.end())
	{
		auto value = querymap.find(U(key))->second;
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

	auto querymap = web::uri::split_query(web::http::uri::decode(message.m_query));
	std::string rt;
	if (querymap.find(U(key)) != querymap.end())
	{
		rt = GET_STD_STRING(querymap.find(U(key))->second);
	}
	LOG_DBG << fname << key << "=" << rt;
	return rt;
}

std::string RestHandler::regexSearch(const std::string &value, const char *expr)
{
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
				throw std::invalid_argument(Utility::stringFormat("no data from path <%s>", value.c_str()));
			}
		}
	}
	throw std::invalid_argument(Utility::stringFormat("failed parse data from path <%s>", value.c_str()));
}

void RestHandler::apiAppEnable(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_ENABLE);

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->enableApp(appName);
	message.reply(status_codes::OK, convertText2Json(std::string("Enable <") + appName + "> success."));
}

void RestHandler::apiAppDisable(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_DISABLE);

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->disableApp(appName);
	message.reply(status_codes::OK, convertText2Json(std::string("Disable <") + appName + "> success."));
}

void RestHandler::apiAppDelete(const HttpRequest &message)
{
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_DELETE);
	if (Configuration::instance()->getApp(appName)->isCloudApp())
		throw std::invalid_argument("not allowed for cloud application");

	if (!(Configuration::instance()->getApp(appName)->getOwner() &&
		  Configuration::instance()->getJwtEnabled() &&
		  Configuration::instance()->getApp(appName)->getOwner()->getName() == getJwtUserName(message)))
	{
		// only check delete permission for none-self app
		permissionCheck(message, PERMISSION_KEY_app_delete);
	}

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->removeApp(appName);
	message.reply(status_codes::OK, convertText2Json(Utility::stringFormat("Application <%s> removed.", appName.c_str())));
}

void RestHandler::apiFileDownload(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiFileDownload() ";

	permissionCheck(message, PERMISSION_KEY_file_download);
	if (!(message.headers().has(HTTP_HEADER_KEY_file_path)))
	{
		message.reply(status_codes::BadRequest, convertText2Json("header 'File-Path' not found"));
		return;
	}
	auto file = GET_STD_STRING(message.headers().find(HTTP_HEADER_KEY_file_path)->second);
	if (!Utility::isFileExist(file))
	{
		message.reply(status_codes::NotAcceptable, convertText2Json("file not found"));
		return;
	}

	LOG_DBG << fname << "Downloading file <" << file << ">";

	concurrency::streams::fstream::open_istream(file, std::ios::in | std::ios::binary)
		.then([=](concurrency::streams::istream fileStream)
			  {
				  // Get the content length, which is used to set the
				  // Content-Length property
				  fileStream.seek(0, std::ios::end);
				  auto length = static_cast<std::size_t>(fileStream.tell());
				  fileStream.seek(0, std::ios::beg);
				  auto fileInfo = os::fileStat(file);

				  web::http::http_response resp(status_codes::OK);
				  resp.set_body(fileStream, length);
				  resp.headers().add(HTTP_HEADER_KEY_file_mode, std::get<0>(fileInfo));
				  resp.headers().add(HTTP_HEADER_KEY_file_user, std::get<1>(fileInfo));
				  resp.headers().add(HTTP_HEADER_KEY_file_group, std::get<2>(fileInfo));
				  message.reply(resp);
				  fileStream.close();
			  })
		.then([=](pplx::task<void> t)
			  {
				  try
				  {
					  t.get();
				  }
				  catch (...)
				  {
					  // opening the file (open_istream) failed.
					  // Reply with an error.
					  message.reply(status_codes::InternalError);
				  }
			  });
}

void RestHandler::apiFileUpload(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiFileUpload() ";
	permissionCheck(message, PERMISSION_KEY_file_upload);
	if (!(message.headers().has(HTTP_HEADER_KEY_file_path)))
	{
		message.reply(status_codes::BadRequest, convertText2Json("header 'File-Path' not found"));
		return;
	}
	auto file = message.headers().find(HTTP_HEADER_KEY_file_path)->second;
	if (Utility::isFileExist(file))
	{
		message.reply(status_codes::Forbidden, convertText2Json("file already exist"));
		return;
	}

	LOG_DBG << fname << "Uploading file <" << file << ">";

	auto stream = concurrency::streams::fstream::open_ostream(file, std::ios::out | std::ios::binary | std::ios::trunc).get();
	message.body().read_to_end(stream.streambuf()).get();
	auto fileSize = stream.streambuf().size();
	stream.close();
	if (message.m_headers.count(HTTP_HEADER_KEY_file_mode))
	{
		os::fileChmod(file, std::stoi(message.m_headers.find(HTTP_HEADER_KEY_file_mode)->second));
	}
	if (message.m_headers.count(HTTP_HEADER_KEY_file_user) && message.m_headers.count(HTTP_HEADER_KEY_file_group))
	{
		os::chown(std::stoi(message.m_headers.find(HTTP_HEADER_KEY_file_user)->second),
				  std::stoi(message.m_headers.find(HTTP_HEADER_KEY_file_group)->second),
				  file, false);
	}
	message.reply(status_codes::OK, convertText2Json(Utility::stringFormat("Success upload file with size %s", Utility::humanReadableSize(fileSize).c_str())));
}

void RestHandler::apiLabelsView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_view);
	message.reply(status_codes::OK, Configuration::instance()->getLabel()->AsJson());
}

void RestHandler::apiLabelAdd(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_set);

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto labelKey = regexSearch(path, REST_PATH_LABEL_ADD);

	auto querymap = web::uri::split_query(web::http::uri::decode(message.m_query));
	if (querymap.find(U(HTTP_QUERY_KEY_label_value)) != querymap.end())
	{
		auto value = GET_STD_STRING(querymap.find(U(HTTP_QUERY_KEY_label_value))->second);

		Configuration::instance()->getLabel()->addLabel(labelKey, value);
		Configuration::instance()->saveConfigToDisk();

		message.reply(status_codes::OK);
	}
	else
	{
		message.reply(status_codes::BadRequest, convertText2Json("query value required"));
	}
}

void RestHandler::apiLabelDel(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_delete);

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto labelKey = regexSearch(path, REST_PATH_LABEL_DELETE);

	Configuration::instance()->getLabel()->delLabel(labelKey);
	Configuration::instance()->saveConfigToDisk();

	message.reply(status_codes::OK);
}

void RestHandler::apiUserPermissionsView(const HttpRequest &message)
{
	std::set<std::string> permissions;
	if (Configuration::instance()->getJwtEnabled())
	{
		const auto result = verifyToken(message);
		const auto userName = std::get<0>(result);
		const auto groupName = std::get<1>(result);
		permissions = Security::instance()->getUserPermissions(userName, groupName);
	}
	else
	{
		permissions = Security::instance()->getAllPermissions();
	}
	auto json = web::json::value::array(permissions.size());
	int index = 0;
	for (auto perm : permissions)
	{
		json[index++] = web::json::value::string(perm);
	}
	message.reply(status_codes::OK, json);
}

void RestHandler::apiBasicConfigView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_config_view);

	auto config = Configuration::instance()->AsJson(false, getJwtUserName(message));
	message.reply(status_codes::OK, config);
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

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_change_passwd);

	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_CHANGE_PWD);
	auto tokenUserName = getJwtUserName(message);
	if (!(message.m_headers.count(HTTP_HEADER_JWT_new_password)))
	{
		throw std::invalid_argument("can not find new password from header");
	}
	auto newPasswd = Utility::stdStringTrim(Utility::decode64(GET_STD_STRING(message.m_headers.find(HTTP_HEADER_JWT_new_password)->second)));

	if (pathUserName != tokenUserName)
	{
		throw std::invalid_argument("user can only change its own password");
	}
	if (newPasswd.length() < APPMESH_PASSWD_MIN_LENGTH)
	{
		throw std::invalid_argument("password length should be greater than 3");
	}

	Security::instance()->changeUserPasswd(tokenUserName, newPasswd);
	Security::instance()->save();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << tokenUserName << "> changed password";
	message.reply(status_codes::OK, convertText2Json("password changed success"));
}

void RestHandler::apiUserLock(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserLock() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_lock_user);
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_LOCK);
	auto tokenUserName = getJwtUserName(message);

	if (pathUserName == JWT_ADMIN_NAME)
	{
		throw std::invalid_argument("User admin can not be locked");
	}

	Security::instance()->getUserInfo(pathUserName)->lock();
	Security::instance()->save();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> locked by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserUnlock(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserUnlock() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_lock_user);
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_UNLOCK);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->getUserInfo(pathUserName)->unlock();
	Security::instance()->save();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> unlocked by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserAdd(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserAdd() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_add_user);
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_ADD);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->addUser(pathUserName, message.extractJson());
	Security::instance()->save();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << pathUserName << "> added by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserDel(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserDel() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_delete_user);
	auto pathUserName = regexSearch(path, REST_PATH_SEC_USER_DELETE);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->delUser(pathUserName);
	Security::instance()->save();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << pathUserName << "> deleted by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUsersView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_get_users);

	auto users = Security::instance()->getUsersJson();
	for (auto &user : users.as_object())
	{
		if (HAS_JSON_FIELD(user.second, JSON_KEY_USER_key))
			user.second.erase(JSON_KEY_USER_key);
	}

	message.reply(status_codes::OK, users);
}

void RestHandler::apiRolesView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_role_view);

	message.reply(status_codes::OK, Security::instance()->getRolesJson());
}

void RestHandler::apiRoleUpdate(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiRoleUpdate() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_role_update);
	auto pathRoleName = regexSearch(path, REST_PATH_SEC_ROLE_UPDATE);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->addRole(message.extractJson(), pathRoleName);
	Security::instance()->save();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "Role <" << pathRoleName << "> updated by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiRoleDelete(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiRoleDelete() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_role_delete);

	auto pathRoleName = regexSearch(path, REST_PATH_SEC_ROLE_DELETE);
	auto tokenUserName = getJwtUserName(message);

	Security::instance()->delRole(pathRoleName);
	Security::instance()->save();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "Role <" << pathRoleName << "> deleted by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserGroupsView(const HttpRequest &message)
{
	auto groups = Security::instance()->getAllUserGroups();
	auto json = web::json::value::array(groups.size());
	int index = 0;
	for (const auto &grp : groups)
	{
		json[index++] = web::json::value::string(grp);
	}
	message.reply(status_codes::OK, json);
}

void RestHandler::apiPermissionsView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_permission_list);

	auto permissions = Security::instance()->getAllPermissions();
	auto json = web::json::value::array(permissions.size());
	int index = 0;
	for (auto perm : permissions)
	{
		json[index++] = web::json::value::string(perm);
	}
	message.reply(status_codes::OK, json);
}

void RestHandler::apiHealth(const HttpRequest &message)
{
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_HEALTH);
	auto health = Configuration::instance()->getApp(appName)->health();
	message.reply(status_codes::OK, std::to_string(health));
}

void RestHandler::apiRestMetrics(const HttpRequest &message)
{
	if (PrometheusRest::instance() != nullptr)
	{
		message.reply(status_codes::OK, PrometheusRest::instance()->collectData(), "text/plain; version=0.0.4");
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
		std::string uname = Utility::decode64(GET_STD_STRING(message.m_headers.find(HTTP_HEADER_JWT_username)->second));
		std::string passwd = Utility::decode64(GET_STD_STRING(message.m_headers.find(HTTP_HEADER_JWT_password)->second));
		std::string userGroup;
		if (Configuration::instance()->getJwtEnabled() && !Security::instance()->verifyUserKey(uname, passwd, userGroup))
		{
			message.reply(status_codes::Unauthorized, convertText2Json("Incorrect user password"));
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

			web::json::value result = web::json::value::object();
			web::json::value profile = web::json::value::object();
			profile[GET_STRING_T("name")] = web::json::value::string(uname);
			profile[GET_STRING_T("auth_time")] = web::json::value::number(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
			result[GET_STRING_T("profile")] = profile;
			result[GET_STRING_T("token_type")] = web::json::value::string(HTTP_HEADER_JWT_Bearer);
			result[HTTP_HEADER_JWT_access_token] = web::json::value::string(GET_STRING_T(token));
			result[GET_STRING_T("expire_time")] = web::json::value::number(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) + timeoutSeconds);
			result[GET_STRING_T("expire_seconds")] = web::json::value::number(timeoutSeconds);

			message.reply(status_codes::OK, result);
			LOG_DBG << fname << "User <" << uname << "> login success";
		}
	}
	else
	{
		message.reply(status_codes::NetworkAuthenticationRequired, convertText2Json("Username or Password missing"));
	}
}

void RestHandler::apiUserAuth(const HttpRequest &message)
{
	std::string permission;
	if (message.m_headers.count(HTTP_HEADER_JWT_auth_permission))
	{
		permission = message.m_headers.find(HTTP_HEADER_JWT_auth_permission)->second;
	}

	if (!Configuration::instance()->getJwtEnabled())
	{
		message.reply(status_codes::OK, convertText2Json("JWT authentication not enabled"));
	}
	else if (permissionCheck(message, permission))
	{
		auto result = web::json::value::object();
		result["user"] = web::json::value::string(getJwtUserName(message));
		result["success"] = web::json::value::boolean(true);
		result["permission"] = web::json::value::string(permission);
		message.reply(status_codes::OK, result);
	}
	else
	{
		message.reply(status_codes::Unauthorized, convertText2Json("Incorrect authentication info"));
	}
}

void RestHandler::apiAppView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_app);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_VIEW);

	checkAppAccessPermission(message, appName, false);

	message.reply(status_codes::OK, Configuration::instance()->getApp(appName)->AsJson(true));
}

std::shared_ptr<Application> RestHandler::parseAndRegRunApp(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::parseAndRegRunApp() ";

	auto jsonApp = message.extractJson();
	auto clientProvideAppName = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name);
	if (!HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_retention))
	{
		// without default retention, application might be removed before get output
		jsonApp[JSON_KEY_APP_retention] = web::json::value::string(std::to_string(DEFAULT_RUN_APP_RETENTION_DURATION));
	}
	std::shared_ptr<Application> fromApp;
	if (clientProvideAppName.length())
	{
		if (Configuration::instance()->isAppExist(clientProvideAppName))
		{
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
			existApp[JSON_KEY_APP_retention] = jsonApp[JSON_KEY_APP_retention];
			existApp[JSON_KEY_APP_name] = web::json::value::string(Utility::createUUID()); // specify a UUID app name
			jsonApp = existApp;
		}
		else
		{
			// CASE: new a application and run, client provide new app name
			if (!HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_command))
			{
				throw std::invalid_argument(Utility::stringFormat("Should specify command run application <%s>", clientProvideAppName.c_str()));
			}
		}
	}
	else
	{
		// CASE: new a application and run, client did not provide app name
		jsonApp[JSON_KEY_APP_name] = web::json::value::string(Utility::createUUID()); // specify a UUID app name
		if (!HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_command))
		{
			throw std::invalid_argument("Should specify command run application");
		}
	}

	jsonApp[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(STATUS::NOTAVIALABLE));
	jsonApp[JSON_KEY_APP_owner] = web::json::value::string(getJwtUserName(message));
	auto app = Configuration::instance()->addApp(jsonApp, fromApp);
	app->setUnPersistable();
	if (fromApp)
		LOG_INF << fname << "Run application <" << app->getName() << "> from " << fromApp->getName();
	else
		LOG_INF << fname << "Run application <" << app->getName() << ">";
	return app;
}

void RestHandler::apiRunAsync(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_async);

	int timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 1, 60 * 60 * 24);
	auto appObj = parseAndRegRunApp(message);

	if (timeout < 0)
		timeout = MAX_RUN_APP_TIMEOUT_SECONDS;
	auto processUuid = appObj->runAsyncrize(timeout);
	auto result = web::json::value::object();
	result[JSON_KEY_APP_name] = web::json::value::string(appObj->getName());
	result[HTTP_QUERY_KEY_process_uuid] = web::json::value::string(processUuid);
	message.reply(status_codes::OK, result);
}

void RestHandler::apiRunSync(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_sync);

	int timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 1, 60 * 60 * 24);
	auto appObj = parseAndRegRunApp(message);

	// Use async reply here
	HttpRequest *asyncRequest = new HttpRequestWithAppRef(message, appObj);
	appObj->runSyncrize(timeout, asyncRequest);
}

void RestHandler::apiAppOutputView(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiAppOutputView() ";
	permissionCheck(message, PERMISSION_KEY_view_app_output);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_OUT_VIEW);

	long pos = getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_position, 0, 0, 0);
	int index = getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_index, 0, 0, 0);
	long maxSize = getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_maxsize, APP_STD_OUT_VIEW_DEFAULT_SIZE, 1024, APP_STD_OUT_VIEW_DEFAULT_SIZE);
	std::string processUuid = getHttpQueryString(message, HTTP_QUERY_KEY_process_uuid);

	checkAppAccessPermission(message, appName, false);

	auto appObj = Configuration::instance()->getApp(appName);
	auto result = appObj->getOutput(pos, maxSize, processUuid, index);
	auto output = std::get<0>(result);
	auto finished = std::get<1>(result);
	auto exitCode = std::get<2>(result);
	LOG_DBG << fname; // << output;
	web::http::http_response resp(status_codes::OK);
	if (pos)
	{
		resp.headers().add(HTTP_HEADER_KEY_output_pos, pos);
	}
	if (finished)
	{
		resp.headers().add(HTTP_HEADER_KEY_exit_code, exitCode);
	}
	message.reply(resp, output);
}

void RestHandler::apiAppsView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_all_app);
	auto tokenUserName = getJwtUserName(message);
	message.reply(status_codes::OK, Configuration::instance()->serializeApplication(true, tokenUserName, true));
}

void RestHandler::apiCloudAppsView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_view);
	message.reply(status_codes::OK, ConsulConnection::instance()->viewCloudApps());
}

void RestHandler::apiCloudAppView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_view);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_CLOUD_APP_VIEW);

	message.reply(status_codes::OK, ConsulConnection::instance()->viewCloudApp(appName));
}

void RestHandler::apiCloudAppAdd(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_reg);

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_CLOUD_APP_ADD);

	auto jsonApp = message.extractJson();
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("Empty json input");
	}
	message.reply(status_codes::OK, ConsulConnection::instance()->addCloudApp(appName, jsonApp));
}

void RestHandler::apiCloudAppDel(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_delete);

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_CLOUD_APP_DELETE);

	ConsulConnection::instance()->deleteCloudApp(appName);
	message.reply(status_codes::OK);
}

void RestHandler::apiCloudHostView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_host_view);
	message.reply(status_codes::OK, ConsulConnection::instance()->getCloudNodes());
}

void RestHandler::apiResourceView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_host_resource);
	message.reply(status_codes::OK, ResourceCollection::instance()->AsJson());
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
	jsonApp[JSON_KEY_APP_owner] = web::json::value::string(getJwtUserName(message));
	auto app = Configuration::instance()->addApp(jsonApp);
	message.reply(status_codes::OK, app->AsJson(false));
}

#include <chrono>

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
#include "../security/User.h"
#include "HttpRequest.h"
#include "PrometheusRest.h"
#include "RestHandler.h"

RestHandler::RestHandler(bool forward2TcpServer) : PrometheusRest(forward2TcpServer)
{
	// 1. Authentication
	bindRestMethod(web::http::methods::POST, "/appmesh/login", std::bind(&RestHandler::apiLogin, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, "/appmesh/auth", std::bind(&RestHandler::apiAuth, this, std::placeholders::_1));

	// 2. View Application
	bindRestMethod(web::http::methods::GET, R"(/appmesh/app/([^/\*]+))", std::bind(&RestHandler::apiGetApp, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, R"(/appmesh/app/([^/\*]+)/output)", std::bind(&RestHandler::apiGetAppOutput, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/applications", std::bind(&RestHandler::apiGetApps, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/cloud/applications", std::bind(&RestHandler::apiGetCloudApps, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/resources", std::bind(&RestHandler::apiGetResources, this, std::placeholders::_1));

	// 3. Manage Application
	bindRestMethod(web::http::methods::PUT, R"(/appmesh/app/([^/\*]+))", std::bind(&RestHandler::apiRegApp, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, R"(/appmesh/app/([^/\*]+)/enable)", std::bind(&RestHandler::apiEnableApp, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, R"(/appmesh/app/([^/\*]+)/disable)", std::bind(&RestHandler::apiDisableApp, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, R"(/appmesh/app/([^/\*]+))", std::bind(&RestHandler::apiDeleteApp, this, std::placeholders::_1));

	// 4. Operate Application
	bindRestMethod(web::http::methods::POST, "/appmesh/app/run", std::bind(&RestHandler::apiRunAsync, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, R"(/appmesh/app/([^/\*]+)/run/output)", std::bind(&RestHandler::apiRunAsyncOut, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, "/appmesh/app/syncrun", std::bind(&RestHandler::apiRunSync, this, std::placeholders::_1));

	// 5. File Management
	bindRestMethod(web::http::methods::GET, "/appmesh/file/download", std::bind(&RestHandler::apiFileDownload, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, "/appmesh/file/upload", std::bind(&RestHandler::apiFileUpload, this, std::placeholders::_1));

	// 6. Label Management
	bindRestMethod(web::http::methods::GET, "/appmesh/labels", std::bind(&RestHandler::apiGetLabels, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, R"(/appmesh/label/([^/\*]+))", std::bind(&RestHandler::apiAddLabel, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, R"(/appmesh/label/([^/\*]+))", std::bind(&RestHandler::apiDeleteLabel, this, std::placeholders::_1));

	// 7. Log level
	bindRestMethod(web::http::methods::GET, "/appmesh/config", std::bind(&RestHandler::apiGetBasicConfig, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, "/appmesh/config", std::bind(&RestHandler::apiSetBasicConfig, this, std::placeholders::_1));

	// 8. Security
	bindRestMethod(web::http::methods::POST, R"(/appmesh/user/([^/\*]+)/passwd)", std::bind(&RestHandler::apiUserChangePwd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, R"(/appmesh/user/([^/\*]+)/lock)", std::bind(&RestHandler::apiUserLock, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, R"(/appmesh/user/([^/\*]+)/unlock)", std::bind(&RestHandler::apiUserUnlock, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, R"(/appmesh/user/([^/\*]+))", std::bind(&RestHandler::apiUserAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, R"(/appmesh/user/([^/\*]+))", std::bind(&RestHandler::apiUserDel, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/users", std::bind(&RestHandler::apiUserList, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/roles", std::bind(&RestHandler::apiRoleView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, R"(/appmesh/role/([^/\*]+))", std::bind(&RestHandler::apiRoleUpdate, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, R"(/appmesh/role/([^/\*]+))", std::bind(&RestHandler::apiRoleDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/user/permissions", std::bind(&RestHandler::apiGetUserPermissions, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/permissions", std::bind(&RestHandler::apiListPermissions, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/user/groups", std::bind(&RestHandler::apiUserGroupsView, this, std::placeholders::_1));

	// 9. metrics
	bindRestMethod(web::http::methods::GET, R"(/appmesh/app/([^/\*]+)/health)", std::bind(&RestHandler::apiHealth, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmesh/metrics", std::bind(&RestHandler::apiRestMetrics, this, std::placeholders::_1));
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
				[&](boost::asio::ssl::context &ctx) {
					boost::system::error_code ec;

					ctx.set_options(boost::asio::ssl::context::default_workarounds |
										boost::asio::ssl::context::no_sslv2 |
										boost::asio::ssl::context::no_sslv3 |
										boost::asio::ssl::context::no_tlsv1 |
										boost::asio::ssl::context::no_tlsv1_1 |
										boost::asio::ssl::context::single_dh_use |
										SSL_OP_CIPHER_SERVER_PREFERENCE,
									ec);
					// LOG_DBG << "lambda::set_options " << ec.value() << " " << ec.message();

					ctx.use_certificate_chain_file(Configuration::instance()->getSSLCertificateFile(), ec);
					// LOG_DBG << "lambda::use_certificate_chain_file " << ec.value() << " " << ec.message();

					ctx.use_private_key_file(Configuration::instance()->getSSLCertificateKeyFile(), boost::asio::ssl::context::pem, ec);
					// LOG_DBG << "lambda::use_private_key " << ec.value() << " " << ec.message();

					// Enable ECDH cipher
					if (!SSL_CTX_set_ecdh_auto(ctx.native_handle(), 1))
					{
						LOG_WAR << "SSL_CTX_set_ecdh_auto failed: " << std::strerror(errno);
					}
					// auto ciphers = "ALL:!RC4:!SSLv2:+HIGH:!MEDIUM:!LOW";
					auto ciphers = "HIGH:!aNULL:!eNULL:!kECDH:!aDH:!RC4:!3DES:!CAMELLIA:!MD5:!PSK:!SRP:!KRB5:@STRENGTH";
					if (!SSL_CTX_set_cipher_list(ctx.native_handle(), ciphers))
					{
						LOG_WAR << "SSL_CTX_set_cipher_list failed: " << std::strerror(errno);
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

int RestHandler::getHttpQueryValue(const HttpRequest &message, const std::string &key, int defaultValue, int min, int max) const
{
	const static char fname[] = "RestHandler::getHttpQueryValue() ";

	auto querymap = web::uri::split_query(web::http::uri::decode(message.m_query));
	int rt = defaultValue;
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

void RestHandler::apiEnableApp(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));

	// /app/$app-name/enable
	std::string appName = path.substr(strlen("/appmesh/app/"));
	appName = appName.substr(0, appName.find_last_of('/'));

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->enableApp(appName);
	message.reply(status_codes::OK, std::string("Enable <") + appName + "> success.");
}

void RestHandler::apiDisableApp(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));

	// /appmesh/app/$app-name/disable
	std::string appName = path.substr(strlen("/appmesh/app/"));
	appName = appName.substr(0, appName.find_last_of('/'));

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->disableApp(appName);
	message.reply(status_codes::OK, std::string("Disable <") + appName + "> success.");
}

void RestHandler::apiDeleteApp(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_app_delete);
	auto path = message.m_relative_uri;

	std::string appName = path.substr(strlen("/appmesh/app/"));
	if (Configuration::instance()->getApp(appName)->isCloudApp())
		throw std::invalid_argument("not allowed for cloud application");

	checkAppAccessPermission(message, appName, true);

	Configuration::instance()->removeApp(appName);
	message.reply(status_codes::OK, Utility::stringFormat("Application <%s> removed.", appName.c_str()));
}

void RestHandler::apiFileDownload(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiFileDownload() ";

	permissionCheck(message, PERMISSION_KEY_file_download);
	if (!(message.headers().has(HTTP_HEADER_KEY_file_path)))
	{
		message.reply(status_codes::BadRequest, "header 'FilePath' not found");
		return;
	}
	auto file = GET_STD_STRING(message.headers().find(HTTP_HEADER_KEY_file_path)->second);
	if (!Utility::isFileExist(file))
	{
		message.reply(status_codes::NotAcceptable, "file not found");
		return;
	}

	LOG_DBG << fname << "Downloading file <" << file << ">";

	concurrency::streams::fstream::open_istream(file, std::ios::in | std::ios::binary)
		.then([=](concurrency::streams::istream fileStream) {
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
		.then([=](pplx::task<void> t) {
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
		message.reply(status_codes::BadRequest, "header 'FilePath' not found");
		return;
	}
	auto file = message.headers().find(HTTP_HEADER_KEY_file_path)->second;
	if (Utility::isFileExist(file))
	{
		message.reply(status_codes::Forbidden, "file already exist");
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
	message.reply(status_codes::OK, Utility::stringFormat("Success upload file with size %s", Utility::humanReadableSize(fileSize).c_str()));
}

void RestHandler::apiGetLabels(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_view);
	message.reply(status_codes::OK, Configuration::instance()->getLabel()->AsJson());
}

void RestHandler::apiAddLabel(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_set);

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto vec = Utility::splitString(path, "/");
	auto labelKey = vec[vec.size() - 1];
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
		message.reply(status_codes::BadRequest, "query value required");
	}
}

void RestHandler::apiDeleteLabel(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_label_delete);

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	auto vec = Utility::splitString(path, "/");
	auto labelKey = vec[vec.size() - 1];

	Configuration::instance()->getLabel()->delLabel(labelKey);
	Configuration::instance()->saveConfigToDisk();

	message.reply(status_codes::OK);
}

void RestHandler::apiGetUserPermissions(const HttpRequest &message)
{
	auto userName = verifyToken(message);
	auto permissions = Configuration::instance()->getUserPermissions(userName);
	auto json = web::json::value::array(permissions.size());
	int index = 0;
	for (auto perm : permissions)
	{
		json[index++] = web::json::value::string(perm);
	}
	message.reply(status_codes::OK, json);
}

void RestHandler::apiGetBasicConfig(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_config_view);

	auto config = Configuration::instance()->AsJson(false, getJwtUserName(message));
	if (HAS_JSON_FIELD(config, JSON_KEY_Security) && HAS_JSON_FIELD(config.at(JSON_KEY_Security), JSON_KEY_JWT_Users))
	{
		config.at(JSON_KEY_Security).erase(JSON_KEY_JWT_Users);
	}
	message.reply(status_codes::OK, config);
}

void RestHandler::apiSetBasicConfig(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_config_set);

	auto json = message.extractJson();
	// do not allow users update from host-update API
	if (HAS_JSON_FIELD(json, JSON_KEY_Security) && HAS_JSON_FIELD(json.at(JSON_KEY_Security), JSON_KEY_JWT_Users))
		json.at(JSON_KEY_Security).erase(JSON_KEY_JWT_Users);
	Configuration::instance()->hotUpdate(json);

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity(true);

	apiGetBasicConfig(message);
}

void RestHandler::apiUserChangePwd(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserChangePwd() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_change_passwd);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 4)
	{
		throw std::invalid_argument(Utility::stringFormat("Failed to get user name from path: %s", path.c_str()));
	}
	auto pathUserName = vec[2];
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

	auto user = Configuration::instance()->getUserInfo(tokenUserName);
	user->updateKey(newPasswd);
	// Store encrypted key if any
	if (Configuration::instance()->getEncryptKey())
		user->updateKey(Utility::hash(user->getKey()));

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> changed password";
	message.reply(status_codes::OK, "password changed success");
}

void RestHandler::apiUserLock(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserLock() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_lock_user);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 4)
	{
		throw std::invalid_argument(Utility::stringFormat("Failed to get user name from path: %s", path.c_str()));
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getJwtUserName(message);

	if (pathUserName == JWT_ADMIN_NAME)
	{
		throw std::invalid_argument("User admin can not be locked");
	}

	Configuration::instance()->getUserInfo(pathUserName)->lock();

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> locked by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserUnlock(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserUnlock() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_lock_user);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 4)
	{
		throw std::invalid_argument(Utility::stringFormat("Failed to get user name from path: %s", path.c_str()));
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getJwtUserName(message);

	Configuration::instance()->getUserInfo(pathUserName)->unlock();

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> unlocked by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserAdd(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserAdd() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_add_user);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 3)
	{
		throw std::invalid_argument(Utility::stringFormat("Failed to get user name from path: %s", path.c_str()));
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getJwtUserName(message);

	auto user = Configuration::instance()->getUsers()->addUser(pathUserName, message.extractJson(), Configuration::instance()->getRoles());
	// Store encrypted key if any
	if (Configuration::instance()->getEncryptKey())
		user->updateKey(Utility::hash(user->getKey()));

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << pathUserName << "> added by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserDel(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiUserDel() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_delete_user);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 3)
	{
		throw std::invalid_argument(Utility::stringFormat("Failed to get user name from path: %s", path.c_str()));
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getJwtUserName(message);

	Configuration::instance()->getUsers()->delUser(pathUserName);

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << pathUserName << "> deleted by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserList(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_get_users);

	auto users = Configuration::instance()->getUsers()->AsJson();
	for (auto &user : users.as_object())
	{
		if (HAS_JSON_FIELD(user.second, JSON_KEY_USER_key))
			user.second.erase(JSON_KEY_USER_key);
	}

	message.reply(status_codes::OK, users);
}

void RestHandler::apiRoleView(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_role_view);

	message.reply(status_codes::OK, Configuration::instance()->getRoles()->AsJson());
}

void RestHandler::apiRoleUpdate(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiRoleUpdate() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_role_update);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 3)
	{
		throw std::invalid_argument(Utility::stringFormat("Failed to get role name from path: %s", path.c_str()));
	}
	auto pathRoleName = vec[2];
	auto tokenUserName = getJwtUserName(message);

	Configuration::instance()->getRoles()->addRole(message.extractJson(), pathRoleName);

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "Role <" << pathRoleName << "> updated by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiRoleDelete(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiRoleDelete() ";

	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	permissionCheck(message, PERMISSION_KEY_role_delete);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 3)
	{
		throw std::invalid_argument(Utility::stringFormat("Failed to get role name from path: %s", path.c_str()));
	}
	auto pathRoleName = vec[2];
	auto tokenUserName = getJwtUserName(message);

	Configuration::instance()->getRoles()->delRole(pathRoleName);

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "Role <" << pathRoleName << "> deleted by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserGroupsView(const HttpRequest &message)
{
	auto groups = Configuration::instance()->getSecurity()->m_jwtUsers->getGroups();
	auto json = web::json::value::array(groups.size());
	int index = 0;
	for (const auto &grp : groups)
	{
		json[index++] = web::json::value::string(grp);
	}
	message.reply(status_codes::OK, json);
}

void RestHandler::apiListPermissions(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_permission_list);

	auto permissions = Configuration::instance()->getAllPermissions();
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
	// /appmesh/app/$app-name/health
	std::string appName = path.substr(strlen("/appmesh/app/"));
	appName = appName.substr(0, appName.find_last_of('/'));
	auto health = Configuration::instance()->getApp(appName)->getHealth();
	message.reply(status_codes::OK, std::to_string(health));
}

void RestHandler::apiRestMetrics(const HttpRequest &message)
{
	message.reply(status_codes::OK, PrometheusRest::instance()->collectData(), "text/plain; version=0.0.4");
}

void RestHandler::apiLogin(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiLogin() ";
	if (message.m_headers.count(HTTP_HEADER_JWT_username) && message.m_headers.count(HTTP_HEADER_JWT_password))
	{
		std::string uname = Utility::decode64(GET_STD_STRING(message.m_headers.find(HTTP_HEADER_JWT_username)->second));
		std::string passwd = Utility::decode64(GET_STD_STRING(message.m_headers.find(HTTP_HEADER_JWT_password)->second));
		int timeoutSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS; // default timeout is 7 days
		if (message.m_headers.count(HTTP_HEADER_JWT_expire_seconds))
		{
			auto timeout = message.m_headers.find(HTTP_HEADER_JWT_expire_seconds)->second;
			timeoutSeconds = std::stoi(timeout);
		}

		if (Configuration::instance()->getEncryptKey())
			passwd = Utility::hash(passwd);
		auto token = createJwtToken(uname, passwd, timeoutSeconds);

		web::json::value result = web::json::value::object();
		web::json::value profile = web::json::value::object();
		profile[GET_STRING_T("name")] = web::json::value::string(uname);
		profile[GET_STRING_T("auth_time")] = web::json::value::number(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
		result[GET_STRING_T("profile")] = profile;
		result[GET_STRING_T("token_type")] = web::json::value::string(HTTP_HEADER_JWT_Bearer);
		result[HTTP_HEADER_JWT_access_token] = web::json::value::string(GET_STRING_T(token));
		result[GET_STRING_T("expire_time")] = web::json::value::number(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) + timeoutSeconds);
		result[GET_STRING_T("expire_seconds")] = web::json::value::number(timeoutSeconds);

		auto userJson = Configuration::instance()->getUserInfo(uname);
		if (passwd == userJson->getKey())
		{
			message.reply(status_codes::OK, result);
			LOG_DBG << fname << "User <" << uname << "> login success";
		}
		else
		{
			message.reply(status_codes::Unauthorized, "Incorrect user password");
		}
	}
	else
	{
		message.reply(status_codes::NetworkAuthenticationRequired, "UserName or Password missing");
	}
}

void RestHandler::apiAuth(const HttpRequest &message)
{
	std::string permission;
	if (message.m_headers.count(HTTP_HEADER_JWT_auth_permission))
	{
		permission = message.m_headers.find(HTTP_HEADER_JWT_auth_permission)->second;
	}

	// permission is empty meas just verify token
	// with permission means token and permission check both
	if (permissionCheck(message, permission))
	{
		auto result = web::json::value::object();
		result["user"] = web::json::value::string(getJwtUserName(message));
		result["success"] = web::json::value::boolean(true);
		result["permission"] = web::json::value::string(permission);
		message.reply(status_codes::OK, result);
	}
	else
	{
		message.reply(status_codes::Unauthorized, "Incorrect authentication info");
	}
}

void RestHandler::apiGetApp(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_app);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));
	std::string appName = path.substr(strlen("/appmesh/app/"));

	checkAppAccessPermission(message, appName, false);

	message.reply(status_codes::OK, Configuration::instance()->getApp(appName)->AsJson(true));
}

std::shared_ptr<Application> RestHandler::apiRunParseApp(const HttpRequest &message)
{
	auto jsonApp = message.extractJson();
	auto clientProvideAppName = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name);
	if (clientProvideAppName.empty())
	{
		// specify a UUID app name
		auto appName = Utility::createUUID();
		jsonApp[JSON_KEY_APP_name] = web::json::value::string(appName);
	}
	else
	{
		// check whether this is normal app, do not broken working app
		if (Configuration::instance()->isAppExist(clientProvideAppName))
		{
			auto app = Configuration::instance()->getApp(clientProvideAppName);
			if (app->isWorkingState())
				throw std::invalid_argument("Should not override an application in working status");
		}
	}
	jsonApp[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(STATUS::NOTAVIALABLE));
	jsonApp[JSON_KEY_APP_owner] = web::json::value::string(getJwtUserName(message));
	return Configuration::instance()->addApp(jsonApp);
}

void RestHandler::apiRunAsync(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_async);

	int retention = getHttpQueryValue(message, HTTP_QUERY_KEY_retention, DEFAULT_RUN_APP_RETENTION_DURATION, 1, 60 * 60 * 24);
	int timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 1, 60 * 60 * 24);
	auto appObj = apiRunParseApp(message);

	if (timeout < 0)
		timeout = MAX_RUN_APP_TIMEOUT_SECONDS;
	auto processUuid = appObj->runAsyncrize(timeout);
	auto result = web::json::value::object();
	result[JSON_KEY_APP_name] = web::json::value::string(appObj->getName());
	result[HTTP_QUERY_KEY_process_uuid] = web::json::value::string(processUuid);
	message.reply(status_codes::OK, result);

	// clean reference from timer
	appObj->regSuicideTimer(timeout + retention);
}

void RestHandler::apiRunSync(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_sync);

	int timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 1, 60 * 60 * 24);
	auto appObj = apiRunParseApp(message);

	// Use async reply here
	HttpRequest *asyncRequest = new HttpRequestWithAppRef(message, appObj);
	appObj->runSyncrize(timeout, asyncRequest);
}

void RestHandler::apiRunAsyncOut(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiAsyncRunOut() ";
	permissionCheck(message, PERMISSION_KEY_run_app_async_output);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));

	// /appmesh/app/$app-name/run?timeout=5
	std::string app = path.substr(strlen("/appmesh/app/"));
	app = app.substr(0, app.find_first_of('/'));

	auto querymap = web::uri::split_query(web::http::uri::decode(message.m_query));
	if (querymap.find(U(HTTP_QUERY_KEY_process_uuid)) != querymap.end())
	{
		auto uuid = GET_STD_STRING(querymap.find(U(HTTP_QUERY_KEY_process_uuid))->second);

		int exitCode = 0;
		bool finished = false;
		auto appObj = Configuration::instance()->getApp(app);
		std::string body = appObj->getAsyncRunOutput(uuid, exitCode, finished);
		web::http::http_response resp(status_codes::OK);
		if (finished)
		{
			resp.set_status_code(status_codes::Created);
			resp.headers().add(HTTP_HEADER_KEY_exit_code, exitCode);
			// remove temp app immediately
			if (!appObj->isWorkingState())
				Configuration::instance()->removeApp(app);
		}

		LOG_DBG << fname << "Use process uuid :" << uuid << " ExitCode:" << exitCode;
		message.reply(resp, body);
	}
	else
	{
		LOG_DBG << fname << "process_uuid is required for get run output";
		throw std::invalid_argument("Query parameter 'process_uuid' is required to get run output");
	}
}

void RestHandler::apiGetAppOutput(const HttpRequest &message)
{
	const static char fname[] = "RestHandler::apiGetAppOutput() ";
	permissionCheck(message, PERMISSION_KEY_view_app_output);
	auto path = GET_STD_STRING(http::uri::decode(message.m_relative_uri));

	// /appmesh/app/$app-name/output
	std::string app = path.substr(strlen("/appmesh/app/"));
	auto appName = app.substr(0, app.find_first_of('/'));

	bool keepHis = getHttpQueryValue(message, HTTP_QUERY_KEY_keep_history, false, 0, 0);
	int index = getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_index, 0, 0, 0);

	checkAppAccessPermission(message, appName, false);

	auto output = Configuration::instance()->getApp(appName)->getOutput(keepHis, index);
	LOG_DBG << fname; // << output;
	message.reply(status_codes::OK, output);
}

void RestHandler::apiGetApps(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_all_app);
	auto tokenUserName = getJwtUserName(message);
	message.reply(status_codes::OK, Configuration::instance()->serializeApplication(true, tokenUserName));
}

void RestHandler::apiGetCloudApps(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_cloud_app_view);
	message.reply(status_codes::OK, ConsulConnection::instance()->viewCloudApps());
}

void RestHandler::apiGetResources(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_view_host_resource);
	message.reply(status_codes::OK, ResourceCollection::instance()->AsJson());
}

void RestHandler::apiRegApp(const HttpRequest &message)
{
	permissionCheck(message, PERMISSION_KEY_app_reg);
	auto jsonApp = message.extractJson();
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("Empty json input");
	}
	auto appName = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name);
	auto initCmd = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_init_command);
	if (initCmd.length())
	{
		// if same app not exist, do init
		// if same app exist but init cmd changed, do init
		if (!Configuration::instance()->isAppExist(appName) || initCmd != Configuration::instance()->getApp(appName)->getInitCmd())
		{
			jsonApp[JSON_KEY_APP_initial_application_only] = web::json::value::boolean(true);
		}
	}
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

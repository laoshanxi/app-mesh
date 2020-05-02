#include <atomic>
#include <chrono>
#include <boost/algorithm/string_regex.hpp>
#include <cpprest/filestream.h>
#include <cpprest/http_listener.h> // HTTP server 
#include <cpprest/http_client.h>

#include "Application.h"
#include "Configuration.h"
#include "ConsulConnection.h"
#include "RestHandler.h"
#include "PrometheusRest.h"
#include "ResourceCollection.h"
#include "User.h"
#include "Label.h"

#include "../common/Utility.h"
#include "../prom_exporter/counter.h"
#include "../prom_exporter/gauge.h"
#include "../common/HttpRequest.h"
#include "../common/Utility.h"
#include "../common/jwt-cpp/jwt.h"
#include "../common/os/linux.hpp"
#include "../common/os/chown.hpp"
#include "../common/HttpRequest.h"
#include "../prom_exporter/text_serializer.h"


RestHandler::RestHandler(const std::string& ipaddress, int port)
	:m_listenAddress(ipaddress.empty() ? std::string("0.0.0.0") : ipaddress)
{
	const static char fname[] = "RestHandler::RestHandler() ";

	// Construct URI
	web::uri_builder uri;
	uri.set_host(m_listenAddress);
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
		auto server_config = new web::http::experimental::listener::http_listener_config();
		server_config->set_ssl_context_callback(
			[&](boost::asio::ssl::context& ctx) {
				boost::system::error_code ec;

				ctx.set_options(boost::asio::ssl::context::default_workarounds |
					boost::asio::ssl::context::no_sslv2 |
					boost::asio::ssl::context::no_sslv3 |
					boost::asio::ssl::context::no_tlsv1 |
					boost::asio::ssl::context::no_tlsv1_1 |
					boost::asio::ssl::context::single_dh_use,
					ec);
				// LOG_DBG << "lambda::set_options " << ec.value() << " " << ec.message();

				ctx.use_certificate_chain_file(Configuration::instance()->getSSLCertificateFile(), ec);
				// LOG_DBG << "lambda::use_certificate_chain_file " << ec.value() << " " << ec.message();

				ctx.use_private_key_file(Configuration::instance()->getSSLCertificateKeyFile(), boost::asio::ssl::context::pem, ec);
				// LOG_DBG << "lambda::use_private_key " << ec.value() << " " << ec.message();

				// Enable ECDH cipher
				if (!SSL_CTX_set_ecdh_auto(ctx.native_handle(), 1))
				{
					LOG_WAR << "SSL_CTX_set_ecdh_auto  failed: " << std::strerror(errno);
				}
				// auto ciphers = "ALL:!RC4:!SSLv2:+HIGH:!MEDIUM:!LOW";
				auto ciphers = "HIGH:!aNULL:!eNULL:!kECDH:!aDH:!RC4:!3DES:!CAMELLIA:!MD5:!PSK:!SRP:!KRB5:@STRENGTH";
				if (!SSL_CTX_set_cipher_list(ctx.native_handle(), ciphers))
				{
					LOG_WAR << "SSL_CTX_set_cipher_list failed: " << std::strerror(errno);
				}
				SSL_CTX_clear_options(ctx.native_handle(), SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

			});
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

	// 1. Authentication
	// http://127.0.0.1:6060/login
	bindRestMethod(web::http::methods::POST, "/appmgr/login", std::bind(&RestHandler::apiLogin, this, std::placeholders::_1));
	// http://127.0.0.1:6060/auth/admin
	bindRestMethod(web::http::methods::POST, R"(/appmgr/auth/([^/\*]+))", std::bind(&RestHandler::apiAuth, this, std::placeholders::_1));
	

	// 2. View Application
	// http://127.0.0.1:6060/app/app-name
	bindRestMethod(web::http::methods::GET, R"(/appmgr/app/([^/\*]+))", std::bind(&RestHandler::apiGetApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/app-name/output
	bindRestMethod(web::http::methods::GET, R"(/appmgr/app/([^/\*]+)/output)", std::bind(&RestHandler::apiGetAppOutput, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app-manager/applications
	bindRestMethod(web::http::methods::GET, "/appmgr/applications", std::bind(&RestHandler::apiGetApps, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app-manager/resources
	bindRestMethod(web::http::methods::GET, "/appmgr/resources", std::bind(&RestHandler::apiGetResources, this, std::placeholders::_1));

	// 3. Manage Application
	// http://127.0.0.1:6060/app/app-name
	bindRestMethod(web::http::methods::PUT, R"(/appmgr/app/([^/\*]+))", std::bind(&RestHandler::apiRegApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/appname/enable
	bindRestMethod(web::http::methods::POST, R"(/appmgr/app/([^/\*]+)/enable)", std::bind(&RestHandler::apiEnableApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/appname/disable
	bindRestMethod(web::http::methods::POST, R"(/appmgr/app/([^/\*]+)/disable)", std::bind(&RestHandler::apiDisableApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/appname
	bindRestMethod(web::http::methods::DEL, R"(/appmgr/app/([^/\*]+))", std::bind(&RestHandler::apiDeleteApp, this, std::placeholders::_1));

	// 4. Operate Application
	// http://127.0.0.1:6060/app/run?timeout=5
	bindRestMethod(web::http::methods::POST, "/appmgr/app/run", std::bind(&RestHandler::apiRunAsync, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/app-name/run/output?process_uuid=uuidabc
	bindRestMethod(web::http::methods::GET, R"(/appmgr/app/([^/\*]+)/run/output)", std::bind(&RestHandler::apiRunAsyncOut, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/syncrun?timeout=5
	bindRestMethod(web::http::methods::POST, "/appmgr/app/syncrun", std::bind(&RestHandler::apiRunSync, this, std::placeholders::_1));

	// 5. File Management
	// http://127.0.0.1:6060/download
	bindRestMethod(web::http::methods::GET, "/appmgr/file/download", std::bind(&RestHandler::apiFileDownload, this, std::placeholders::_1));
	// http://127.0.0.1:6060/upload
	bindRestMethod(web::http::methods::POST, "/appmgr/file/upload", std::bind(&RestHandler::apiFileUpload, this, std::placeholders::_1));

	// 6. Label Management
	// http://127.0.0.1:6060/labels
	bindRestMethod(web::http::methods::GET, "/appmgr/labels", std::bind(&RestHandler::apiGetLabels, this, std::placeholders::_1));
	// http://127.0.0.1:6060/label/abc?value=123
	bindRestMethod(web::http::methods::PUT, R"(/appmgr/label/([^/\*]+))", std::bind(&RestHandler::apiAddLabel, this, std::placeholders::_1));
	// http://127.0.0.1:6060/label/abc
	bindRestMethod(web::http::methods::DEL, R"(/appmgr/label/([^/\*]+))", std::bind(&RestHandler::apiDeleteLabel, this, std::placeholders::_1));

	// 7. Log level
	bindRestMethod(web::http::methods::GET, "/appmgr/config", std::bind(&RestHandler::apiGetBasicConfig, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, "/appmgr/config", std::bind(&RestHandler::apiSetBasicConfig, this, std::placeholders::_1));

	// 8. Security
	bindRestMethod(web::http::methods::POST, R"(/appmgr/user/([^/\*]+)/passwd)", std::bind(&RestHandler::apiUserChangePwd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, R"(/appmgr/user/([^/\*]+)/lock)", std::bind(&RestHandler::apiUserLock, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, R"(/appmgr/user/([^/\*]+)/unlock)", std::bind(&RestHandler::apiUserUnlock, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, R"(/appmgr/user/([^/\*]+))", std::bind(&RestHandler::apiUserAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, R"(/appmgr/user/([^/\*]+))", std::bind(&RestHandler::apiUserDel, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmgr/users", std::bind(&RestHandler::apiUserList, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmgr/roles", std::bind(&RestHandler::apiRoleView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, R"(/appmgr/role/([^/\*]+))", std::bind(&RestHandler::apiRoleUpdate, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, R"(/appmgr/role/([^/\*]+))", std::bind(&RestHandler::apiRoleDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmgr/user/permissions", std::bind(&RestHandler::apiGetUserPermissions, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmgr/permissions", std::bind(&RestHandler::apiListPermissions, this, std::placeholders::_1));

	// 9. metrics
	bindRestMethod(web::http::methods::GET, R"(/appmgr/app/([^/\*]+)/health)", std::bind(&RestHandler::apiHealth, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/appmgr/metrics", std::bind(&RestHandler::apiMetrics, this, std::placeholders::_1));

	// 10. consul
	bindRestMethod(web::http::methods::POST, R"(/appmgr/watch/([^/\*]+))", std::bind(&RestHandler::apiPostWatch, this, std::placeholders::_1));

	this->open();

	LOG_INF << fname << "Listening for requests at:" << uri.to_string();
}

RestHandler::~RestHandler()
{
	this->close();
}

void RestHandler::open()
{
	m_listener->open().wait();
}

void RestHandler::close()
{
	m_listener->close();// .wait();
}

void RestHandler::handle_get(const HttpRequest& message)
{
	REST_INFO_PRINT;
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		if (m_restGetCounter) m_restGetCounter->metric().Increment();
	}
	handleRest(message, m_restGetFunctions);
}

void RestHandler::handle_put(const HttpRequest& message)
{
	REST_INFO_PRINT;
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		if (m_restPutCounter) m_restPutCounter->metric().Increment();
	}
	handleRest(message, m_restPutFunctions);
}

void RestHandler::handle_post(const HttpRequest& message)
{
	REST_INFO_PRINT;
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		if (m_restPostCounter) m_restPostCounter->metric().Increment();
	}
	handleRest(message, m_restPstFunctions);
}

void RestHandler::handle_delete(const HttpRequest& message)
{
	REST_INFO_PRINT;
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		if (m_restDelCounter) m_restDelCounter->metric().Increment();
	}
	handleRest(message, m_restDelFunctions);
}

void RestHandler::handle_options(const HttpRequest& message)
{
	message.reply(status_codes::OK);
}

void RestHandler::handleRest(const http_request& message, const std::map<std::string, std::function<void(const HttpRequest&)>>& restFunctions)
{
	static char fname[] = "RestHandler::handle_rest() ";

	std::function<void(const HttpRequest&)> stdFunction;
	auto path = Utility::stringReplace(GET_STD_STRING(message.relative_uri().path()), "//", "/");

	const auto request = std::move(HttpRequest(message));

	if (path == "/" || path.empty())
	{
		request.reply(status_codes::OK, "Application Manager");
		return;
	}

	bool findRest = false;
	for (const auto& kvp : restFunctions)
	{
		if (path == kvp.first || boost::regex_match(path, boost::regex(kvp.first)))
		{
			findRest = true;
			stdFunction = kvp.second;
			break;
		}
	}
	if (!findRest)
	{
		request.reply(status_codes::NotFound, "Path not found");
		return;
	}

	try
	{
		// LOG_DBG << fname << "rest " << path;
		stdFunction(request);
	}
	catch (const std::exception& e)
	{
		LOG_WAR << fname << "rest " << path << " failed :" << e.what();
		request.reply(web::http::status_codes::BadRequest, e.what());
	}
	catch (...)
	{
		LOG_WAR << fname << "rest " << path << " failed";
		request.reply(web::http::status_codes::BadRequest, "unknow exception");
	}
}

void RestHandler::bindRestMethod(web::http::method method, std::string path, std::function< void(const HttpRequest&)> func)
{
	static char fname[] = "RestHandler::bindRest() ";

	LOG_DBG << fname << "bind " << GET_STD_STRING(method).c_str() << " " << path;

	// bind to map
	if (method == web::http::methods::GET)
		m_restGetFunctions[path] = func;
	else if (method == web::http::methods::PUT)
		m_restPutFunctions[path] = func;
	else if (method == web::http::methods::POST)
		m_restPstFunctions[path] = func;
	else if (method == web::http::methods::DEL)
		m_restDelFunctions[path] = func;
	else
		LOG_ERR << fname << GET_STD_STRING(method).c_str() << " not supported.";
}

void RestHandler::handle_error(pplx::task<void>& t)
{
	const static char fname[] = "RestHandler::handle_error() ";

	try
	{
		t.get();
	}
	catch (const std::exception& e)
	{
		LOG_ERR << fname << e.what();
	}
	catch (...)
	{
		LOG_ERR << fname << "unknown exception";
	}
}

std::string RestHandler::verifyToken(const HttpRequest& message)
{
	if (!Configuration::instance()->getJwtEnabled()) return "";

	auto token = getTokenStr(message);
	auto decoded_token = jwt::decode(token);
	if (decoded_token.has_payload_claim(HTTP_HEADER_JWT_name))
	{
		// get user info
		auto userName = decoded_token.get_payload_claim(HTTP_HEADER_JWT_name);
		auto userObj = Configuration::instance()->getUserInfo(userName.as_string());
		auto userKey = userObj->getKey();

		// check locked
		if (userObj->locked()) throw std::invalid_argument("User was locked");

		// check user token
		auto verifier = jwt::verify()
			.allow_algorithm(jwt::algorithm::hs256{ userKey })
			.with_issuer(HTTP_HEADER_JWT_ISSUER)
			.with_claim(HTTP_HEADER_JWT_name, userName);
		verifier.verify(decoded_token);

		return std::move(userName.as_string());
	}
	else
	{
		throw std::invalid_argument("No user info in token");
	}
}

std::string RestHandler::getTokenUser(const HttpRequest& message)
{
	auto token = getTokenStr(message);
	auto decoded_token = jwt::decode(token);
	if (decoded_token.has_payload_claim(HTTP_HEADER_JWT_name))
	{
		// get user info
		auto userName = decoded_token.get_payload_claim(HTTP_HEADER_JWT_name).as_string();
		return std::move(userName);
	}
	else
	{
		throw std::invalid_argument("No user info in token");
	}
}

bool RestHandler::permissionCheck(const HttpRequest& message, const std::string& permission)
{
	const static char fname[] = "RestHandler::permissionCheck() ";

	auto userName = verifyToken(message);
	if (permission.length() && userName.length() && Configuration::instance()->getJwtEnabled())
	{
		// check user role permission
		if (Configuration::instance()->getUserPermissions(userName).count(permission))
		{
			LOG_DBG << fname << "authentication success for remote: " << message.remote_address() << " with user : " << userName << " and permission : " << permission;
			return true;
		}
		else
		{
			LOG_WAR << fname << "No such permission " << permission << " for user " << userName;
			throw std::invalid_argument(std::string("No such permission <") + permission + "> for user <" + userName + ">");
		}
	}
	else
	{
		// JWT not enabled
		return true;
	}
}

std::string RestHandler::getTokenStr(const HttpRequest& message)
{
	std::string token;
	if (message.headers().has(HTTP_HEADER_JWT_Authorization))
	{
		token = Utility::stdStringTrim(GET_STD_STRING(message.headers().find(HTTP_HEADER_JWT_Authorization)->second));
		std::string bearerFlag = HTTP_HEADER_JWT_BearerSpace;
		if (Utility::startWith(token, bearerFlag))
		{
			token = token.substr(bearerFlag.length());
		}
	}
	return std::move(token);
}

std::string RestHandler::createToken(const std::string& uname, const std::string& passwd, int timeoutSeconds)
{
	if (uname.empty() || passwd.empty())
	{
		throw std::invalid_argument("must provide name and password to generate token");
	}

	// https://thalhammer.it/projects/
	// https://www.cnblogs.com/mantoudev/p/8994341.html
	// 1. Header {"typ": "JWT","alg" : "HS256"}
	// 2. Payload{"iss": "appmgr-auth0","name" : "u-name",}
	// 3. Signature HMACSHA256((base64UrlEncode(header) + "." + base64UrlEncode(payload)), 'secret');
	// creating a token that will expire in one hour
	auto token = jwt::create()
		.set_issuer(HTTP_HEADER_JWT_ISSUER)
		.set_type(HTTP_HEADER_JWT)
		.set_issued_at(jwt::date(std::chrono::system_clock::now()))
		.set_expires_at(jwt::date(std::chrono::system_clock::now() + std::chrono::seconds{ timeoutSeconds }))
		.set_payload_claim(HTTP_HEADER_JWT_name, jwt::claim(uname))
		.sign(jwt::algorithm::hs256{ passwd });
	return std::move(token);
}

int RestHandler::getHttpQueryValue(const HttpRequest& message, const std::string& key, int defaultValue, int min, int max) const
{
	const static char fname[] = "RestHandler::getQueryValue() ";

	auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
	int rt = defaultValue;
	if (querymap.find(U(key)) != querymap.end())
	{
		rt = std::stoi(GET_STD_STRING(querymap.find(U(key))->second));
		if (min < max && (rt < min || rt > max)) rt = DEFAULT_RUN_APP_RETENTION_DURATION;
	}
	LOG_DBG << fname << key << "=" << rt;
	return rt;
}

void RestHandler::apiEnableApp(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

	// /app/$app-name/enable
	std::string appName = path.substr(strlen("/appmgr/app/"));
	appName = appName.substr(0, appName.find_last_of('/'));

	Configuration::instance()->enableApp(appName);
	message.reply(status_codes::OK, std::string("Enable <") + appName + "> success.");
}

void RestHandler::apiDisableApp(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

	// /appmgr/app/$app-name/disable
	std::string appName = path.substr(strlen("/appmgr/app/"));
	appName = appName.substr(0, appName.find_last_of('/'));

	Configuration::instance()->disableApp(appName);
	message.reply(status_codes::OK, std::string("Disable <") + appName + "> success.");
}

void RestHandler::apiDeleteApp(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_app_delete);
	auto path = GET_STD_STRING(message.relative_uri().path());

	std::string appName = path.substr(strlen("/appmgr/app/"));
	Configuration::instance()->removeApp(appName);
	auto msg = std::string("application <") + appName + "> removed.";
	message.reply(status_codes::OK, msg);
}

void RestHandler::apiFileDownload(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiFileDownload() ";
	permissionCheck(message, PERMISSION_KEY_file_download);
	if (!message.headers().has(U(HTTP_HEADER_KEY_file_path)))
	{
		message.reply(status_codes::BadRequest, "file_path header not found");
		return;
	}
	auto file = GET_STD_STRING(message.headers().find(U(HTTP_HEADER_KEY_file_path))->second);
	if (!Utility::isFileExist(file))
	{
		message.reply(status_codes::NotAcceptable, "file not found");
		return;
	}

	LOG_DBG << fname << "Downloading file <" << file << ">";

	concurrency::streams::fstream::open_istream(file, std::ios::in | std::ios::binary).then([=](concurrency::streams::istream fileStream)
		{
			// Get the content length, which is used to set the
			// Content-Length property
			fileStream.seek(0, std::ios::end);
			auto length = static_cast<size_t>(fileStream.tell());
			fileStream.seek(0, std::ios::beg);

			web::http::http_response resp(status_codes::OK);
			resp.set_body(fileStream, length);
			resp.headers().add(HTTP_HEADER_KEY_file_mode, os::fileStat(file));
			resp.headers().add(HTTP_HEADER_KEY_file_user, os::fileUser(file));
			message.reply(resp).then([this](pplx::task<void> t) { this->handle_error(t); });
		}).then([=](pplx::task<void> t)
			{
				try
				{
					t.get();
				}
				catch (...)
				{
					// opening the file (open_istream) failed.
					// Reply with an error.
					message.reply(status_codes::InternalError).then([this](pplx::task<void> t) { this->handle_error(t); });
				}
			});
}

void RestHandler::apiFileUpload(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiFileUpload() ";
	permissionCheck(message, PERMISSION_KEY_file_upload);
	if (!message.headers().has(U(HTTP_HEADER_KEY_file_path)))
	{
		message.reply(status_codes::BadRequest, "file_path header not found");
		return;
	}
	auto file = GET_STD_STRING(message.headers().find(U(HTTP_HEADER_KEY_file_path))->second);
	if (Utility::isFileExist(file))
	{
		message.reply(status_codes::Forbidden, "file already exist");
		return;
	}

	LOG_DBG << fname << "Uploading file <" << file << ">";

	concurrency::streams::file_stream<uint8_t>::open_ostream(file, std::ios::out | std::ios::binary | std::ios::trunc)
		.then([=](concurrency::streams::ostream os)
			{
				message.body().read_to_end(os.streambuf()).then([=](pplx::task<size_t> t)
					{
						os.close();
						if (message.headers().has(HTTP_HEADER_KEY_file_mode))
						{
							os::fileChmod(file, std::stoi(message.headers().find(HTTP_HEADER_KEY_file_mode)->second));
						}
						if (message.headers().has(HTTP_HEADER_KEY_file_user))
						{
							os::chown(file, message.headers().find(HTTP_HEADER_KEY_file_user)->second);
						}
						message.reply(status_codes::OK, "Success").then([=](pplx::task<void> t) { this->handle_error(t); });
					});
			}).then([=](pplx::task<void> t)
				{
					try
					{
						t.get();
					}
					catch (...)
					{
						// opening the file (open_istream) failed.
						// Reply with an error.
						message.reply(status_codes::InternalError, "Failed to write file in server").then([this](pplx::task<void> t) { this->handle_error(t); });
					}
				});
}

void RestHandler::apiGetLabels(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_label_view);
	message.reply(status_codes::OK, Configuration::instance()->getLabel()->AsJson());
}

void RestHandler::apiAddLabel(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_label_set);

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	auto vec = Utility::splitString(path, "/");
	auto labelKey = vec[vec.size() - 1];
	auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
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

void RestHandler::apiDeleteLabel(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_label_delete);

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	auto vec = Utility::splitString(path, "/");
	auto labelKey = vec[vec.size() - 1];

	Configuration::instance()->getLabel()->delLabel(labelKey);
	Configuration::instance()->saveConfigToDisk();

	message.reply(status_codes::OK);
}

void RestHandler::apiGetUserPermissions(const HttpRequest& message)
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

void RestHandler::apiGetBasicConfig(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_config_view);

	auto config = Configuration::instance()->AsJson(false);
	if (HAS_JSON_FIELD(config, JSON_KEY_Security) && HAS_JSON_FIELD(config.at(JSON_KEY_Security), JSON_KEY_JWT_Users))
		config.at(JSON_KEY_Security).erase(JSON_KEY_JWT_Users);

	message.reply(status_codes::OK, config);
}

void RestHandler::apiSetBasicConfig(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_config_set);

	auto json = message.extract_json().get();
	// do not allow users update from host-update API
	if (HAS_JSON_FIELD(json, JSON_KEY_Security) && HAS_JSON_FIELD(json.at(JSON_KEY_Security), JSON_KEY_JWT_Users))
		json.at(JSON_KEY_Security).erase(JSON_KEY_JWT_Users);
	Configuration::instance()->hotUpdate(json);

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	apiGetBasicConfig(message);
}

void RestHandler::apiUserChangePwd(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiUserChangePwd() ";

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	permissionCheck(message, PERMISSION_KEY_change_passwd);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 4)
	{
		throw std::invalid_argument("failed to get user name from path");
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getTokenUser(message);
	if (!message.headers().has(HTTP_HEADER_JWT_new_password))
	{
		throw std::invalid_argument("can not find new password from header");
	}
	auto newPasswd = Utility::stdStringTrim(Utility::decode64(GET_STD_STRING(message.headers().find(HTTP_HEADER_JWT_new_password)->second)));

	if (pathUserName != tokenUserName)
	{
		throw std::invalid_argument("user can only change its own password");
	}
	if (newPasswd.length() < APPMGR_PASSWD_MIN_LENGTH)
	{
		throw std::invalid_argument("password length should be greater than 3");
	}

	auto user = Configuration::instance()->getUserInfo(tokenUserName);
	user->updateKey(newPasswd);
	// Store encrypted key if any
	if (Configuration::instance()->getEncryptKey()) user->updateKey(Utility::hash(user->getKey()));

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> changed password";
	message.reply(status_codes::OK, "password changed success");
}

void RestHandler::apiUserLock(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiUserLock() ";

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	permissionCheck(message, PERMISSION_KEY_lock_user);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 4)
	{
		throw std::invalid_argument("failed to get user name from path");
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getTokenUser(message);

	if (pathUserName == JWT_ADMIN_NAME)
	{
		throw std::invalid_argument("admin user can not be locked");
	}
	//if (tokenUserName != JWT_ADMIN_NAME)
	//{
	//	throw std::invalid_argument("only admin can lock/unlock users");
	//}

	Configuration::instance()->getUserInfo(pathUserName)->lock();

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> locked by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserUnlock(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiUserUnlock() ";

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	permissionCheck(message, PERMISSION_KEY_lock_user);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 4)
	{
		throw std::invalid_argument("failed to get user name from path");
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getTokenUser(message);
	//if (tokenUserName != JWT_ADMIN_NAME)
	//{
	//	throw std::invalid_argument("only admin can lock/unlock users");
	//}

	Configuration::instance()->getUserInfo(pathUserName)->unlock();

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << uname << "> unlocked by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserAdd(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiUserAdd() ";

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	permissionCheck(message, PERMISSION_KEY_add_user);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 3)
	{
		throw std::invalid_argument("failed to get user name from path");
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getTokenUser(message);

	auto user = Configuration::instance()->getUsers()->addUser(pathUserName, message.extract_json(true).get(), Configuration::instance()->getRoles());
	// Store encrypted key if any
	if (Configuration::instance()->getEncryptKey()) user->updateKey(Utility::hash(user->getKey()));

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << pathUserName << "> added by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserDel(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiUserDel() ";

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	permissionCheck(message, PERMISSION_KEY_delete_user);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 3)
	{
		throw std::invalid_argument("failed to get user name from path");
	}
	auto pathUserName = vec[2];
	auto tokenUserName = getTokenUser(message);

	Configuration::instance()->getUsers()->delUser(pathUserName);

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "User <" << pathUserName << "> deleted by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiUserList(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_get_users);

	auto users = Configuration::instance()->getUsers()->AsJson();
	for (auto& user : users.as_object())
	{
		if (HAS_JSON_FIELD(user.second, JSON_KEY_USER_key)) user.second.erase(JSON_KEY_USER_key);
	}

	message.reply(status_codes::OK, users);
}

void RestHandler::apiRoleView(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_role_view);

	message.reply(status_codes::OK, Configuration::instance()->getRoles()->AsJson());
}

void RestHandler::apiRoleUpdate(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiRoleUpdate() ";

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	permissionCheck(message, PERMISSION_KEY_role_update);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 3)
	{
		throw std::invalid_argument("failed to get role name from path");
	}
	auto pathRoleName = vec[2];
	auto tokenUserName = getTokenUser(message);

	//if (tokenUserName == JWT_ADMIN_NAME)
	//{
	//	throw std::invalid_argument("role can be only updated by admin");
	//}

	Configuration::instance()->getRoles()->addRole(message.extract_json(true).get(), pathRoleName);

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "Role <" << pathRoleName << "> updated by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiRoleDelete(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiRoleDelete() ";

	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	permissionCheck(message, PERMISSION_KEY_role_delete);

	auto vec = Utility::splitString(path, "/");
	if (vec.size() != 3)
	{
		throw std::invalid_argument("failed to get role name from path");
	}
	auto pathRoleName = vec[2];
	auto tokenUserName = getTokenUser(message);

	//if (tokenUserName == JWT_ADMIN_NAME)
	//{
	//	throw std::invalid_argument("role can be only updated by admin");
	//}

	Configuration::instance()->getRoles()->delRole(pathRoleName);

	Configuration::instance()->saveConfigToDisk();
	ConsulConnection::instance()->saveSecurity();

	LOG_INF << fname << "Role <" << pathRoleName << "> deleted by " << tokenUserName;
	message.reply(status_codes::OK);
}

void RestHandler::apiListPermissions(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_permission_list);

	auto userName = verifyToken(message);
	auto permissions = Configuration::instance()->getAllPermissions();
	auto json = web::json::value::array(permissions.size());
	int index = 0;
	for (auto perm : permissions)
	{
		json[index++] = web::json::value::string(perm);
	}
	message.reply(status_codes::OK, json);
}

void RestHandler::apiHealth(const HttpRequest& message)
{
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	// /appmgr/app/$app-name/health
	std::string appName = path.substr(strlen("/appmgr/app/"));
	appName = appName.substr(0, appName.find_last_of('/'));
	auto health = Configuration::instance()->getApp(appName)->getHealth();
	http::status_code status = status_codes::OK;
	if (health != 0) status = status_codes::NotAcceptable;
	message.reply(status, std::to_string(health));
}

void RestHandler::apiMetrics(const HttpRequest& message)
{
	message.reply(status_codes::OK, PrometheusRest::instance()->collectData(), "text/plain; version=0.0.4");
}

void RestHandler::apiPostWatch(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_consul_watch);
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	std::string type = path.substr(strlen("/appmgr/watch/"));
	if (type == "security")
	{
		message.reply(status_codes::OK, "success");
		ConsulConnection::instance()->syncSecurity();
	}
	else if (type == "topology")
	{
		message.reply(status_codes::OK, "success");
		ConsulConnection::instance()->syncTopology();
	}
	else if (type == "schedule")
	{
		message.reply(status_codes::OK, "success");
		// avoid schedule storm, only need leave one schedule request in pending
		static std::atomic_int scheduleWorkers(0);
		if (scheduleWorkers < 2)
		{
			scheduleWorkers++;
			ConsulConnection::instance()->syncSchedule();
			scheduleWorkers--;
		}
		
	}
	else
	{
		message.reply(status_codes::BadRequest, "invalid watch type");
	}
}

void RestHandler::apiLogin(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiLogin() ";

	if (message.headers().has(HTTP_HEADER_JWT_username) && message.headers().has(HTTP_HEADER_JWT_password))
	{
		auto uname = Utility::decode64(GET_STD_STRING(message.headers().find(HTTP_HEADER_JWT_username)->second));
		auto passwd = Utility::decode64(GET_STD_STRING(message.headers().find(HTTP_HEADER_JWT_password)->second));
		int timeoutSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS;	// default timeout is 1 hour
		if (message.headers().has(HTTP_HEADER_JWT_expire_seconds))
		{
			auto timeout = message.headers().find(HTTP_HEADER_JWT_expire_seconds)->second;
			auto timeoutValue = std::stoi(timeout);
			// timeout should less than 24h for none-admin user
			if (uname != JWT_ADMIN_NAME)
			{
				if (timeoutValue > 1 && timeoutValue < MAX_TOKEN_EXPIRE_SECONDS)
				{
					timeoutSeconds = timeoutValue;
					LOG_WAR << fname << "User <" << uname << "> login expire_seconds was set from " << timeout << "to " << timeoutValue;
				}
			}
		}

		if (Configuration::instance()->getEncryptKey()) passwd = Utility::hash(passwd);
		auto token = createToken(uname, passwd, timeoutSeconds);

		web::json::value result = web::json::value::object();
		web::json::value profile = web::json::value::object();
		profile[GET_STRING_T("name")] = web::json::value::string(uname);
		profile[GET_STRING_T("auth_time")] = web::json::value::number(std::chrono::system_clock::now().time_since_epoch().count());
		result[GET_STRING_T("profile")] = profile;
		result[GET_STRING_T("token_type")] = web::json::value::string(HTTP_HEADER_JWT_Bearer);
		result[HTTP_HEADER_JWT_access_token] = web::json::value::string(GET_STRING_T(token));
		result[GET_STRING_T("expire_time")] = web::json::value::number(std::chrono::system_clock::now().time_since_epoch().count() + timeoutSeconds);

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
		message.reply(status_codes::NetworkAuthenticationRequired, "username or password missing");
	}
}

void RestHandler::apiAuth(const HttpRequest& message)
{
	std::string permission;
	if (message.headers().has(HTTP_HEADER_JWT_auth_permission))
	{
		permission = message.headers().find(HTTP_HEADER_JWT_auth_permission)->second;
	}

	// permission is empty meas just verify token
	// with permission means token and permission check both
	if (permissionCheck(message, permission))
	{
		auto result = web::json::value::object();
		result["user"] = web::json::value::string(getTokenUser(message));
		message.reply(status_codes::OK, result);
	}
	else
	{
		message.reply(status_codes::Unauthorized, "Incorrect authentication info");
	}
}

void RestHandler::apiGetApp(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_view_app);
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	std::string app = path.substr(strlen("/appmgr/app/"));
	message.reply(status_codes::OK, Utility::prettyJson(GET_STD_STRING(Configuration::instance()->getApp(app)->AsJson(true).serialize())));
}

std::shared_ptr<Application> RestHandler::apiRunParseApp(const HttpRequest& message)
{
	auto jsonApp = const_cast<HttpRequest*>(&message)->extract_json(true).get();
	// force specify a UUID app name
	auto appName = Utility::createUUID();
	jsonApp[JSON_KEY_APP_name] = web::json::value::string(appName);
	jsonApp[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(Application::STATUS::NOTAVIALABLE));
	jsonApp[JSON_KEY_APP_cache_lines] = web::json::value::number(MAX_APP_CACHED_LINES);
	return Configuration::instance()->addApp(jsonApp);
}

void RestHandler::apiRunAsync(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiAsyncRun() ";
	permissionCheck(message, PERMISSION_KEY_run_app_async);

	int retention = getHttpQueryValue(message, HTTP_QUERY_KEY_retention, DEFAULT_RUN_APP_RETENTION_DURATION, 1, 60 * 60 * 24);
	int timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 1, 60 * 60 * 24);
	auto appObj = apiRunParseApp(message);

	auto processUuid = appObj->runAsyncrize(timeout);
	auto result = web::json::value::object();
	result[JSON_KEY_APP_name] = web::json::value::string(appObj->getName());
	result[HTTP_QUERY_KEY_process_uuid] = web::json::value::string(processUuid);
	message.reply(status_codes::OK, result);

	// clean reference from timer
	appObj->registerTimer(1000L * (timeout + retention), 0, std::bind(&Application::onSuicideEvent, appObj, std::placeholders::_1), fname);
}

void RestHandler::apiRunSync(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_sync);

	int timeout = getHttpQueryValue(message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 1, 60 * 60 * 24);
	auto appObj = apiRunParseApp(message);

	// Use async reply here
	HttpRequest* asyncRequest = new HttpRequestWithAppRef(message, appObj);
	appObj->runSyncrize(timeout, asyncRequest);
}

void RestHandler::apiRunAsyncOut(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiAsyncRunOut() ";
	permissionCheck(message, PERMISSION_KEY_run_app_async_output);
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

	// /appmgr/app/$app-name/run?timeout=5
	std::string app = path.substr(strlen("/appmgr/app/"));
	app = app.substr(0, app.find_first_of('/'));

	auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
	if (querymap.find(U(HTTP_QUERY_KEY_process_uuid)) != querymap.end())
	{
		auto uuid = GET_STD_STRING(querymap.find(U(HTTP_QUERY_KEY_process_uuid))->second);

		int exitCode = 0;
		bool finished = false;
		auto appObj = Configuration::instance()->getApp(app);
		std::string body = appObj->getAsyncRunOutput(uuid, exitCode, finished);
		web::http::http_response resp(status_codes::OK);
		resp.set_body(body);
		if (finished)
		{
			resp.set_status_code(status_codes::Created);
			resp.headers().add(HTTP_HEADER_KEY_exit_code, exitCode);
			// remove temp app immediately
			if (!appObj->isWorkingState()) Configuration::instance()->removeApp(app);
		}

		LOG_DBG << fname << "Use process uuid :" << uuid << " exit_code:" << exitCode;
		message.reply(resp);
	}
	else
	{
		LOG_DBG << fname << "process_uuid is required for get run output";
		throw std::invalid_argument("process_uuid is required for get run output");
	}
}

void RestHandler::apiGetAppOutput(const HttpRequest& message)
{
	const static char fname[] = "RestHandler::apiGetAppOutput() ";

	permissionCheck(message, PERMISSION_KEY_view_app_output);
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

	// /app/$app-name/output
	std::string app = path.substr(strlen("/appmgr/app/"));
	app = app.substr(0, app.find_first_of('/'));
	bool keepHis = getHttpQueryValue(message, HTTP_QUERY_KEY_keep_history, false, 0, 0);
	auto output = Configuration::instance()->getApp(app)->getOutput(keepHis);
	LOG_DBG << fname;// << output;
	message.reply(status_codes::OK, output);
}

void RestHandler::apiGetApps(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_view_all_app);
	message.reply(status_codes::OK, Configuration::instance()->getApplicationJson(true));
}

void RestHandler::apiGetResources(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_view_host_resource);
	message.reply(status_codes::OK, Utility::prettyJson(GET_STD_STRING(ResourceCollection::instance()->AsJson().serialize())));
}

void RestHandler::apiRegApp(const HttpRequest& message)
{
	permissionCheck(message, PERMISSION_KEY_app_reg);
	auto jsonApp = message.extract_json(true).get();
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("invalid json format");
	}
	auto initCmd = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_init_command);
	if (initCmd.length())
	{
		// if same app not exist, do init
		// if same app exist but init cmd changed, do init
		auto appName = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name);
		if (!Configuration::instance()->isAppExist(appName) || initCmd != Configuration::instance()->getApp(appName)->getInitCmd())
		{
			jsonApp[JSON_KEY_APP_initial_application_only] = web::json::value::boolean(true);
		}
	}
	auto app = Configuration::instance()->addApp(jsonApp);
	message.reply(status_codes::OK, Utility::prettyJson(GET_STD_STRING(app->AsJson(false).serialize())));
}

void RestHandler::initMetrics(std::shared_ptr<PrometheusRest> prom)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);

	// clean
	m_restGetCounter = nullptr;
	m_restPutCounter = nullptr;
	m_restDelCounter = nullptr;
	m_restPostCounter = nullptr;

	// update
	if (prom)
	{
		m_restGetCounter = prom->createPromCounter(
			PROM_METRIC_NAME_appmgr_http_request_count, PROM_METRIC_HELP_appmgr_http_request_count,
			{ {"method", "GET"}, {"listen", m_listenAddress} }
		);
		m_restPutCounter = prom->createPromCounter(
			PROM_METRIC_NAME_appmgr_http_request_count, PROM_METRIC_HELP_appmgr_http_request_count,
			{ {"method", "PUT"}, { "listen", m_listenAddress } }
		);
		m_restDelCounter = prom->createPromCounter(
			PROM_METRIC_NAME_appmgr_http_request_count, PROM_METRIC_HELP_appmgr_http_request_count,
			{ {"method", "DELETE"}, { "listen", m_listenAddress } }
		);
		m_restPostCounter = prom->createPromCounter(
			PROM_METRIC_NAME_appmgr_http_request_count, PROM_METRIC_HELP_appmgr_http_request_count,
			{ {"method", "POST"}, { "listen", m_listenAddress } }
		);
	}
}

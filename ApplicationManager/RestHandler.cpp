#include <chrono>
#include <boost/algorithm/string_regex.hpp>
#include <cpprest/filestream.h>
#include "RestHandler.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"
#include "../common/jwt-cpp/jwt.h"
#include "../common/os/linux.hpp"
#include "../common//os/chown.hpp"

#define REST_INFO_PRINT \
	LOG_DBG << "Method: " << message.method(); \
	LOG_DBG << "URI: " << http::uri::decode(message.relative_uri().path()); \
	LOG_DBG << "Query: " << http::uri::decode(message.relative_uri().query()); \
	LOG_DBG << "Remote: " << message.remote_address(); // for new version of cpprestsdk

RestHandler::RestHandler(std::string ipaddress, int port)
{
	const static char fname[] = "RestHandler::RestHandler() ";

	// Construct URI
	web::uri_builder uri;
	if (ipaddress.empty())
	{
		uri.set_host("0.0.0.0");
	}
	else
	{
		uri.set_host(ipaddress);
	}
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
		auto server_config = new http_listener_config();
		server_config->set_ssl_context_callback(
			[&](boost::asio::ssl::context & ctx) {
				boost::system::error_code ec;

				ctx.set_options(boost::asio::ssl::context::default_workarounds |
					boost::asio::ssl::context::no_sslv2 |
					boost::asio::ssl::context::no_sslv3 |
					boost::asio::ssl::context::no_tlsv1 |
					boost::asio::ssl::context::no_tlsv1_1 |
					boost::asio::ssl::context::single_dh_use,
					ec);
				LOG_INF << "lambda::set_options " << ec.value() << " " << ec.message();

				ctx.use_certificate_chain_file(Configuration::instance()->getSSLCertificateFile(), ec);
				LOG_INF << "lambda::use_certificate_chain_file " << ec.value() << " " << ec.message();

				ctx.use_private_key_file(Configuration::instance()->getSSLCertificateKeyFile(), boost::asio::ssl::context::pem, ec);
				LOG_INF << "lambda::use_private_key " << ec.value() << " " << ec.message();

				// Enable ECDH cipher
				if (!SSL_CTX_set_ecdh_auto(ctx.native_handle(), 1))
				{
					LOG_WAR << "SSL_CTX_set_ecdh_auto  failed: " << std::strerror(errno);
				}
				auto ciphers = "ALL:!RC4:!SSLv2:+HIGH:!MEDIUM:!LOW";
				// auto ciphers = "HIGH:!aNULL:!eNULL:!kECDH:!aDH:!RC4:!3DES:!CAMELLIA:!MD5:!PSK:!SRP:!KRB5:@STRENGTH";
				if (!SSL_CTX_set_cipher_list(ctx.native_handle(), ciphers))
				{
					LOG_WAR << "SSL_CTX_set_cipher_list failed: " << std::strerror(errno);
				}

			});
		m_listener = std::make_shared<http_listener>(uri.to_uri(), *server_config);
	}
	else
	{
		uri.set_scheme("http");
		m_listener = std::make_shared<http_listener>(uri.to_uri());
	}

	m_listener->support(methods::GET, std::bind(&RestHandler::handle_get, this, std::placeholders::_1));
	m_listener->support(methods::PUT, std::bind(&RestHandler::handle_put, this, std::placeholders::_1));
	m_listener->support(methods::POST, std::bind(&RestHandler::handle_post, this, std::placeholders::_1));
	m_listener->support(methods::DEL, std::bind(&RestHandler::handle_delete, this, std::placeholders::_1));

	// http://127.0.0.1:6060/login
	bindRest(web::http::methods::POST, "/login", std::bind(&RestHandler::apiLogin, this, std::placeholders::_1));
	// http://127.0.0.1:6060/auth/admin
	bindRest(web::http::methods::POST, R"(/auth/([^/\*]+))", std::bind(&RestHandler::apiAuth, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/app-name
	bindRest(web::http::methods::GET, R"(/app/([^/\*]+))", std::bind(&RestHandler::apiGetApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/app-name/run?timeout=5
	bindRest(web::http::methods::POST, R"(/app/([^/\*]+)/run)", std::bind(&RestHandler::apiRunApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/app-name/waitrun?timeout=5
	bindRest(web::http::methods::POST, R"(/app/([^/\*]+)/waitrun)", std::bind(&RestHandler::apiWaitRunApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/app-name/run/output?process_uuid=uuidabc
	bindRest(web::http::methods::GET, R"(/app/([^/\*]+)/run/output)", std::bind(&RestHandler::apiRunOutput, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app-manager/applications
	bindRest(web::http::methods::GET, "/app-manager/applications", std::bind(&RestHandler::apiGetApps, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app-manager/resources
	bindRest(web::http::methods::GET, "/app-manager/resources", std::bind(&RestHandler::apiGetResources, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/app-name
	bindRest(web::http::methods::PUT, R"(/app/([^/\*]+))", std::bind(&RestHandler::apiRegApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/sh/shell-app-id
	bindRest(web::http::methods::PUT, R"(/app/sh/([^/\*]+))", std::bind(&RestHandler::apiRegShellApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/appname?action=start
	bindRest(web::http::methods::POST, R"(/app/([^/\*]+))", std::bind(&RestHandler::apiControlApp, this, std::placeholders::_1));
	// http://127.0.0.1:6060/app/appname
	bindRest(web::http::methods::DEL, R"(/app/([^/\*]+))", std::bind(&RestHandler::apiDeleteApp, this, std::placeholders::_1));

	// http://127.0.0.1:6060/download
	bindRest(web::http::methods::GET, "/download", std::bind(&RestHandler::apiDownloadFile, this, std::placeholders::_1));
	// http://127.0.0.1:6060/upload
	bindRest(web::http::methods::PUT, "/upload", std::bind(&RestHandler::apiUploadFile, this, std::placeholders::_1));

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

void RestHandler::handle_get(http_request message)
{
	REST_INFO_PRINT;
	verifyUserToken(message, getToken(message));

	handleRest(message, m_restGetFunctions);
}

void RestHandler::handle_put(http_request message)
{
	REST_INFO_PRINT;
	verifyAdminToken(message, getToken(message));

	handleRest(message, m_restPutFunctions);
}

void RestHandler::handle_post(http_request message)
{
	REST_INFO_PRINT;
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

	// login and auth does not need check token here.
	if (path != "/login" && !Utility::startWith(path, "/auth/"))
	{
		verifyAdminToken(message, getToken(message));
	}

	handleRest(message, m_restPstFunctions);
}

void RestHandler::handle_delete(http_request message)
{
	REST_INFO_PRINT;
	verifyAdminToken(message, getToken(message));

	handleRest(message, m_restDelFunctions);
}

void RestHandler::handleRest(http_request& message, std::map<utility::string_t, std::function<void(http_request&)>>& restFunctions)
{
	static char fname[] = "RestHandler::handle_rest() ";

	std::function<void(http_request&)> stdFunction;
	auto path = GET_STD_STRING(message.relative_uri().path());
	while (path.find("//") != std::string::npos) boost::algorithm::replace_all(path, "//", "/");

	if (path == "/" || path.empty())
	{
		message.reply(status_codes::OK, "REST service");
		return;
	}

	bool findRest = false;
	for (const auto& kvp : restFunctions)
	{
		if (path == GET_STD_STRING(kvp.first) || boost::regex_match(path, boost::regex(GET_STD_STRING(kvp.first))))
		{
			findRest = true;
			stdFunction = kvp.second;
			break;
		}
	}
	if (!findRest)
	{
		message.reply(status_codes::NotFound, "Path not found");
		return;
	}

	try
	{
		LOG_DBG << fname << "rest " << path;
		stdFunction(message);
	}
	catch (const std::exception& e)
	{
		LOG_WAR << fname << "rest " << path << " failed :" << e.what();
		message.reply(web::http::status_codes::BadRequest, e.what());
	}
	catch (...)
	{
		LOG_WAR << fname << "rest " << path << " failed";
		message.reply(web::http::status_codes::BadRequest, "unknow exception");
	}
}

void RestHandler::bindRest(web::http::method method, std::string path, std::function< void(http_request&)> func)
{
	static char fname[] = "RestHandler::bindRest()";

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


bool RestHandler::verifyAdminToken(const http_request& message, const std::string& token)
{
	return verifyToken(message, token, Configuration::instance()->getJwtAdminName(), Configuration::instance()->getJwtAdminKey());
}

bool RestHandler::verifyUserToken(const http_request& message, const std::string & token)
{
	auto decoded_token = jwt::decode(token);
	auto claims = decoded_token.get_payload_claims();
	auto userIter = claims.find("name");
	if (userIter != claims.end())
	{
		if (userIter->second.as_string() == "admin")
		{
			return verifyToken(message, token, Configuration::instance()->getJwtAdminName(), Configuration::instance()->getJwtAdminKey());
		}
		else if (userIter->second.as_string() == "user")
		{
			return verifyToken(message, token, Configuration::instance()->getJwtUserName(), Configuration::instance()->getJwtUserKey());
		}
	}
	throw std::invalid_argument("Unsupported jwt claims format");
}

bool RestHandler::verifyToken(const http_request& message, const std::string& token, const std::string& user, const std::string& key)
{
	const static char fname[] = "RestHandler::verifyToken() ";

	if (Configuration::instance()->getJwtEnabled())
	{
		if (token.empty())
		{
			LOG_WAR << fname << "Authentication failed for Remote: " << message.remote_address();
			throw std::invalid_argument("Access denied: must have a token.");
		}
		auto decoded_token = jwt::decode(token);
		auto verifier = jwt::verify()
			.allow_algorithm(jwt::algorithm::hs256{ key })
			.with_issuer(JWT_ISSUER)
			.with_claim("name", std::string(user));
		verifier.verify(decoded_token);
		LOG_DBG << fname << "Authentication success for Remote: " << message.remote_address();
	}
	return true;
}

std::string RestHandler::getToken(const http_request& message)
{
	std::string token;
	if (message.headers().has("Authorization"))
	{
		token = Utility::stdStringTrim(GET_STD_STRING(message.headers().find("Authorization")->second));
		std::string bearerFlag = "Bearer ";
		if (Utility::startWith(token, bearerFlag))
		{
			token = token.substr(bearerFlag.length());
		}
	}
	return std::move(token);
}

std::string RestHandler::createToken(const std::string uname, const std::string passwd, int timeoutSeconds)
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
		.set_issuer(JWT_ISSUER)
		.set_type("JWT")
		.set_issued_at(jwt::date(std::chrono::system_clock::now()))
		.set_expires_at(jwt::date(std::chrono::system_clock::now() + std::chrono::seconds{ timeoutSeconds }))
		.set_payload_claim("name", std::string(uname))
		.sign(jwt::algorithm::hs256{ passwd });
	return std::move(token);
}

void RestHandler::apiRegShellApp(const http_request& message)
{
	const static char fname[] = "RestHandler::apiRegShellApp() ";

	auto jsonApp = message.extract_json(true).get();
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("invalid json format");
	}
	auto jobj = jsonApp.as_object();

	jobj[GET_STRING_T("status")] = web::json::value::number(0);
	// /bin/sh -c "export A=b;export B=c;env | grep B"
	std::string shellCommandLine = "/bin/sh -c '";
	shellCommandLine.append(Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, "command_line")));
	shellCommandLine.append("'");
	jobj[GET_STRING_T("command_line")] = web::json::value::string(GET_STRING_T(shellCommandLine));
	LOG_DBG << fname << "Shell app json: " << jsonApp.serialize();

	auto app = Configuration::instance()->addApp(jobj);
	message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(app->AsJson(true).serialize())));
}

void RestHandler::apiControlApp(const http_request & message)
{
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
	auto appName = path.substr(strlen("/app/"));

	if (querymap.find(U("action")) != querymap.end())
	{
		auto action = GET_STD_STRING(querymap.find(U("action"))->second);
		auto msg = action + " <" + appName + "> success.";
		if (action == "start")
		{
			Configuration::instance()->startApp(appName);
			message.reply(status_codes::OK, msg);
		}
		else if (action == "stop")
		{
			Configuration::instance()->stopApp(appName);
			message.reply(status_codes::OK, msg);
		}
		else
		{
			message.reply(status_codes::ServiceUnavailable, "No such action query flag");
		}
	}
	else
	{
		message.reply(status_codes::ServiceUnavailable, "Require action query flag");
	}
}

void RestHandler::apiDeleteApp(const http_request & message)
{
	auto path = GET_STD_STRING(message.relative_uri().path());

	std::string appName = path.substr(strlen("/app/"));
	Configuration::instance()->removeApp(appName);
	auto msg = std::string("application <") + appName + "> removed.";
	message.reply(status_codes::OK, msg);
}

void RestHandler::apiDownloadFile(const http_request& message)
{
	const static char fname[] = "RestHandler::apiDownloadFile() ";

	if (!message.headers().has(U("file_path")))
	{
		message.reply(status_codes::BadRequest, "file_path header not found");
		return;
	}
	auto file = GET_STD_STRING(message.headers().find(U("file_path"))->second);
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

		message.reply(status_codes::OK, fileStream, length).then([this](pplx::task<void> t) { this->handle_error(t); });
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

void RestHandler::apiUploadFile(const http_request & message)
{
	const static char fname[] = "RestHandler::apiUploadFile() ";

	if (!message.headers().has(U("file_path")))
	{
		message.reply(status_codes::BadRequest, "file_path header not found");
		return;
	}
	auto file = GET_STD_STRING(message.headers().find(U("file_path"))->second);
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
				if (message.headers().has("file_mode"))
				{
					os::fileChmod(file, std::stoi(message.headers().find("file_mode")->second));
				}
				if (message.headers().has("file_user"))
				{
					os::chown(file, message.headers().find("file_user")->second);
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

void RestHandler::apiLogin(const http_request& message)
{
	const static char fname[] = "RestHandler::apiLogin() ";

	if (message.headers().has("username") && message.headers().has("password"))
	{
		auto uname = Utility::decode64(GET_STD_STRING(message.headers().find("username")->second));
		auto passwd = Utility::decode64(GET_STD_STRING(message.headers().find("password")->second));
		int timeoutSeconds = 60 * 10;	// default timeout is 10 minutes
		if (message.headers().has("expire_seconds"))
		{
			auto timeout = message.headers().find("expire_seconds")->second;
			auto timeoutValue = std::stoi(timeout);
			if (timeoutValue > 1 && timeoutValue < (24 * 60 * 60)) timeoutSeconds = timeoutValue;
		}
		auto token = createToken(uname, passwd, timeoutSeconds);

		web::json::value result = web::json::value::object();
		web::json::value profile = web::json::value::object();
		profile[GET_STRING_T("name")] = web::json::value::string(uname);
		profile[GET_STRING_T("auth_time")] = web::json::value::number(std::chrono::system_clock::now().time_since_epoch().count());
		result[GET_STRING_T("profile")] = profile;
		result[GET_STRING_T("token_type")] = web::json::value::string("Bearer");
		result[GET_STRING_T("access_token")] = web::json::value::string(GET_STRING_T(token));
		result[GET_STRING_T("expire_time")] = web::json::value::number(std::chrono::system_clock::now().time_since_epoch().count() + timeoutSeconds);

		if (verifyUserToken(message, token))
		{
			message.reply(status_codes::OK, result);
			LOG_DBG << fname << "User <" << uname << "> login success";
		}
		else
		{
			message.reply(status_codes::Unauthorized, "Incorrect authentication info");
		}
	}
	else
	{
		message.reply(status_codes::NetworkAuthenticationRequired, "username or password missing");
	}
}

void RestHandler::apiAuth(const http_request& message)
{
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	auto userName = path.substr(strlen("/auth/"));
	if (userName == "admin")
	{
		verifyAdminToken(message, getToken(message));
		message.reply(status_codes::OK, "Success");
	}
	else if (userName == "user")
	{
		verifyUserToken(message, getToken(message));
		message.reply(status_codes::OK, "Success");
	}
	else
	{
		message.reply(status_codes::Unauthorized, "No such user");
	}
}

void RestHandler::apiGetApp(const http_request& message)
{
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
	std::string app = path.substr(strlen("/app/"));
	message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(Configuration::instance()->getApp(app)->AsJson(true).serialize())));
}

void RestHandler::apiRunApp(const http_request& message)
{
	const static char fname[] = "RestHandler::apiRunApp() ";
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

	// /app/$app-name/run?timeout=5
	std::string app = path.substr(strlen("/app/"));
	app = app.substr(0, app.find_first_of('/'));

	auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
	int timeout = 10; // default use 10 seconds
	if (querymap.find(U("timeout")) != querymap.end())
	{
		timeout = std::abs(std::stoi(GET_STD_STRING(querymap.find(U("timeout"))->second)));
		if (timeout == 0) timeout = 10;
		LOG_DBG << fname << "Use timeout :" << timeout;

	}
	else
	{
		LOG_DBG << fname << "Use default timeout :" << timeout;
	}
	// Parse env map  (optional)
	std::map<std::string, std::string> envMap;
	auto body = const_cast<http_request*>(&message)->extract_utf8string(true).get();
	if (body.length() && body != "null")
	{
		auto jsonEnv = web::json::value::parse(body).as_object();
		if (HAS_JSON_FIELD(jsonEnv, "env"))
		{
			auto env = jsonEnv.at(GET_STRING_T("env")).as_object();
			for (auto it = env.begin(); it != env.end(); it++)
			{
				envMap[GET_STD_STRING((*it).first)] = GET_STD_STRING((*it).second.as_string());
			}
		}
	}
	message.reply(status_codes::OK, Configuration::instance()->getApp(app)->testRun(timeout, envMap));
}

void RestHandler::apiWaitRunApp(const http_request& message)
{
	const static char fname[] = "RestHandler::apiWaitRunApp() ";
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

	// /app/$app-name/run?timeout=5
	std::string app = path.substr(strlen("/app/"));
	app = app.substr(0, app.find_first_of('/'));

	auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
	int timeout = 10; // default use 10 seconds
	if (querymap.find(U("timeout")) != querymap.end())
	{
		timeout = std::abs(std::stoi(GET_STD_STRING(querymap.find(U("timeout"))->second)));
		if (timeout == 0) timeout = 10;
		LOG_DBG << fname << "Use timeout :" << timeout;

	}
	else
	{
		LOG_DBG << fname << "Use default timeout :" << timeout;
	}

	// Parse env map  (optional)
	std::map<std::string, std::string> envMap;
	auto body = const_cast<http_request*>(&message)->extract_utf8string(true).get();
	if (body.length() && body != "null")
	{
		auto jsonEnv = web::json::value::parse(body).as_object();
		if (HAS_JSON_FIELD(jsonEnv, "env"))
		{
			auto env = jsonEnv.at(GET_STRING_T("env")).as_object();
			for (auto it = env.begin(); it != env.end(); it++)
			{
				envMap[GET_STD_STRING((*it).first)] = GET_STD_STRING((*it).second.as_string());
			}
		}
	}

	// Use async reply here
	http_request* asyncRequest = new http_request(message);
	Configuration::instance()->getApp(app)->testRun(timeout, envMap, asyncRequest);
}

void RestHandler::apiRunOutput(const http_request& message)
{
	const static char fname[] = "RestHandler::apiRunOutput() ";
	auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

	// /app/$app-name/run?timeout=5
	std::string app = path.substr(strlen("/app/"));
	app = app.substr(0, app.find_first_of('/'));

	auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
	if (querymap.find(U("process_uuid")) != querymap.end())
	{
		auto uuid = GET_STD_STRING(querymap.find(U("process_uuid"))->second);


		int exitCode = 0;
		bool finished = false;
		std::string body = Configuration::instance()->getApp(app)->getTestOutput(uuid, exitCode, finished);
		web::http::http_response resp(status_codes::OK);
		resp.set_body(body);
		if (finished)
		{
			resp.set_status_code(status_codes::NotFound);
			resp.headers().add("exit_code", exitCode);
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

void RestHandler::apiGetApps(const http_request& message)
{
	message.reply(status_codes::OK, Configuration::instance()->getApplicationJson(true));
}

void RestHandler::apiGetResources(const http_request& message)
{
	message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(ResourceCollection::instance()->AsJson().serialize())));
}

void RestHandler::apiRegApp(const http_request& message)
{
	auto jsonApp = message.extract_json(true).get();
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("invalid json format");
	}
	auto app = Configuration::instance()->addApp(jsonApp.as_object());
	message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(app->AsJson(true).serialize())));
}

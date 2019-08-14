#include <chrono>
#include "RestHandler.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"
#include "../common/jwt-cpp/jwt.h"

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
			if (!SSL_CTX_set_cipher_list(ctx.native_handle(), 
				"HIGH:!aNULL:!eNULL:!kECDH:!aDH:!RC4:!3DES:!CAMELLIA:!MD5:!PSK:!SRP:!KRB5:@STRENGTH"))
			{
				LOG_WAR << "SSL_CTX_set_cipher_list failed: "<< std::strerror(errno);
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
	const static char fname[] = "RestHandler::handle_get() ";
	try
	{
		REST_INFO_PRINT;
		verifyUserToken(message, getToken(message));
		auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

		if (path == std::string("/app-manager/applications"))
		{
			message.reply(status_codes::OK, Configuration::instance()->getApplicationJson(true));
		}
		if (path == std::string("/app-manager/resources"))
		{
			message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(ResourceCollection::instance()->AsJson().serialize())));
		}
		else if (path == "/app-manager/config")
		{
			message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(Configuration::instance()->AsJson(false).serialize())));
		}
		else if (Utility::startWith(path, "/app/"))
		{
			// Get app name from path
			std::string app;
			std::vector<std::string> pathVec = Utility::splitString(path, "/");
			if (pathVec.size() >= 2) app = pathVec[1];
			// /app/someapp
			std::string getPath = std::string("/app/").append(app);
			// /app/someapp/testrun
			std::string testRunPath = getPath + "/testrun";
			// /app/someapp/testrun/output
			std::string testRunOutputPath = getPath + "/testrun/output";
			if (path == getPath)
			{
				message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(Configuration::instance()->getApp(app)->AsJson(true).serialize())));
			}
			else if (path == testRunOutputPath)
			{
				auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
				if (querymap.find(U("process_uuid")) != querymap.end())
				{
					auto uuid = GET_STD_STRING(querymap.find(U("process_uuid"))->second);
					LOG_DBG << fname << "Use process uuid :" << uuid;
					message.reply(status_codes::OK, Configuration::instance()->getApp(app)->getTestOutput(uuid));
				}
				else
				{
					LOG_DBG << fname << "process_uuid is required for get testrun output";
					throw std::invalid_argument("process_uuid is required for get testrun output");
				}
			}
			else if (path == testRunPath)
			{
				auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
				int timeout = 5; // default use 5 seconds
				if (querymap.find(U("timeout")) != querymap.end())
				{
					// Limit range in [-60 ~ 60]
					auto requestTimeout = std::stoi(GET_STD_STRING(querymap.find(U("timeout"))->second));
					// set max timeout to 60s
					if (requestTimeout > 60 || requestTimeout == 0) requestTimeout = 60;
					if (requestTimeout < -60) requestTimeout = -60;
					timeout = requestTimeout;
					LOG_DBG << fname << "Use timeout :" << timeout;
					
				}
				else
				{
					LOG_DBG << fname << "Use default timeout :" << timeout;
				}
				// Parse env map
				std::map<std::string, std::string> envMap;
				auto jsonApp = message.extract_json(true).get();
				if (!jsonApp.is_null() && HAS_JSON_FIELD(jsonApp.as_object(), "env"))
				{
					auto jobj = jsonApp.as_object();
					auto env = jobj.at(GET_STRING_T("env")).as_object();
					for (auto it = env.begin(); it != env.end(); it++)
					{
						envMap[GET_STD_STRING((*it).first)] = GET_STD_STRING((*it).second.as_string());
					}
				}
				message.reply(status_codes::OK, Configuration::instance()->getApp(app)->testRun(timeout, envMap));
			}
			else
			{
				throw std::invalid_argument("No such path");
			}
		}
		else
		{
			throw std::invalid_argument("No such path");
		}
	}
	catch (const std::exception& e)
	{
		LOG_WAR << fname << e.what();
		message.reply(web::http::status_codes::InternalError, e.what());
	}
	catch (...)
	{
		LOG_WAR << fname << "unknown exception";
		message.reply(web::http::status_codes::InternalError, U("unknown exception"));
	}
}

void RestHandler::handle_put(http_request message)
{
	const static char fname[] = "RestHandler::handle_put() ";
	try
	{
		REST_INFO_PRINT;
		verifyAdminToken(message, getToken(message));

		auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
		if (path == "/app/sh")
		{
			this->registerShellApp(message);
		}
		else if (Utility::startWith(path, "/app/"))
		{
			auto jsonApp = message.extract_json(true).get();
			if (jsonApp.is_null())
			{
				throw std::invalid_argument("invalid json format");
			}
			auto app = Configuration::instance()->addApp(jsonApp.as_object());
			message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(app->AsJson(true).serialize())));
		}
		else
		{
			message.reply(status_codes::ServiceUnavailable, "No such path");
		}
	}
	catch (const std::exception& e)
	{
		LOG_WAR << fname << e.what();
		message.reply(web::http::status_codes::InternalError, e.what());
	}
	catch (...)
	{
		LOG_WAR << fname << "unknown exception";
		message.reply(web::http::status_codes::InternalError, U("unknown exception"));
	}
	return;
}

void RestHandler::handle_post(http_request message)
{
	const static char fname[] = "RestHandler::handle_post() ";

	try
	{
		REST_INFO_PRINT;

		auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));
		auto querymap = web::uri::split_query(web::http::uri::decode(message.relative_uri().query()));
		if (Utility::startWith(path, "/app/"))
		{
			verifyAdminToken(message, getToken(message));

			auto appName = path.substr(strlen("/app/"), path.length() - strlen("/app/"));

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
		else if (Utility::startWith(path, "/auth/"))
		{
			auto userName = path.substr(strlen("/auth/"), path.length() - strlen("/auth/"));
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
		else if (path == "/login")
		{
			if (message.headers().has("username") && message.headers().has("password"))
			{
				auto uname = Utility::decode64(GET_STD_STRING(message.headers().find("username")->second));
				auto passwd = Utility::decode64(GET_STD_STRING(message.headers().find("password")->second));
				auto token = createToken(uname, passwd);

				web::json::value result = web::json::value::object();
				web::json::value profile = web::json::value::object();
				profile[GET_STRING_T("name")] = web::json::value::string(uname);
				profile[GET_STRING_T("auth_time")] = web::json::value::number(std::chrono::system_clock::now().time_since_epoch().count());
				result[GET_STRING_T("profile")] = profile;
				result[GET_STRING_T("token_type")] = web::json::value::string("Bearer");
				result[GET_STRING_T("access_token")] = web::json::value::string(GET_STRING_T(token));

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
		else
		{
			message.reply(status_codes::ServiceUnavailable, "No such path");
		}
	}
	catch (const std::exception& e)
	{
		LOG_WAR << fname << e.what();
		message.reply(web::http::status_codes::InternalError, e.what());
	}
	catch (...)
	{
		LOG_WAR << fname << "unknown exception";
		message.reply(web::http::status_codes::InternalError, U("unknown exception"));
	}
}

void RestHandler::handle_delete(http_request message)
{
	const static char fname[] = "RestHandler::handle_delete() ";

	try
	{
		REST_INFO_PRINT;

		verifyAdminToken(message, getToken(message));
		auto path = GET_STD_STRING(message.relative_uri().path());
		
		if (Utility::startWith(path, "/app/"))
		{
			auto appName = path.substr(strlen("/app/"), path.length() - strlen("/app/"));

			Configuration::instance()->removeApp(appName);
			auto msg = std::string("application <") + appName + "> removed.";
			message.reply(status_codes::OK, msg);
		}
		else
		{
			message.reply(status_codes::ServiceUnavailable, "No such path");
		}
	}
	catch (const std::exception& e)
	{
		LOG_WAR << fname << e.what();
		message.reply(web::http::status_codes::InternalError, e.what());
	}
	catch (...)
	{
		LOG_WAR << fname << "unknown exception";
		message.reply(web::http::status_codes::InternalError, U("unknown exception"));
	}
	return;
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
		token = GET_STD_STRING(message.headers().find("Authorization")->second);
		std::string bearerFlag = "Bearer ";
		if (Utility::startWith(token, bearerFlag))
		{
			token = token.substr(bearerFlag.length());
		}
	}
	return std::move(token);
}

std::string RestHandler::createToken(const std::string uname, const std::string passwd)
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
		.set_expires_at(jwt::date(std::chrono::system_clock::now() + std::chrono::minutes{ 60 }))
		.set_payload_claim("name", std::string(uname))
		.sign(jwt::algorithm::hs256{ passwd });
	return std::move(token);
}

void RestHandler::registerShellApp(const http_request& message)
{
	auto jsonApp = message.extract_json(true).get();
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("invalid json format");
	}
	auto jobj = jsonApp.as_object();

	ERASE_JSON_FIELD(jobj, "run_once");
	jobj[GET_STRING_T("run_once")] = web::json::value::boolean(true);
	// /bin/sh -c "export A=b;export B=c;env | grep B"
	std::string shellCommandLine = "/bin/sh -c '";
	if (HAS_JSON_FIELD(jobj, "env"))
	{
		auto env = jobj.at(GET_STRING_T("env")).as_object();
		for (auto it = env.begin(); it != env.end(); it++)
		{
			std::string envCmd = std::string("export ") + GET_STD_STRING((*it).first) + "=" + GET_STD_STRING((*it).second.as_string()) + ";";
			shellCommandLine.append(envCmd);
		}
	}
	//ERASE_JSON_FIELD(jobj, "env");
	shellCommandLine.append(Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, "command_line")));
	shellCommandLine.append("'");
	jobj[GET_STRING_T("command_line")] = web::json::value::string(GET_STRING_T(shellCommandLine));

	auto app = Configuration::instance()->addApp(jobj);
	message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(app->AsJson(true).serialize())));
}

#include "RestHandler.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"
#include "../common/jwt-cpp/jwt.h"

#define REST_INFO_PRINT \
	LOG_DBG << "Method: " << message.method(); \
	LOG_DBG << "URI: " << http::uri::decode(message.relative_uri().path()); \
	LOG_DBG << "Query: " << http::uri::decode(message.relative_uri().query());
	//LOG_DBG << "Remote: " << message.remote_address(); // for new version of cpprestsdk

RestHandler::RestHandler(int port)
{
	const static char fname[] = "RestHandler::RestHandler() ";
	
	// Construct URI
	web::uri_builder uri;
	uri.set_host("0.0.0.0");
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

			ctx.set_options(boost::asio::ssl::context::default_workarounds, ec);
			LOG_INF << "lambda::set_options " << ec.value() << " " << ec.message();

			ctx.use_certificate_chain_file(Configuration::instance()->getSSLCertificateFile(), ec);
			LOG_INF << "lambda::use_certificate_chain_file " << ec.value() << " " << ec.message();

			ctx.use_private_key_file(Configuration::instance()->getSSLCertificateKeyFile(), boost::asio::ssl::context::pem, ec);
			LOG_INF << "lambda::use_private_key " << ec.value() << " " << ec.message();
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
		auto path = GET_STD_STRING(http::uri::decode(message.relative_uri().path()));

		if (path == std::string("/app-manager/applications"))
		{
			message.reply(status_codes::OK, Configuration::instance()->getApplicationJson());
		}
		if (path == std::string("/app-manager/resources"))
		{
			message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(ResourceCollection::instance()->AsJson().serialize())));
		}
		else if (path == "/app-manager/config")
		{
			message.reply(status_codes::OK, Configuration::prettyJson(GET_STD_STRING(Configuration::instance()->getConfigContentStr())));
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
				const int maxTimeout = 100; // set max timeout to 100s
				if (querymap.find(U("timeout")) != querymap.end())
				{
					// max than 1 and less than 100
					auto requestTimeout = std::max(std::stoi(GET_STD_STRING(querymap.find(U("timeout"))->second)), 1);
					timeout = std::min(requestTimeout, maxTimeout);
					LOG_DBG << fname << "Use timeout :" << timeout;
				}
				else
				{
					LOG_DBG << fname << "Use default timeout :" << timeout;
				}
				message.reply(status_codes::OK, Configuration::instance()->getApp(app)->testRun(timeout));
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
		message.reply(web::http::status_codes::InternalError, e.what());
	}
	catch (...)
	{
		message.reply(web::http::status_codes::InternalError, U("unknown exception"));
	}
}

void RestHandler::handle_put(http_request message)
{
	try
	{
		REST_INFO_PRINT;
		checkToken(getToken(message));

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
		message.reply(web::http::status_codes::InternalError, e.what());
	}
	catch (...)
	{
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
			checkToken(getToken(message));

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
		else if (path == "/login")
		{
			if (message.headers().has("username") && message.headers().has("password"))
			{
				auto uname = GET_STD_STRING(message.headers().find("username")->second);
				auto passwd = GET_STD_STRING(message.headers().find("password")->second);
				if (passwd != JWT_ADMIN_KEY || uname != JWT_ADMIN_NAME)
				{
					message.reply(status_codes::Unauthorized, "Incorrect authentication info");
				}
				else
				{
					// https://thalhammer.it/projects/jwt_cpp
					// 1. Header
					//{
					//	"typ": "JWT",
					//  "alg" : "HS256"
					//}

					// 2. Payload
					//{
					//  "iss": "appmgr-auth0",
					//	"name" : "u-name",
					//}

					// 3. Signature
					// HMACSHA256((base64UrlEncode(header) + "." + base64UrlEncode(payload)), 'secret');
					auto token = jwt::create()
						.set_issuer(JWT_ISSUER)
						.set_type("JWT")
						.set_payload_claim("name", std::string(JWT_ADMIN_NAME))
						.sign(jwt::algorithm::hs256{ JWT_ADMIN_KEY });

					//web::json::value result = web::json::value::object();
					//result[GET_STRING_T("code")] = web::json::value::number(0);
					//result[GET_STRING_T("msg")] = web::json::value::string("success");
					//result[GET_STRING_T("token")] = web::json::value::string(GET_STRING_T(token));
					message.reply(status_codes::OK, token);
					LOG_DBG << fname << "User <" << uname << "> login success";
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
		message.reply(web::http::status_codes::InternalError, e.what());
	}
	catch (...)
	{
		message.reply(web::http::status_codes::InternalError, U("unknown exception"));
	}
}

void RestHandler::handle_delete(http_request message)
{
	try
	{
		REST_INFO_PRINT;

		checkToken(getToken(message));
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
		message.reply(web::http::status_codes::InternalError, e.what());
	}
	catch (...)
	{
		message.reply(web::http::status_codes::InternalError, U("unknown exception"));
	}
	return;
}

void RestHandler::handle_error(pplx::task<void>& t)
{
	const static char fname[] = "Configuration::handle_error() ";

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


bool RestHandler::checkToken(const std::string& token)
{
	const static char fname[] = "Configuration::checkToken() ";

	auto decoded_token = jwt::decode(token);
	for (auto& e : decoded_token.get_payload_claims())
	{
		LOG_DBG << fname << e.first << " = " << e.second.as_string();
	}
	auto verifier = jwt::verify()
		.allow_algorithm(jwt::algorithm::hs256{ JWT_PASSWD })
		.with_issuer(JWT_ISSUER)
		.with_claim("name", std::string(JWT_UNAME));
	verifier.verify(decoded_token);
	return true;
}

std::string RestHandler::getToken(const http_request& message)
{
	std::string token;
	if (message.headers().has("token"))
	{
		token = GET_STD_STRING(message.headers().find("token")->second);
		//token = Utility::decode64(token);
	}
	else
	{
		throw std::invalid_argument("Access denied:must have token.");
	}
	return token;
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

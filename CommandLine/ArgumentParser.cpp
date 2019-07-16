#include <iostream>
#include <thread>
#include <functional>
#include <boost/program_options.hpp>
#include <cpprest/json.h>
#include "ArgumentParser.h"
#include "../common/Utility.h"

#define OPTION_HOST_NAME ("host,b", po::value<std::string>()->default_value("localhost"), "host name or ip address")
#define HELP_ARG_CHECK_WITH_RETURN if (m_commandLineVariables.count("help") > 0) { std::cout << desc << std::endl; return; } m_hostname = m_commandLineVariables["host"].as<std::string>();
#define RESPONSE_CHECK_WITH_RETURN if (response.status_code() != status_codes::OK) { std::cout << response.extract_utf8string(true).get() << std::endl; return; }
#define RESPONSE_CHECK_WITH_RETURN_NO_DEBUGPRINT if (response.status_code() != status_codes::OK) { return; }
#define OUTPUT_SPLITOR_PRINT std::cout << "--------------------------------------------------------" << std::endl;

ArgumentParser::ArgumentParser(int argc, const char* argv[], int listenPort, bool sslEnabled, bool printDebug)
	:m_listenPort(listenPort), m_sslEnabled(sslEnabled), m_printDebug(printDebug)
{
	po::options_description global("Global options");
	global.add_options()
		("help,h", "help message")
		("command", po::value<std::string>(), "command to execute")
		("subargs", po::value<std::vector<std::string> >(), "arguments for command");

	po::positional_options_description pos;
	pos.add("command", 1).
		add("subargs", -1);

	auto parsed = po::command_line_parser(argc, argv).options(global).positional(pos).allow_unregistered().run();
	m_pasrsedOptions = parsed.options;
	po::store(parsed, m_commandLineVariables);
	po::notify(m_commandLineVariables);
}


ArgumentParser::~ArgumentParser()
{
}

void ArgumentParser::parse()
{
	if (m_commandLineVariables.count("help") || m_commandLineVariables.size() == 0 || m_commandLineVariables.count("command") == 0)
	{
		printMainHelp();
		return;
	}
	
	
	std::string cmd = m_commandLineVariables["command"].as<std::string>();
	if (cmd == "reg")
	{
		// PUT /app/$app-name
		processReg();
	}
	else if (cmd == "unreg")
	{
		// DELETE /app/$app-name
		processUnReg();
	}
	else if (cmd == "view")
	{
		// GET /app/$app-name
		// GET /app-manager/applications
		processView();
	}
	else if (cmd == "resource")
	{
		// GET /app-manager/resources
		processResource();
	}
	else if (cmd == "config")
	{
		// GET /app-manager/config
		processConfig();
	}
	else if (cmd == "start")
	{
		// POST /app/$app-name?action=start
		processStartStop(true);
	}
	else if (cmd == "stop")
	{
		// POST /app/$app-name?action=stop
		processStartStop(false);
	}
	else if(cmd == "restart")
	{
		auto tmpOpts = m_pasrsedOptions;
		processStartStop(false);
		m_pasrsedOptions = tmpOpts;
		processStartStop(true);
	}
	else if (cmd == "test")
	{
		// GET /app/$app-name/output
		processTest();
	}
	else if (cmd == "sh")
	{
		processShell();
	}
	else
	{
		printMainHelp();
	}
}

void ArgumentParser::printMainHelp()
{
	std::cout << "Commands:" << std::endl;
	std::cout << "  view        List application[s]" << std::endl;
	std::cout << "  config      Display configurations" << std::endl;
	std::cout << "  resource    Display host resource usage" << std::endl;
	std::cout << "  start       Start a application" << std::endl;
	std::cout << "  stop        Stop a application" << std::endl;
	std::cout << "  restart     Restart a application" << std::endl;
	std::cout << "  reg         Add a new application" << std::endl;
	std::cout << "  unreg       Remove an application" << std::endl;
	std::cout << "  test        Test run an application and get output" << std::endl;
	std::cout << "  sh          Use shell run a command and get output" << std::endl;

	std::cout << std::endl;
	std::cout << "Run 'appc COMMAND --help' for more information on a command." << std::endl;
	std::cout << "Use '-b hostname' to run remote command." << std::endl;

	std::cout << std::endl;
	std::cout << "Usage:  appc [COMMAND] [ARG...] [flags]" << std::endl;
}

void ArgumentParser::processReg(const char* appName)
{
	po::options_description desc("Register a new application");
	desc.add_options()
		OPTION_HOST_NAME
		("name,n", po::value<std::string>(), "application name")
		("user,u", po::value<std::string>()->default_value("root"), "application process running user name")
		("cmd,c", po::value<std::string>(), "full command line with arguments")
		("workdir,w", po::value<std::string>()->default_value("/tmp"), "working directory")
		("status,a", po::value<bool>()->default_value(true), "application status status (start is true, stop is false)")
		("start_time,t", po::value<std::string>(), "start date time for short running app (e.g., '2018-01-01 09:00:00')")
		("daily_start,s", po::value<std::string>(), "daily start time (e.g., '09:00:00')")
		("daily_end,d", po::value<std::string>(), "daily end time (e.g., '20:00:00')")
		("memory,m", po::value<int>(), "memory limit in MByte")
		("virtual_memory,v", po::value<int>(), "virtual memory limit in MByte")
		("cpu_shares,p", po::value<int>(), "CPU shares (relative weight)")
		("env,e", po::value<std::vector<std::string>>(), "environment variables (e.g., -e env1=value1 -e env2=value2)")
		("interval,i", po::value<int>(), "start interval seconds for short running app")
		("extra_time,x", po::value<int>(), "extra timeout for short running app,the value must less than interval  (default 0)")
		("timezone,z", po::value<std::string>(), "posix timezone for the application, reflect [start_time|daily_start|daily_end] (e.g., 'WST+08:00' is Australia Standard Time)")
		("keep_running,k", po::value<bool>()->default_value(false), "monitor and keep running for short running app in start interval")
		("force,f", "force without confirm")
		("debug,g", "print debug information")
		("help,h", "help message");

	moveForwardCommandLineVariables(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	if (
		(nullptr == appName && m_commandLineVariables.count("name") == 0)
		|| m_commandLineVariables.count("user") == 0
		|| m_commandLineVariables.count("cmd") == 0
		|| m_commandLineVariables.count("workdir") == 0
		)
	{
		std::cout << desc << std::endl;
		return;
	}

	if (m_commandLineVariables.count("interval") > 0 && m_commandLineVariables.count("extra_time") >0)
	{
		if (m_commandLineVariables["interval"].as<int>() <= m_commandLineVariables["extra_time"].as<int>())
		{
			std::cout << "The extra_time seconds must less than interval." << std::endl;
			return;
		}
	}
	// Shell app does not need check app existance
	if (nullptr == appName && isAppExist(m_commandLineVariables["name"].as<std::string>()))
	{
		if (m_commandLineVariables.count("force") == 0)
		{
			if (!confirmInput("Application already exist, are you sure you want to update the application? [y/n]"))
			{
				return;
			}
		}
	}
	web::json::value jsobObj;
	jsobObj["name"] = appName == nullptr ? web::json::value::string(m_commandLineVariables["name"].as<std::string>()) : web::json::value::string(appName);
	jsobObj["command_line"] = web::json::value::string(m_commandLineVariables["cmd"].as<std::string>());
	jsobObj["run_as"] = web::json::value::string(m_commandLineVariables["user"].as<std::string>());
	jsobObj["working_dir"] = web::json::value::string(m_commandLineVariables["workdir"].as<std::string>());
	jsobObj["status"] = web::json::value::number(m_commandLineVariables["status"].as<bool>() ? 1 : 0);
	if (m_commandLineVariables.count("timezone") > 0)
	{
		jsobObj["posix_timezone"] = web::json::value::string(m_commandLineVariables["timezone"].as<std::string>());
	}
	if (m_commandLineVariables.count("start_time") > 0)
	{
		jsobObj["start_time"] = web::json::value::string(m_commandLineVariables["start_time"].as<std::string>());
	}
	if (m_commandLineVariables.count("interval") > 0)
	{
		jsobObj["start_interval_seconds"] = web::json::value::number(m_commandLineVariables["interval"].as<int>());
	}

	if (m_commandLineVariables.count("extra_time") > 0)
	{
		jsobObj["start_interval_timeout"] = web::json::value::number(m_commandLineVariables["extra_time"].as<int>());
	}

	if (m_commandLineVariables.count("keep_running"))
	{
		jsobObj["keep_running"] = web::json::value::boolean(m_commandLineVariables["keep_running"].as<bool>());
	}

	if (m_commandLineVariables.count("daily_start") && m_commandLineVariables.count("daily_end"))
	{
		web::json::value objDailyLimitation = web::json::value::object();
		objDailyLimitation["daily_start"] = web::json::value::string(m_commandLineVariables["daily_start"].as<std::string>());
		objDailyLimitation["daily_end"] = web::json::value::string(m_commandLineVariables["daily_end"].as<std::string>());
		jsobObj["daily_limitation"] = objDailyLimitation;
	}

	if (m_commandLineVariables.count("memory") || m_commandLineVariables.count("virtual_memory") ||
		m_commandLineVariables.count("cpu_shares"))
	{
		web::json::value objResourceLimitation = web::json::value::object();
		if (m_commandLineVariables.count("memory")) objResourceLimitation["memory_mb"] = web::json::value::number(m_commandLineVariables["memory"].as<int>());
		if (m_commandLineVariables.count("virtual_memory")) objResourceLimitation["memory_virt_mb"] = web::json::value::number(m_commandLineVariables["virtual_memory"].as<int>());
		if (m_commandLineVariables.count("cpu_shares")) objResourceLimitation["cpu_shares"] = web::json::value::number(m_commandLineVariables["cpu_shares"].as<int>());
		jsobObj["resource_limit"] = objResourceLimitation;
	}


	if (m_commandLineVariables.count("env"))
	{
		std::vector<std::string> envs = m_commandLineVariables["env"].as<std::vector<std::string>>();
		if (envs.size())
		{
			web::json::value objEnvs = web::json::value::object();
			std::for_each(envs.begin(), envs.end(), [&objEnvs](std::string env)
			{
				std::vector<std::string> envVec = Utility::splitString(env, "=");
				if (envVec.size() == 2)
				{
					objEnvs[GET_STRING_T(envVec.at(0))] = web::json::value::string(GET_STRING_T(envVec.at(1)));
				}
			});
			jsobObj["env"] = objEnvs;
		}
	}

	std::string restPath;
	if (nullptr	== appName)
	{
		// Normal app
		restPath = std::string("/app/") + m_commandLineVariables["name"].as<std::string>();
	}
	else
	{
		// Shell app
		restPath = std::string("/app/sh");
	}
	auto response = requestHttp(methods::PUT, restPath, jsobObj);
	RESPONSE_CHECK_WITH_RETURN;
	auto appJsonStr = response.extract_utf8string(true).get();
	if (m_printDebug) std::cout << GET_STD_STRING(appJsonStr) << std::endl;
}

void ArgumentParser::processUnReg()
{
	po::options_description desc("Unregister and remove an application");
	desc.add_options()
		("help,h", "help message")
		OPTION_HOST_NAME
		("name,n", po::value<std::vector<std::string>>(), "remove application by name")
		("force,f", "force without confirm.");

	moveForwardCommandLineVariables(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count("name") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	auto appNames = m_commandLineVariables["name"].as<std::vector<std::string>>();
	for (auto appName : appNames)
	{
		if (isAppExist(appName))
		{
			if (m_commandLineVariables.count("force") == 0)
			{
				std::string msg = std::string("Are you sure you want to remove the application <") + appName + "> ? [y/n]";
				if (!confirmInput(msg.c_str()))
				{
					return;
				}
			}
			std::string restPath = std::string("/app/") + appName;
			auto response = requestHttp(methods::DEL, restPath);
			RESPONSE_CHECK_WITH_RETURN;
			if (m_printDebug) std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
		}
		else
		{
			throw std::invalid_argument(std::string("no such application : ") + appName);
		}
	}
}

void ArgumentParser::processView()
{
	po::options_description desc("List application[s]");
	desc.add_options()
		("help,h", "help message")
		OPTION_HOST_NAME
		("name,n", po::value<std::string>(), "view application by name.")
		("long,l", "display the complete information without reduce")
		;
	
	moveForwardCommandLineVariables(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	bool reduce = !(m_commandLineVariables.count("long"));
	if (m_commandLineVariables.count("name") > 0)
	{
		std::string restPath = std::string("/app/") + m_commandLineVariables["name"].as<std::string>();
		auto response = requestHttp(methods::GET, restPath);
		RESPONSE_CHECK_WITH_RETURN;
		auto arr = web::json::value::array(1);
		arr[0] = response.extract_json(true).get();
		printApps(arr, reduce);
	}
	else
	{
		std::string restPath = "/app-manager/applications";
		auto response = requestHttp(methods::GET, restPath);
		RESPONSE_CHECK_WITH_RETURN;
		printApps(response.extract_json(true).get(), reduce);
	}
}

void ArgumentParser::processResource()
{
	po::options_description desc("View host resource usage:");
	desc.add_options()
		OPTION_HOST_NAME
		("help,h", "help message")
		;
	moveForwardCommandLineVariables(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/app-manager/resources";
	auto bodyStr = requestHttp(methods::GET, restPath).extract_utf8string(true).get();
	std::cout << GET_STD_STRING(bodyStr) << std::endl;
}

void ArgumentParser::processConfig()
{
	po::options_description desc("View configuration:");
	desc.add_options()
		OPTION_HOST_NAME
		("help,h", "help message")
		;
	moveForwardCommandLineVariables(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/app-manager/config";
	auto bodyStr = requestHttp(methods::GET, restPath).extract_utf8string(true).get();
	std::cout << GET_STD_STRING(bodyStr) << std::endl;
}

void ArgumentParser::processStartStop(bool start)
{
	po::options_description desc("Start application:");
	desc.add_options()
		("help,h", "help message")
		OPTION_HOST_NAME
		("all,a", "action for all applications")
		("name,n", po::value<std::vector<std::string>>(), "start/stop application by name.")
		;
	
	moveForwardCommandLineVariables(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	if (m_commandLineVariables.empty()) 
	{
		std::cout << desc << std::endl;
		return;
	}
	std::vector<std::string> appList;
	bool all = m_commandLineVariables.count("all");
	if (all)
	{
		auto appMap = this->getAppList();
		std::for_each(appMap.begin(), appMap.end(), [&appList, &start](const std::pair<std::string, bool>& pair)
		{
			if (start != pair.second)
			{
				appList.push_back(pair.first);
			}
		});
	}
	else
	{
		auto appNames = m_commandLineVariables["name"].as<std::vector<std::string>>();
		for (auto appName : appNames)
		{
			if (!isAppExist(appName))
			{
				throw std::invalid_argument("no such application");
			}
			appList.push_back(appName);
		}
	}
	for (auto app : appList)
	{
		std::map<std::string, std::string> query;
		query["action"] = start ? "start" : "stop";
		std::string restPath = std::string("/app/") + app;
		auto response = requestHttp(methods::POST, restPath, query);
		std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
	}
	if (appList.size() == 0)
	{
		std::cout << "No application processed." << std::endl;
	}
}

void ArgumentParser::processTest()
{
	po::options_description desc("Run application:");
	desc.add_options()
		("help,h", "help message")
		OPTION_HOST_NAME
		("name,n", po::value<std::string>(), "test run application by name.")
		("timeout,t", po::value<int>()->default_value(60), "timeout seconds for the test run (default 60).")
		;

	moveForwardCommandLineVariables(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	if (m_commandLineVariables.count("name") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}
	if (!isAppExist(m_commandLineVariables["name"].as<std::string>()))
	{
		throw std::invalid_argument("no such application");
	}

	std::map<std::string, std::string> query;
	if (m_commandLineVariables.count("timeout") > 0)
	{
		query["timeout"] = std::to_string(m_commandLineVariables["timeout"].as<int>());
	}
	auto appName = m_commandLineVariables["name"].as<std::string>();
	// /app/testapp/testrun?timeout=5
	std::string restPath = std::string("/app/").append(appName).append("/testrun");
	auto response = requestHttp(methods::GET, restPath, query);
	RESPONSE_CHECK_WITH_RETURN;

	auto process_uuid = GET_STD_STRING(response.extract_utf8string(true).get());
	while (process_uuid.length())
	{
		// /app/testapp/testrun/output?process_uuid=ABDJDD-DJKSJDKF
		restPath = std::string("/app/").append(appName).append("/testrun/output");
		query.clear();
		query["process_uuid"] = process_uuid;
		response = requestHttp(methods::GET, restPath, query);
		if (m_printDebug)
		{
			RESPONSE_CHECK_WITH_RETURN;
		}
		else
		{
			RESPONSE_CHECK_WITH_RETURN_NO_DEBUGPRINT;
		}
		std::cout << GET_STD_STRING(response.extract_utf8string(true).get());
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void ArgumentParser::processShell()
{
	po::options_description desc("Shell application:");
	desc.add_options()
		("help,h", "help message")
		OPTION_HOST_NAME
		("user,u", po::value<std::string>()->default_value("root"), "application process running user name")
		("cmd,c", po::value<std::string>(), "full command line with arguments")
		("debug,g", "print debug information")
		("env,e", po::value<std::vector<std::string>>(), "environment variables (e.g., -e env1=value1 -e env2=value2)")
		("timeout,x", po::value<int>()->default_value(60), "timeout seconds for the shell command run (default 60).")
		;
	m_commandLineVariables.clear();
	std::vector<std::string> opts = po::collect_unrecognized(m_pasrsedOptions, po::include_positional);
	po::store(po::command_line_parser(opts).options(desc).run(), m_commandLineVariables);
	po::notify(m_commandLineVariables);

	if (m_commandLineVariables.count("cmd") == 0 || m_commandLineVariables.count("help"))
	{
		std::cout << desc << std::endl;
		return;
	}
	m_printDebug = m_commandLineVariables.count("debug");
	m_hostname = m_commandLineVariables["host"].as<std::string>();
	// Use uuid for shell app to avoid overide existing app
	auto appName = Utility::createUUID();

	if (m_printDebug) OUTPUT_SPLITOR_PRINT;

	// 1. Reg a temp application
	// PUT /app/sh
	processReg(appName.c_str());

	if (m_printDebug) OUTPUT_SPLITOR_PRINT;

	// 2. Call testrun and check output
	if (m_commandLineVariables.count("extra_time"))
	{
		const char* argv[] = { "appc" , "test", "-b", strdup(m_hostname.c_str()), "-n", strdup(appName.c_str()), "-t",  
			strdup(std::to_string(m_commandLineVariables["extra_time"].as<int>()).c_str()), "\0" };
		ArgumentParser testParser(ARRAY_LEN(argv), argv, m_listenPort, m_sslEnabled, m_printDebug);
		testParser.parse();
	}
	else
	{
		const char* argv[] = { "appc" , "test", "-b", strdup(m_hostname.c_str()), "-n", strdup(appName.c_str()), "\0" };
		ArgumentParser testParser(ARRAY_LEN(argv), argv, m_listenPort, m_sslEnabled, m_printDebug);
		testParser.parse();
	}

	if (m_printDebug) OUTPUT_SPLITOR_PRINT;

	// 3. Unregist application
	const char* argv[] = { "appc" , "unreg", "-b", strdup(m_hostname.c_str()), "-n", strdup(appName.c_str()), "-f", "\0" };
	ArgumentParser unregParser(ARRAY_LEN(argv), argv, m_listenPort, m_sslEnabled, m_printDebug);
	unregParser.parse();

	if (m_printDebug) OUTPUT_SPLITOR_PRINT;
}

bool ArgumentParser::confirmInput(const char* msg)
{
	std::cout << msg << ":";
	std::string result;
	std::cin >> result;
	return result == "y";
}

http_response ArgumentParser::requestHttp(const method & mtd, const std::string& path)
{
	std::map<std::string, std::string> query;
	return std::move(requestHttp(mtd, path, query));
}

http_response ArgumentParser::requestHttp(const method & mtd, const std::string& path, web::json::value & body)
{
	std::map<std::string, std::string> query;
	return std::move(requestHttp(mtd, path, query, &body));
}

http_response ArgumentParser::requestHttp(const method & mtd, const std::string& path, std::map<std::string, std::string>& query, web::json::value * body)
{
	auto protocol = m_sslEnabled ? U("https://") : U("http://");
	// Create http_client to send the request.
	auto restPath = (protocol + GET_STRING_T(m_hostname) + ":" + GET_STRING_T(std::to_string(m_listenPort)));
	http_client_config config;
	config.set_validate_certificates(false);
	http_client client(restPath, config);
	// Build request URI and start the request.
	uri_builder builder(GET_STRING_T(path));
	std::for_each(query.begin(), query.end(), [&builder](const std::pair<std::string, std::string>& pair)
	{
		builder.append_query(GET_STRING_T(pair.first), GET_STRING_T(pair.second));
	});
	
	http_request request(mtd);
	addAuthenToken(request);
	request.set_request_uri(builder.to_uri());
	if (body != nullptr)
	{
		request.set_body(*body);
	}
	http_response response = client.request(request).get();
	return std::move(response);
}

bool ArgumentParser::isAppExist(const std::string& appName)
{
	static auto apps = getAppList();
	return apps.find(appName) != apps.end();
}

std::map<std::string, bool> ArgumentParser::getAppList()
{
	std::map<std::string, bool> apps;
	auto jsonValue = requestHttp(methods::GET, "/app-manager/applications").extract_json(true).get();
	auto arr = jsonValue.as_array();
	for (auto iter = arr.begin(); iter != arr.end(); iter++)
	{
		auto jobj = iter->as_object();
		apps[GET_JSON_STR_VALUE(jobj, "name")] = GET_JSON_INT_VALUE(jobj, "status") == 1;
	}
	return apps;
}

void ArgumentParser::addAuthenToken(http_request & request)
{
	static std::string jwtToken;
	if (jwtToken.empty())
	{
		auto protocol = m_sslEnabled ? U("https://") : U("http://");
		auto restPath = (protocol + GET_STRING_T(m_hostname) + ":" + GET_STRING_T(std::to_string(m_listenPort)));
		http_client_config config;
		config.set_validate_certificates(false);
		http_client client(restPath, config);
		http_request requestLogin(web::http::methods::POST);
		uri_builder builder(GET_STRING_T("/authenticate"));
		requestLogin.set_request_uri(builder.to_uri());
		requestLogin.headers().add("username", JWT_ADMIN_NAME);
		requestLogin.headers().add("password", JWT_ADMIN_KEY);
		http_response response = client.request(requestLogin).get();
		if (response.status_code() != status_codes::OK)
		{
			std::cout << "login failed : " << response.extract_utf8string(true).get();
		}
		else
		{
			auto jwtContent = response.extract_json(true).get();
			jwtToken = GET_JSON_STR_VALUE(jwtContent.as_object(), "access_token");
		}
	}
	request.headers().add("Authorization", std::string("Bearer ") + jwtToken);
}

void ArgumentParser::printApps(web::json::value json, bool reduce)
{
	// Title:
	std::cout << std::left;
	std::cout
		<< std::setw(3) << ("id")
		<< std::setw(12) << ("name")
		<< std::setw(6) << ("user")
		<< std::setw(9) << ("status")
		<< std::setw(7) << ("pid")
		<< std::setw(7) << ("return")
		<< std::setw(8) << ("memory")
		<< ("command_line")
		<< std::endl;

	int index = 1;
	auto jsonArr = json.as_array();
	auto reduceFunc = std::bind(&ArgumentParser::reduceStr, this, std::placeholders::_1, std::placeholders::_2);
	std::for_each(jsonArr.begin(), jsonArr.end(), [&index, &reduceFunc, reduce](web::json::value &x) {
		auto jobj = x.as_object();
		auto name = GET_JSON_STR_VALUE(jobj, "name");
		if (reduce) name = reduceFunc(name, 12);
		else if (name.length() >= 12) name += " ";
		std::cout << std::setw(3) << index++;
		std::cout << std::setw(12) << name;
		std::cout << std::setw(6) << reduceFunc(GET_JSON_STR_VALUE(jobj, "run_as"), 6);
		std::cout << std::setw(9) << GET_STATUS_STR(GET_JSON_INT_VALUE(jobj, "status"));
		std::cout << std::setw(7) << (GET_JSON_INT_VALUE(jobj, "pid") > 0 ? GET_JSON_INT_VALUE(jobj, "pid") : 0);
		std::cout << std::setw(7) << GET_JSON_INT_VALUE(jobj, "return");
		std::cout << std::setw(8) << Utility::humanReadableSize(GET_JSON_INT_VALUE(jobj, "memory"));
		std::cout << GET_JSON_STR_VALUE(jobj, "command_line");

		std::cout << std::endl;
	});
}

void ArgumentParser::moveForwardCommandLineVariables(po::options_description& desc)
{
	m_commandLineVariables.clear();
	std::vector<std::string> opts = po::collect_unrecognized(m_pasrsedOptions, po::include_positional);
	opts.erase(opts.begin());
	po::store(po::command_line_parser(opts).options(desc).run(), m_commandLineVariables);
	po::notify(m_commandLineVariables);
}

std::string ArgumentParser::reduceStr(std::string source, int limit)
{
	if (source.length() >= (size_t)limit)
	{
		return std::move(source.substr(0, limit - 2).append("*"));
	}
	else
	{
		return source;
	}
}


#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
#include <iostream>
#include <thread>
#include <chrono>
#include <functional>
#include <boost/program_options.hpp>
#include <cpprest/filestream.h>
#include <cpprest/json.h>
#include "ArgumentParser.h"
#include "../common/Utility.h"
#include "../common/os/linux.hpp"
#include "../common/os/chown.hpp"

#define OPTION_HOST_NAME ("host,b", po::value<std::string>()->default_value("localhost"), "host name or ip address")
#define HELP_ARG_CHECK_WITH_RETURN if (m_commandLineVariables.count("help") > 0) { std::cout << desc << std::endl; return; } m_hostname = m_commandLineVariables["host"].as<std::string>();

// Each user should have its own token path
const static std::string m_tokenFilePrefix = std::string(getenv("HOME") ? getenv("HOME") : ".") + "/._appmgr_";
static std::string m_jwtToken;

ArgumentParser::ArgumentParser(int argc, const char* argv[], int listenPort, bool sslEnabled)
	:m_listenPort(listenPort), m_sslEnabled(sslEnabled), m_tokenTimeoutSeconds(0)
	, m_username(JWT_USER_NAME), m_userpwd(JWT_USER_KEY)
{
	po::options_description global("Global options");
	global.add_options()
		("command", po::value<std::string>(), "command to execute")
		("subargs", po::value<std::vector<std::string> >(), "arguments for command");

	po::positional_options_description pos;
	pos.add("command", 1).
		add("subargs", -1);

	// parse [command] and all other arguments in [subargs]
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
	if (m_commandLineVariables.size() == 0)
	{
		printMainHelp();
		return;
	}


	std::string cmd = m_commandLineVariables["command"].as<std::string>();
	if (cmd == "logon")
	{
		processLogon();
	}
	else if (cmd == "logoff")
	{
		processLogoff();
	}
	else if (cmd == "reg")
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
	else if (cmd == "enable")
	{
		// POST /app/$app-name/enable
		processEnableDisable(true);
	}
	else if (cmd == "disable")
	{
		// POST /app/$app-name/disable
		processEnableDisable(false);
	}
	else if (cmd == "restart")
	{
		auto tmpOpts = m_pasrsedOptions;
		processEnableDisable(false);
		m_pasrsedOptions = tmpOpts;
		processEnableDisable(true);
	}
	else if (cmd == "run")
	{
		processRun();
	}
	else if (cmd == "get")
	{
		processDownload();
	}
	else if (cmd == "put")
	{
		processUpload();
	}
	else if (cmd == "label")
	{
		processTags();
	}
	else if (cmd == "log")
	{
		processLoglevel();
	}
	else if (cmd == "config")
	{
		processConfigView();
	}
	else if (cmd == "passwd")
	{
		processChangePwd();
	}
	else if (cmd == "lock")
	{
		processLockUser();
	}
	else
	{
		printMainHelp();
	}
}

void ArgumentParser::printMainHelp()
{
	std::cout << "Commands:" << std::endl;
	std::cout << "  logon       Log on to AppManager for a specific time period." << std::endl;
	std::cout << "  logoff      End a AppManager user session" << std::endl;

	std::cout << "  view        List application[s]" << std::endl;
	std::cout << "  resource    Display host resource usage" << std::endl;
	std::cout << "  label       Manage host labels" << std::endl;
	std::cout << "  enable      Enable a application" << std::endl;
	std::cout << "  disable     Disable a application" << std::endl;
	std::cout << "  restart     Restart a application" << std::endl;
	std::cout << "  reg         Add a new application" << std::endl;
	std::cout << "  unreg       Remove an application" << std::endl;
	std::cout << "  run         Run application and get output" << std::endl;
	std::cout << "  get         Download remote file to local" << std::endl;
	std::cout << "  put         Upload file to server" << std::endl;
	std::cout << "  config      Manage basic configurations" << std::endl;
	std::cout << "  passwd      Change user password" << std::endl;
	std::cout << "  lock        Lock unlock a user" << std::endl;
	std::cout << "  log         Set log level" << std::endl;

	std::cout << std::endl;
	std::cout << "Run 'appc COMMAND --help' for more information on a command." << std::endl;
	std::cout << "Use '-b hostname' to run remote command." << std::endl;

	std::cout << std::endl;
	std::cout << "Usage:  appc [COMMAND] [ARG...] [flags]" << std::endl;
}

void ArgumentParser::processLogon()
{
	po::options_description desc("Log on to AppManager:");
	desc.add_options()
		OPTION_HOST_NAME
		("user,u", po::value<std::string>(), "Specifies the name of the user to connect to AppManager for this command.")
		("password,x", po::value<std::string>(), "Specifies the user password to connect to AppManager for this command.")
		("timeout,t", po::value<int>()->default_value(DEFAULT_TOKEN_EXPIRE_SECONDS), "Specifies the command session duration in minutes.")
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	m_tokenTimeoutSeconds = m_commandLineVariables["timeout"].as<int>();
	if (m_commandLineVariables.count("user"))
	{
		m_username = m_commandLineVariables["user"].as<std::string>();
	}
	else
	{
		std::cout << "User: ";
		std::cin >> m_username;
	}

	if (m_commandLineVariables.count("password"))
	{
		m_userpwd = m_commandLineVariables["password"].as<std::string>();
	}
	else
	{
		if (!m_commandLineVariables.count("user"))
		{
			std::cin.clear();
			std::cin.ignore(1024, '\n');
		}
		std::cout << "Password: ";
		char buffer[256] = { 0 };
		char* str = buffer;
		FILE* fp = stdin;
		inputSecurePasswd(&str, sizeof(buffer), '*', fp);
		m_userpwd = buffer;
		std::cout << std::endl;
	}

	std::string tokenFile = std::string(m_tokenFilePrefix) + m_hostname;
	// clear token first
	if (Utility::isFileExist(tokenFile))
	{

		std::ofstream ofs(tokenFile, std::ios::trunc);
		ofs.close();
	}
	// get token from REST
	m_jwtToken = getAuthenToken();

	// write token to disk
	if (m_jwtToken.length())
	{
		std::ofstream ofs(tokenFile, std::ios::trunc);
		if (ofs.is_open())
		{
			ofs << m_jwtToken;
			ofs.close();
			std::cout << "User <" << m_username << "> logon to " << m_hostname << " success." << std::endl;
		}
		else
		{
			std::cout << "Failed to open token file " << tokenFile << std::endl;
		}
	}
}

void ArgumentParser::processLogoff()
{
	po::options_description desc("Log off to AppManager:");
	desc.add_options()
		OPTION_HOST_NAME
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string tokenFile = std::string(m_tokenFilePrefix) + m_hostname;
	if (Utility::isFileExist(tokenFile))
	{
		std::ofstream ofs(tokenFile, std::ios::trunc);
		ofs.close();
	}
	std::cout << "User <" << m_username << "> logoff from " << m_hostname << " success." << std::endl;
}

// appName is null means this is a normal application (not a shell application)
void ArgumentParser::processReg()
{
	po::options_description desc("Register a new application");
	desc.add_options()
		OPTION_HOST_NAME
		("name,n", po::value<std::string>(), "application name")
		("comments,g", po::value<std::string>(), "application comments")
		("user,u", po::value<std::string>()->default_value("root"), "application process running user name")
		("cmd,c", po::value<std::string>(), "full command line with arguments")
		("health_check,l", po::value<std::string>(), "health check script command (e.g., sh -x 'curl host:port/health', return 0 is health)")
		("docker_image,d", po::value<std::string>(), "docker image which used to run command line (this will enable docker)")
		("workdir,w", po::value<std::string>()->default_value("/tmp"), "working directory")
		("status,a", po::value<bool>()->default_value(true), "application status status (start is true, stop is false)")
		("start_time,t", po::value<std::string>(), "start date time for short running app (e.g., '2018-01-01 09:00:00')")
		("daily_start,s", po::value<std::string>(), "daily start time (e.g., '09:00:00')")
		("daily_end,y", po::value<std::string>(), "daily end time (e.g., '20:00:00')")
		("memory,m", po::value<int>(), "memory limit in MByte")
		("pid,p", po::value<int>(), "process id used to attach")
		("virtual_memory,v", po::value<int>(), "virtual memory limit in MByte")
		("cpu_shares,r", po::value<int>(), "CPU shares (relative weight)")
		("env,e", po::value<std::vector<std::string>>(), "environment variables (e.g., -e env1=value1 -e env2=value2, APP_DOCKER_OPTS is used to input docker parameters)")
		("interval,i", po::value<int>(), "start interval seconds for short running app")
		("extra_time,x", po::value<int>(), "extra timeout for short running app,the value must less than interval  (default 0)")
		("timezone,z", po::value<std::string>(), "posix timezone for the application, reflect [start_time|daily_start|daily_end] (e.g., 'WST+08:00' is Australia Standard Time)")
		("keep_running,k", po::value<bool>()->default_value(false), "monitor and keep running for short running app in start interval")
		("cache_lines,o", po::value<int>()->default_value(0), "number of output lines will be cached in server side (used for none-container app)")
		("force,f", "force without confirm")
		("debug,g", "print debug information")
		("help,h", "Prints command usage to stdout and exits");

	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	if (m_commandLineVariables.count("name") == 0 ||
	   (m_commandLineVariables.count("docker_image")== 0 && m_commandLineVariables.count("cmd") == 0))
	{
		std::cout << desc << std::endl;
		return;
	}

	if (m_commandLineVariables.count("interval") > 0 && m_commandLineVariables.count("extra_time") > 0)
	{
		if (m_commandLineVariables["interval"].as<int>() <= m_commandLineVariables["extra_time"].as<int>())
		{
			std::cout << "The extra_time seconds must less than interval." << std::endl;
			return;
		}
	}
	// Shell app does not need check app existance
	if (isAppExist(m_commandLineVariables["name"].as<std::string>()))
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
	jsobObj[JSON_KEY_APP_name] = web::json::value::string(m_commandLineVariables["name"].as<std::string>());
	if (m_commandLineVariables.count("cmd"))jsobObj[JSON_KEY_APP_command] = web::json::value::string(m_commandLineVariables["cmd"].as<std::string>());
	if (m_commandLineVariables.count("health_check"))jsobObj[JSON_KEY_APP_health_check_cmd] = web::json::value::string(m_commandLineVariables["health_check"].as<std::string>());
	if (m_commandLineVariables.count("user")) jsobObj[JSON_KEY_APP_user] = web::json::value::string(m_commandLineVariables["user"].as<std::string>());
	jsobObj[JSON_KEY_APP_working_dir] = web::json::value::string(m_commandLineVariables["workdir"].as<std::string>());
	jsobObj[JSON_KEY_APP_status] = web::json::value::number(m_commandLineVariables["status"].as<bool>() ? 1 : 0);
	if (m_commandLineVariables.count(JSON_KEY_APP_comments)) jsobObj[JSON_KEY_APP_comments] = web::json::value::string(m_commandLineVariables[JSON_KEY_APP_comments].as<std::string>());
	if (m_commandLineVariables.count("docker_image")) jsobObj[JSON_KEY_APP_docker_image] = web::json::value::string(m_commandLineVariables["docker_image"].as<std::string>());
	if (m_commandLineVariables.count("timezone")) jsobObj[JSON_KEY_APP_posix_timezone] = web::json::value::string(m_commandLineVariables["timezone"].as<std::string>());
	if (m_commandLineVariables.count("start_time")) jsobObj[JSON_KEY_SHORT_APP_start_time] = web::json::value::string(m_commandLineVariables["start_time"].as<std::string>());
	if (m_commandLineVariables.count("interval")) jsobObj[JSON_KEY_SHORT_APP_start_interval_seconds] = web::json::value::number(m_commandLineVariables["interval"].as<int>());
	if (m_commandLineVariables.count("extra_time")) jsobObj[JSON_KEY_SHORT_APP_start_interval_timeout] = web::json::value::number(m_commandLineVariables["extra_time"].as<int>());
	if (m_commandLineVariables.count("keep_running")) jsobObj[JSON_KEY_PERIOD_APP_keep_running] = web::json::value::boolean(m_commandLineVariables["keep_running"].as<bool>());
	if (m_commandLineVariables.count("daily_start") && m_commandLineVariables.count("daily_end"))
	{
		web::json::value objDailyLimitation = web::json::value::object();
		objDailyLimitation[JSON_KEY_DAILY_LIMITATION_daily_start] = web::json::value::string(m_commandLineVariables["daily_start"].as<std::string>());
		objDailyLimitation[JSON_KEY_DAILY_LIMITATION_daily_end] = web::json::value::string(m_commandLineVariables["daily_end"].as<std::string>());
		jsobObj[JSON_KEY_APP_daily_limitation] = objDailyLimitation;
	}

	if (m_commandLineVariables.count("memory") || m_commandLineVariables.count("virtual_memory") ||
		m_commandLineVariables.count("cpu_shares"))
	{
		web::json::value objResourceLimitation = web::json::value::object();
		if (m_commandLineVariables.count("memory")) objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_memory_mb] = web::json::value::number(m_commandLineVariables["memory"].as<int>());
		if (m_commandLineVariables.count("virtual_memory")) objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb] = web::json::value::number(m_commandLineVariables["virtual_memory"].as<int>());
		if (m_commandLineVariables.count("cpu_shares")) objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_cpu_shares] = web::json::value::number(m_commandLineVariables["cpu_shares"].as<int>());
		jsobObj[JSON_KEY_APP_resource_limit] = objResourceLimitation;
	}


	if (m_commandLineVariables.count("env"))
	{
		std::vector<std::string> envs = m_commandLineVariables["env"].as<std::vector<std::string>>();
		if (envs.size())
		{
			web::json::value objEnvs = web::json::value::object();
			for (auto env : envs)
			{
				auto find = env.find_first_of('=');
				if (find != std::string::npos)
				{
					auto key = Utility::stdStringTrim(env.substr(0, find));
					auto val = Utility::stdStringTrim(env.substr(find + 1));
					objEnvs[key] = web::json::value::string(val);
				}
			}
			jsobObj[JSON_KEY_APP_env] = objEnvs;
		}
	}
	if (m_commandLineVariables.count("cache_lines")) jsobObj[JSON_KEY_APP_cache_lines] = web::json::value::number(m_commandLineVariables["cache_lines"].as<int>());
	if (m_commandLineVariables.count("pid")) jsobObj[JSON_KEY_APP_pid] = web::json::value::number(m_commandLineVariables["pid"].as<int>());
	std::string restPath = std::string("/app/") + m_commandLineVariables["name"].as<std::string>();
	auto response = requestHttp(methods::PUT, restPath, jsobObj);
	auto appJsonStr = response.extract_utf8string(true).get();
	std::cout << GET_STD_STRING(appJsonStr) << std::endl;
}

void ArgumentParser::processUnReg()
{
	po::options_description desc("Unregister and remove an application");
	desc.add_options()
		("help,h", "Prints command usage to stdout and exits")
		OPTION_HOST_NAME
		("name,n", po::value<std::vector<std::string>>(), "remove application by name")
		("force,f", "force without confirm.");

	shiftCommandLineArgs(desc);
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
			std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
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
		("help,h", "Prints command usage to stdout and exits")
		OPTION_HOST_NAME
		("name,n", po::value<std::string>(), "view application by name.")
		("long,l", "display the complete information without reduce")
		("output,o", "view the application output")
		;

	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	bool reduce = !(m_commandLineVariables.count("long"));
	if (m_commandLineVariables.count("name") > 0)
	{
		if (!m_commandLineVariables.count("output"))
		{
			// view app info
			std::string restPath = std::string("/app/") + m_commandLineVariables["name"].as<std::string>();
			auto response = requestHttp(methods::GET, restPath);
			std::cout << response.extract_utf8string(true).get() << std::endl;
		}
		else
		{
			// view app output
			std::string restPath = std::string("/app/") + m_commandLineVariables["name"].as<std::string>() + "/output";
			auto response = requestHttp(methods::GET, restPath);
			auto bodyStr = response.extract_utf8string(true).get();
			std::cout << bodyStr;
		}
	}
	else
	{
		std::string restPath = "/app-manager/applications";
		auto response = requestHttp(methods::GET, restPath);
		printApps(response.extract_json(true).get(), reduce);
	}
}

void ArgumentParser::processResource()
{
	po::options_description desc("View host resource usage:");
	desc.add_options()
		OPTION_HOST_NAME
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/app-manager/resources";
	auto bodyStr = requestHttp(methods::GET, restPath).extract_utf8string(true).get();
	std::cout << GET_STD_STRING(bodyStr) << std::endl;
}

void ArgumentParser::processEnableDisable(bool start)
{
	po::options_description desc("Start application:");
	desc.add_options()
		("help,h", "Prints command usage to stdout and exits")
		OPTION_HOST_NAME
		("all,a", "action for all applications")
		("name,n", po::value<std::vector<std::string>>(), "enable/disable application by name.")
		;

	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	if (m_commandLineVariables.empty() || (!m_commandLineVariables.count("all") && !m_commandLineVariables.count("name")))
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
		std::string restPath = std::string("/app/") + app + +"/" + (start ? HTTP_QUERY_KEY_action_start : HTTP_QUERY_KEY_action_stop);
		auto response = requestHttp(methods::POST, restPath);
		std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
	}
	if (appList.size() == 0)
	{
		std::cout << "No application processed." << std::endl;
	}
}

void ArgumentParser::processRun()
{
	po::options_description desc("Shell application:");
	desc.add_options()
		("help,h", "Prints command usage to stdout and exits")
		OPTION_HOST_NAME
		("user,u", po::value<std::string>()->default_value("root"), "application process running user name")
		("cmd,c", po::value<std::string>(), "full command line with arguments")
		("workdir,w", po::value<std::string>()->default_value("/tmp"), "working directory")
		("env,e", po::value<std::vector<std::string>>(), "environment variables (e.g., -e env1=value1 -e env2=value2)")
		("timeout,x", po::value<int>()->default_value(DEFAULT_RUN_APP_TIMEOUT_SECONDS), "timeout seconds for the shell command run. More than 0 means output will be fetch and print immediately, less than 0 means output will be print when process exited.")
		("retention,r", po::value<int>()->default_value(DEFAULT_RUN_APP_RETENTION_DURATION), "retention duration after run finished (default 10s)")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count("cmd") == 0 || m_commandLineVariables.count("help"))
	{
		std::cout << desc << std::endl;
		return;
	}

	std::map<std::string, std::string> query;
	int timeout = m_commandLineVariables["timeout"].as<int>();
	if (m_commandLineVariables.count("timeout")) query[HTTP_QUERY_KEY_timeout] = std::to_string(timeout);

	web::json::value jsobObj;
	jsobObj[JSON_KEY_APP_command] = web::json::value::string(m_commandLineVariables["cmd"].as<std::string>());
	if (m_commandLineVariables.count("user")) jsobObj[JSON_KEY_APP_user] = web::json::value::string(m_commandLineVariables["user"].as<std::string>());
	if (m_commandLineVariables.count("workdir")) jsobObj[JSON_KEY_APP_working_dir] = web::json::value::string(m_commandLineVariables["workdir"].as<std::string>());
	if (m_commandLineVariables.count("env"))
	{
		std::vector<std::string> envs = m_commandLineVariables["env"].as<std::vector<std::string>>();
		if (envs.size())
		{
			web::json::value objEnvs = web::json::value::object();
			for (auto env : envs)
			{
				auto find = env.find_first_of('=');
				if (find != std::string::npos)
				{
					auto key = Utility::stdStringTrim(env.substr(0, find));
					auto val = Utility::stdStringTrim(env.substr(find + 1));
					objEnvs[key] = web::json::value::string(val);
				}
			}
			jsobObj[JSON_KEY_APP_env] = objEnvs;
		}
	}

	if (timeout < 0)
	{
		// Use syncrun directly
		// /app/syncrun?timeout=5
		std::string restPath = "/app/syncrun";
		auto response = requestHttp(methods::POST, restPath, query, &jsobObj);

		std::cout << GET_STD_STRING(response.extract_utf8string(true).get());
	}
	else
	{
		// Use run and output
		// /app/run?timeout=5
		if (m_commandLineVariables.count(HTTP_QUERY_KEY_retention)) query[HTTP_QUERY_KEY_retention] = std::to_string(m_commandLineVariables[HTTP_QUERY_KEY_retention].as<int>());
		std::string restPath = "/app/run";
		auto response = requestHttp(methods::POST, restPath, query, &jsobObj);
		auto result = response.extract_json(true).get();
		auto appName = result[JSON_KEY_APP_name].as_string();
		auto process_uuid = result[HTTP_QUERY_KEY_process_uuid].as_string();
		while (process_uuid.length())
		{
			// /app/testapp/run/output?process_uuid=ABDJDD-DJKSJDKF
			restPath = std::string("/app/").append(appName).append("/run/output");
			query.clear();
			query[HTTP_QUERY_KEY_process_uuid] = process_uuid;
			response = requestHttp(methods::GET, restPath, query);
			std::cout << GET_STD_STRING(response.extract_utf8string(true).get());
			if (response.status_code() != http::status_codes::OK) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}
	}
}

void ArgumentParser::processDownload()
{
	po::options_description desc("Download file:");
	desc.add_options()
		OPTION_HOST_NAME
		("remote,r", po::value<std::string>(), "remote file path")
		("local,l", po::value<std::string>(), "save to local file path")
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count("remote") == 0 || m_commandLineVariables.count("local") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	std::string restPath = "/download";
	auto file = m_commandLineVariables["remote"].as<std::string>();
	auto local = m_commandLineVariables["local"].as<std::string>();
	std::map<std::string, std::string> query, headers;
	headers[HTTP_HEADER_KEY_file_path] = file;
	auto response = requestHttp(methods::GET, restPath, query, nullptr, &headers);

	auto stream = concurrency::streams::file_stream<uint8_t>::open_ostream(local, std::ios_base::trunc | std::ios_base::binary).get();
	response.body().read_to_end(stream.streambuf()).wait();

	std::cout << "Download file <" << local << "> size <" << Utility::humanReadableSize(stream.streambuf().size()) << ">" << std::endl;

	if (response.headers().has(HTTP_HEADER_KEY_file_mode))
		os::fileChmod(local, std::stoi(response.headers().find(HTTP_HEADER_KEY_file_mode)->second));
	if (response.headers().has(HTTP_HEADER_KEY_file_user))
		os::chown(local, response.headers().find(HTTP_HEADER_KEY_file_user)->second);
}

void ArgumentParser::processUpload()
{
	po::options_description desc("Upload file:");
	desc.add_options()
		OPTION_HOST_NAME
		("remote,r", po::value<std::string>(), "save to remote file path")
		("local,l", po::value<std::string>(), "local file path")
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count("remote") == 0 || m_commandLineVariables.count("local") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	auto file = m_commandLineVariables["remote"].as<std::string>();
	auto local = m_commandLineVariables["local"].as<std::string>();

	if (!Utility::isFileExist(local))
	{
		std::cout << "local file not exist" << std::endl;
		return;
	}
	// https://msdn.microsoft.com/en-us/magazine/dn342869.aspx

	auto fileStream = concurrency::streams::file_stream<uint8_t>::open_istream(local, std::ios_base::binary).get();
	// Get the content length, which is used to set the
	// Content-Length property
	fileStream.seek(0, std::ios::end);
	auto length = static_cast<size_t>(fileStream.tell());
	fileStream.seek(0, std::ios::beg);


	std::map<std::string, std::string> query, header;
	header[HTTP_HEADER_KEY_file_path] = file;

	auto protocol = m_sslEnabled ? U("https://") : U("http://");
	auto restPath = (protocol + GET_STRING_T(m_hostname) + ":" + GET_STRING_T(std::to_string(m_listenPort)));
	// Create http_client to send the request.
	http_client_config config;
	config.set_timeout(std::chrono::seconds(200));
	config.set_validate_certificates(false);
	http_client client(restPath, config);
	http_request request = createRequest(methods::POST, "/upload", query, &header);

	request.set_body(fileStream, length);
	request.headers().add(HTTP_HEADER_KEY_file_mode, os::fileStat(local));
	request.headers().add(HTTP_HEADER_KEY_file_user, os::fileUser(local));
	http_response response = client.request(request).get();
	fileStream.close();
	std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
}

void ArgumentParser::processTags()
{
	po::options_description desc("Manage labels:");
	desc.add_options()
		OPTION_HOST_NAME
		("view,v", "list labels")
		("add,a", "add labels")
		("remove,r", "remove labels")
		("label,l", po::value<std::vector<std::string>>(), "labels (e.g., -l os=linux -t arch=arm64)")
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	
	std::vector<std::string> inputTags;
	if (m_commandLineVariables.count("label")) inputTags = m_commandLineVariables["label"].as<std::vector<std::string>>();

	if (m_commandLineVariables.count("add") &&
		!m_commandLineVariables.count("remove") && !m_commandLineVariables.count("view"))
	{
		// Process add
		if (inputTags.empty())
		{
			std::cout << "No label specified" << std::endl;
			return;
		}
		for (auto str : inputTags)
		{
			std::vector<std::string> envVec = Utility::splitString(str, "=");
			if (envVec.size() == 2)
			{
				std::string restPath = std::string("/label/").append(envVec.at(0));
				std::map<std::string, std::string> query = { {"value", envVec.at(1)} };
				requestHttp(methods::PUT, restPath, query, nullptr, nullptr);
			}
		}
	}
	else if (m_commandLineVariables.count("remove") &&
		!m_commandLineVariables.count("add") && !m_commandLineVariables.count("view"))
	{
		// Process remove
		if (inputTags.empty())
		{
			std::cout << "No label specified" << std::endl;
			return;
		}
		for (auto str : inputTags)
		{
			std::vector<std::string> envVec = Utility::splitString(str, "=");
			std::string restPath = std::string("/label/").append(envVec.at(0));
			requestHttp(methods::DEL, restPath);
		}
	}
	else if (m_commandLineVariables.count("view") &&
		!m_commandLineVariables.count("remove") && !m_commandLineVariables.count("add"))
	{
		// view
	}
	else
	{
		std::cout << desc << std::endl;
		return;
	}

	std::string restPath = "/labels";
	http_response response = requestHttp(methods::GET, restPath);

	// Finally print current
	auto tags = response.extract_json().get().as_object();
	for (auto tag : tags)
	{
		std::cout << tag.first << "=" << tag.second.as_string() << std::endl;
	}
}

void ArgumentParser::processLoglevel()
{
	po::options_description desc("Set log level:");
	desc.add_options()
		OPTION_HOST_NAME
		("level,l", po::value<std::string>(), "log level (e.g., DEBUG,INFO,NOTICE,WARN,ERROR)")
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.size() == 0 || m_commandLineVariables.count("level") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	auto level = m_commandLineVariables["level"].as<std::string>();

	web::json::value jsobObj;
	jsobObj[JSON_KEY_LogLevel] = web::json::value::string(level);
	// /app-manager/config
	auto restPath = std::string("/app-manager/config");
	auto response = requestHttp(methods::POST, restPath, jsobObj);
	std::cout << "Log level set to : " << response.extract_json(true).get().at(JSON_KEY_LogLevel).as_string() << std::endl;
}

void ArgumentParser::processConfigView()
{
	po::options_description desc("Manage labels:");
	desc.add_options()
		OPTION_HOST_NAME
		("view,v", "view basic configurations")
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/app-manager/config";
	http_response response = requestHttp(methods::GET, restPath);
	std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
}

void ArgumentParser::processChangePwd()
{
	po::options_description desc("Manage labels:");
	desc.add_options()
		OPTION_HOST_NAME
		("user,u", po::value<std::string>(), "new password")
		("passwd,x", po::value<std::string>(), "new password")
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (!m_commandLineVariables.count("user") || !m_commandLineVariables.count("passwd"))
	{
		std::cout << desc << std::endl;
		return;
	}

	auto user = m_commandLineVariables["user"].as<std::string>();
	auto passwd = m_commandLineVariables["passwd"].as<std::string>();

	std::string restPath = std::string("/user/") + user + "/passwd";
	std::map<std::string, std::string> query, headers;
	headers[HTTP_HEADER_JWT_new_password] = Utility::encode64(passwd);
	http_response response = requestHttp(methods::POST, restPath, query, nullptr, &headers);
	std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
}

void ArgumentParser::processLockUser()
{
	po::options_description desc("Manage labels:");
	desc.add_options()
		OPTION_HOST_NAME
		("user,u", po::value<std::string>(), "new password")
		("unlock,k", po::value<bool>(), "lock or unlock user")
		("help,h", "Prints command usage to stdout and exits")
		;
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (!m_commandLineVariables.count("user") || !m_commandLineVariables.count("unlock"))
	{
		std::cout << desc << std::endl;
		return;
	}

	auto user = m_commandLineVariables["user"].as<std::string>();
	auto lock = !m_commandLineVariables["lock"].as<bool>();

	std::string restPath = std::string("/user/") + user + (lock ? "/lock" : "/unlock");
	http_response response = requestHttp(methods::POST, restPath);
	std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
}

bool ArgumentParser::confirmInput(const char* msg)
{
	std::cout << msg << ":";
	std::string result;
	std::cin >> result;
	return result == "y";
}

http_response ArgumentParser::requestHttp(const method& mtd, const std::string& path)
{
	std::map<std::string, std::string> query;
	return std::move(requestHttp(mtd, path, query));
}

http_response ArgumentParser::requestHttp(const method& mtd, const std::string& path, web::json::value& body)
{
	std::map<std::string, std::string> query;
	return std::move(requestHttp(mtd, path, query, &body));
}

http_response ArgumentParser::requestHttp(const method& mtd, const std::string& path, std::map<std::string, std::string>& query, web::json::value* body, std::map<std::string, std::string>* header)
{
	auto protocol = m_sslEnabled ? U("https://") : U("http://");
	auto restURL = (protocol + GET_STRING_T(m_hostname) + ":" + GET_STRING_T(std::to_string(m_listenPort)));
	// Create http_client to send the request.
	web::http::client::http_client_config config;
	config.set_timeout(std::chrono::seconds(65));
	config.set_validate_certificates(false);
	web::http::client::http_client client(restURL, config);
	http_request request = createRequest(mtd, path, query, header);
	if (body != nullptr)
	{
		request.set_body(*body);
	}
	http_response response = client.request(request).get();
	if (response.status_code() != status_codes::OK)
	{
		throw std::invalid_argument(response.extract_utf8string(true).get());
	}
	return std::move(response);
}

http_request ArgumentParser::createRequest(const method& mtd, const std::string& path, std::map<std::string, std::string>& query, std::map<std::string, std::string>* header)
{
	// Build request URI and start the request.
	uri_builder builder(GET_STRING_T(path));
	std::for_each(query.begin(), query.end(), [&builder](const std::pair<std::string, std::string>& pair)
		{
			builder.append_query(GET_STRING_T(pair.first), GET_STRING_T(pair.second));
		});

	http_request request(mtd);
	if (header)
	{
		for (auto h : *header)
		{
			request.headers().add(h.first, h.second);
		}
	}
	auto jwtToken = getAuthenToken();
	request.headers().add(HTTP_HEADER_JWT_Authorization, std::string(HTTP_HEADER_JWT_BearerSpace) + jwtToken);
	request.set_request_uri(builder.to_uri());
	return std::move(request);
}

bool ArgumentParser::isAppExist(const std::string& appName)
{
	static auto apps = getAppList();
	return apps.find(appName) != apps.end();
}

std::map<std::string, bool> ArgumentParser::getAppList()
{
	std::map<std::string, bool> apps;
	auto response = requestHttp(methods::GET, "/app-manager/applications");
	if (response.status_code() != status_codes::OK)
	{
		throw std::invalid_argument(response.extract_utf8string(true).get());
	}
	auto jsonValue = response.extract_json(true).get();
	auto arr = jsonValue.as_array();
	for (auto iter = arr.begin(); iter != arr.end(); iter++)
	{
		auto jobj = *iter;
		apps[GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_name)] = GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_status) == 1;
	}
	return apps;
}

std::string ArgumentParser::getAuthenToken()
{
	// 1. try to read from token file
	m_jwtToken = readAuthenToken();

	// 2. try to get from REST
	if (m_jwtToken.empty())
	{
		auto protocol = m_sslEnabled ? U("https://") : U("http://");
		auto restPath = (protocol + GET_STRING_T(m_hostname) + ":" + GET_STRING_T(std::to_string(m_listenPort)));
		http_client_config config;
		config.set_validate_certificates(false);
		http_client client(restPath, config);
		http_request requestLogin(web::http::methods::POST);
		uri_builder builder(GET_STRING_T("/login"));
		requestLogin.set_request_uri(builder.to_uri());
		requestLogin.headers().add(HTTP_HEADER_JWT_username, Utility::encode64(m_username));
		requestLogin.headers().add(HTTP_HEADER_JWT_password, Utility::encode64(m_userpwd));
		if (m_tokenTimeoutSeconds) requestLogin.headers().add(HTTP_HEADER_JWT_expire_seconds, std::to_string(m_tokenTimeoutSeconds));
		http_response response = client.request(requestLogin).get();
		if (response.status_code() != status_codes::OK)
		{
			throw std::invalid_argument(std::string("Login failed ") + response.extract_utf8string(true).get());
		}
		else
		{
			auto jwtContent = response.extract_json(true).get();
			m_jwtToken = GET_JSON_STR_VALUE(jwtContent, HTTP_HEADER_JWT_access_token);
		}
	}
	return m_jwtToken;
}

std::string ArgumentParser::readAuthenToken()
{
	std::string jwtToken;
	std::string tokenFile = std::string(m_tokenFilePrefix) + m_hostname;
	if (Utility::isFileExist(tokenFile) && m_hostname.length())
	{
		std::ifstream ifs(tokenFile);
		if (ifs.is_open())
		{
			ifs >> jwtToken;
			ifs.close();
		}
	}
	return std::move(jwtToken);
}

void ArgumentParser::printApps(web::json::value json, bool reduce)
{
	// Title:
	std::cout << std::left;
	std::cout
		<< std::setw(3) << ("id")
		<< std::setw(12) << (JSON_KEY_APP_name)
		<< std::setw(6) << (JSON_KEY_APP_user)
		<< std::setw(9) << (JSON_KEY_APP_status)
		<< std::setw(7) << (JSON_KEY_APP_health)
		<< std::setw(7) << (JSON_KEY_APP_pid)
		<< std::setw(8) << (JSON_KEY_APP_memory)
		<< std::setw(7) << (JSON_KEY_APP_return)
		<< std::setw(20) << (JSON_KEY_APP_last_start)
		<< (JSON_KEY_APP_command)
		<< std::endl;

	int index = 1;
	auto jsonArr = json.as_array();
	auto reduceFunc = std::bind(&ArgumentParser::reduceStr, this, std::placeholders::_1, std::placeholders::_2);
	std::for_each(jsonArr.begin(), jsonArr.end(), [&index, &reduceFunc, reduce](web::json::value& jobj) {
		const char* slash = " -";
		auto name = GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_name);
		if (reduce) name = reduceFunc(name, 12);
		else if (name.length() >= 12) name += " ";
		std::cout << std::setw(3) << index++;
		std::cout << std::setw(12) << name;
		std::cout << std::setw(6) << reduceFunc(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_user), 6);
		std::cout << std::setw(9) << GET_STATUS_STR(GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_status));
		std::cout << std::setw(7) << GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_health);
		std::cout << std::setw(7);
		{
			if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_pid))
				std::cout << GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_pid);
			else
				std::cout << slash;
		}
		std::cout << std::setw(8);
		{
			if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_memory))
				std::cout << Utility::humanReadableSize(GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_memory));
			else
				std::cout << slash;
		}
		std::cout << std::setw(7);
		{
			if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_return))
				std::cout << GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_return);
			else
				std::cout << slash;
		}
		std::cout << std::setw(20);
		{
			if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_last_start))
				std::cout << GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_last_start);
			else
				std::cout << slash;
		}
		std::cout << GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_command);
		std::cout << std::endl;
		});
}

void ArgumentParser::shiftCommandLineArgs(po::options_description& desc)
{
	m_commandLineVariables.clear();
	std::vector<std::string> opts = po::collect_unrecognized(m_pasrsedOptions, po::include_positional);
	// remove [command] option and parse all others in m_commandLineVariables
	if (opts.size()) opts.erase(opts.begin());
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

void ArgumentParser::setStdinEcho(bool enable)
{
	// https://stackoverflow.com/questions/1413445/reading-a-password-from-stdcin
#ifdef WIN32
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode;
	GetConsoleMode(hStdin, &mode);

	if (!enable)
		mode &= ~ENABLE_ECHO_INPUT;
	else
		mode |= ENABLE_ECHO_INPUT;

	SetConsoleMode(hStdin, mode);

#else
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	if (!enable)
		tty.c_lflag &= ~ECHO;
	else
		tty.c_lflag |= ECHO;

	(void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

ssize_t ArgumentParser::inputSecurePasswd(char** pw, size_t sz, int mask, FILE* fp)
{
	if (!pw || !sz || !fp) return -1;       /* validate input   */
#ifdef MAXPW
	if (sz > MAXPW) sz = MAXPW;
#endif

	if (*pw == NULL) {              /* reallocate if no address */
		void* tmp = realloc(*pw, sz * sizeof * *pw);
		if (!tmp)
			return -1;
		memset(tmp, 0, sz);    /* initialize memory to 0   */
		*pw = (char*)tmp;
	}

	size_t idx = 0;         /* index, number of chars in read   */
	int c = 0;

	struct termios old_kbd_mode;    /* orig keyboard settings   */
	struct termios new_kbd_mode;

	if (tcgetattr(0, &old_kbd_mode)) { /* save orig settings   */
		fprintf(stderr, "%s() error: tcgetattr failed.\n", __func__);
		return -1;
	}   /* copy old to new */
	memcpy(&new_kbd_mode, &old_kbd_mode, sizeof(struct termios));

	new_kbd_mode.c_lflag &= ~(ICANON | ECHO);  /* new kbd flags */
	new_kbd_mode.c_cc[VTIME] = 0;
	new_kbd_mode.c_cc[VMIN] = 1;
	if (tcsetattr(0, TCSANOW, &new_kbd_mode)) {
		fprintf(stderr, "%s() error: tcsetattr failed.\n", __func__);
		return -1;
	}

	/* read chars from fp, mask if valid char specified */
	while (((c = fgetc(fp)) != '\n' && c != EOF && idx < sz - 1) ||
		(idx == sz - 1 && c == 127))
	{
		if (c != 127) {
			if (31 < mask && mask < 127)    /* valid ascii char */
				fputc(mask, stdout);
			(*pw)[idx++] = c;
		}
		else if (idx > 0) {         /* handle backspace (del)   */
			if (31 < mask && mask < 127) {
				fputc(0x8, stdout);
				fputc(' ', stdout);
				fputc(0x8, stdout);
			}
			(*pw)[--idx] = 0;
		}
	}
	(*pw)[idx] = 0; /* null-terminate   */

					/* reset original keyboard  */
	if (tcsetattr(0, TCSANOW, &old_kbd_mode)) {
		fprintf(stderr, "%s() error: tcsetattr failed.\n", __func__);
		return -1;
	}

	if (idx == sz - 1 && c != '\n') /* warn if pw truncated */
		fprintf(stderr, " (%s() warning: truncated at %zu chars.)\n",
			__func__, sz - 1);

	return idx; /* number of chars in passwd    */
}
#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
#include <ace/Signal.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <functional>
#include <boost/io/ios_state.hpp>
#include <boost/program_options.hpp>
#include <cpprest/filestream.h>
#include <cpprest/json.h>
#include "ArgumentParser.h"
#include "../common/DurationParse.h"
#include "../common/jwt-cpp/jwt.h"
#include "../common/Utility.h"
#include "../common/os/linux.hpp"
#include "../common/os/chown.hpp"

#define OPTION_HOST_NAME ("host,b", po::value<std::string>()->default_value("localhost"), "host name or ip address")("port,B", po::value<int>(), "port number")
#define COMMON_OPTIONS                                                                                                              \
	OPTION_HOST_NAME("user,u", po::value<std::string>(), "Specifies the name of the user to connect to App Mesh for this command.") \
	("password,x", po::value<std::string>(), "Specifies the user password to connect to App Mesh for this command.")
#define GET_USER_NAME_PASS                                                                \
	if (m_commandLineVariables.count("password") && m_commandLineVariables.count("user")) \
	{                                                                                     \
		m_username = m_commandLineVariables["user"].as<std::string>();                    \
		m_userpwd = m_commandLineVariables["password"].as<std::string>();                 \
	}
#define HELP_ARG_CHECK_WITH_RETURN                                 \
	GET_USER_NAME_PASS                                             \
	if (m_commandLineVariables.count("help") > 0)                  \
	{                                                              \
		std::cout << desc << std::endl;                            \
		return;                                                    \
	}                                                              \
	m_hostname = m_commandLineVariables["host"].as<std::string>(); \
	if (m_commandLineVariables.count("port"))                      \
		m_listenPort = m_commandLineVariables["port"].as<int>();

// Each user should have its own token path
const static std::string m_tokenFilePrefix = std::string(getenv("HOME") ? getenv("HOME") : ".") + "/._appmesh_";
static std::string m_jwtToken;
extern char **environ;

// Global variable for appc exec
static bool SIGINIT_BREAKING = false;
static std::string APPC_EXEC_APP_NAME;
static ArgumentParser *WORK_PARSE = nullptr;

ArgumentParser::ArgumentParser(int argc, const char *argv[], int listenPort, bool sslEnabled)
	: m_argc(argc), m_argv(argv), m_listenPort(listenPort), m_sslEnabled(sslEnabled), m_tokenTimeoutSeconds(0)
{
	WORK_PARSE = this;
	po::options_description global("Global options");
	global.add_options()
	("command", po::value<std::string>(), "command to execute")
	("subargs", po::value<std::vector<std::string>>(), "arguments for command");

	po::positional_options_description pos;
	pos.add("command", 1).add("subargs", -1);

	// parse [command] and all other arguments in [subargs]
	auto parsed = po::command_line_parser(argc, argv).options(global).positional(pos).allow_unregistered().run();
	m_pasrsedOptions = parsed.options;
	po::store(parsed, m_commandLineVariables);
	po::notify(m_commandLineVariables);
}

ArgumentParser::~ArgumentParser()
{
	unregSignal();
	WORK_PARSE = nullptr;
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
	else if (cmd == "loginfo")
	{
		processLoginfo();
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
	else if (cmd == "exec")
	{
		processExec();
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
	else if (cmd == "appmgpwd")
	{
		processEncryptUserPwd();
	}
	else
	{
		printMainHelp();
	}
}

void ArgumentParser::printMainHelp()
{
	std::cout << "Commands:" << std::endl;
	std::cout << "  logon       Log on to App Mesh for a specific time period." << std::endl;
	std::cout << "  logoff      End a App Mesh user session" << std::endl;
	std::cout << "  loginfo     Print current logon user" << std::endl;

	std::cout << "  view        List application[s]" << std::endl;
	std::cout << "  resource    Display host resource usage" << std::endl;
	std::cout << "  label       Manage host labels" << std::endl;
	std::cout << "  enable      Enable a application" << std::endl;
	std::cout << "  disable     Disable a application" << std::endl;
	std::cout << "  restart     Restart a application" << std::endl;
	std::cout << "  reg         Add a new application" << std::endl;
	std::cout << "  unreg       Remove an application" << std::endl;
	std::cout << "  run         Run application and get output" << std::endl;
	std::cout << "  exec        Run current cmd by appmesh and impersonate context" << std::endl;
	std::cout << "  get         Download remote file to local" << std::endl;
	std::cout << "  put         Upload file to server" << std::endl;
	std::cout << "  config      Manage basic configurations" << std::endl;
	std::cout << "  passwd      Change user password" << std::endl;
	std::cout << "  lock        Lock unlock a user" << std::endl;
	std::cout << "  log         Set log level" << std::endl;

	std::cout << std::endl;
	std::cout << "Run 'appc COMMAND --help' for more information on a command." << std::endl;
	std::cout << "Use '-b $hostname','-B $port' to run remote command." << std::endl;

	std::cout << std::endl;
	std::cout << "Usage:  appc [COMMAND] [ARG...] [flags]" << std::endl;
}

void ArgumentParser::processLogon()
{
	po::options_description desc("Log on to App Mesh:");
	desc.add_options()
		COMMON_OPTIONS
		("timeout,t", po::value<std::string>()->default_value(std::to_string(DEFAULT_TOKEN_EXPIRE_SECONDS)), "Specifies the command session duration in minutes.")
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	m_tokenTimeoutSeconds = DurationParse().parse(m_commandLineVariables["timeout"].as<std::string>());
	if (!m_commandLineVariables.count("user"))
	{
		std::cout << "User: ";
		std::cin >> m_username;
	}

	if (!m_commandLineVariables.count("password"))
	{
		if (!m_commandLineVariables.count("user"))
		{
			std::cin.clear();
			std::cin.ignore(1024, '\n');
		}
		std::cout << "Password: ";
		char buffer[256] = {0};
		char *str = buffer;
		FILE *fp = stdin;
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
	po::options_description desc("Logoff to App Mesh:");
	desc.add_options()
		OPTION_HOST_NAME
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string tokenFile = std::string(m_tokenFilePrefix) + m_hostname;
	if (Utility::isFileExist(tokenFile))
	{
		std::ofstream ofs(tokenFile, std::ios::trunc);
		ofs.close();
	}
	std::cout << "User logoff from " << m_hostname << " success." << std::endl;
}

void ArgumentParser::processLoginfo()
{
	po::options_description desc("Print logon user:");
	desc.add_options()
		OPTION_HOST_NAME
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	auto token = getAuthenToken();
	if (token.length())
	{
		auto decoded_token = jwt::decode(token);
		if (decoded_token.has_payload_claim(HTTP_HEADER_JWT_name))
		{
			// get user info
			auto userName = decoded_token.get_payload_claim(HTTP_HEADER_JWT_name).as_string();
			std::cout << userName << std::endl;
		}
	}
}

// appName is null means this is a normal application (not a shell application)
void ArgumentParser::processReg()
{
	po::options_description desc("Register a new application");
	desc.add_options()
		COMMON_OPTIONS
		("name,n", po::value<std::string>(), "application name")
		("metadata,g", po::value<std::string>(), "application metadata string")
		("perm", po::value<int>(), "application user permission, value = [group & other], each can be deny:1, read:2, write: 3.")
		("cmd,c", po::value<std::string>(), "full command line with arguments")
		("shell_mode,S", "command line will be executed in shell in this mode")
		("init,I", po::value<std::string>(), "initial command line with arguments")
		("fini,F", po::value<std::string>(), "fini command line with arguments")
		("health_check,l", po::value<std::string>(), "health check script command (e.g., sh -x 'curl host:port/health', return 0 is health)")
		("docker_image,d", po::value<std::string>(), "docker image which used to run command line (this will enable docker)")
		("workdir,w", po::value<std::string>(), "working directory")
		("status,s", po::value<bool>()->default_value(true), "application status status (start is true, stop is false)")
		("start_time,t", po::value<std::string>(), "start date time for app (ISO8601 time format, e.g., '2020-10-11T09:22:05+08:00')")
		("end_time,E", po::value<std::string>(), "end date time for app (ISO8601 time format, e.g., '2020-10-11T09:22:05+08:00')")
		("daily_start,j", po::value<std::string>(), "daily start time (e.g., '09:00:00')")
		("daily_end,y", po::value<std::string>(), "daily end time (e.g., '20:00:00')")
		("memory,m", po::value<int>(), "memory limit in MByte")
		("pid,p", po::value<int>(), "process id used to attach")
		("stdout_cache_size,O", po::value<int>(), "stdout file cache number")
		("virtual_memory,v", po::value<int>(), "virtual memory limit in MByte")
		("cpu_shares,r", po::value<int>(), "CPU shares (relative weight)")
		("env,e", po::value<std::vector<std::string>>(), "environment variables (e.g., -e env1=value1 -e env2=value2, APP_DOCKER_OPTS is used to input docker parameters)")
		("interval,i", po::value<std::string>(), "start interval seconds for short running app, support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W')")
		("extra_time,q", po::value<std::string>(), "extra timeout for short running app,the value must less than interval  (default 0), support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W')")
		("keep_running,k", "monitor and keep running for short running app in start interval")
		("force,f", "force without confirm")
		("help,h", "Prints command usage to stdout and exits");

	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	if (m_commandLineVariables.count("name") == 0 ||
		(m_commandLineVariables.count("docker_image") == 0 && m_commandLineVariables.count("cmd") == 0))
	{
		std::cout << desc << std::endl;
		return;
	}

	if (m_commandLineVariables.count("interval") > 0 && m_commandLineVariables.count("extra_time") > 0)
	{
		if (DurationParse().parse(m_commandLineVariables["interval"].as<std::string>()) <=
			DurationParse().parse(m_commandLineVariables["extra_time"].as<std::string>()))
		{
			std::cout << "The extra_time seconds must less than interval." << std::endl;
			return;
		}
	}
	// Shell app does not need check app existence
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
	if (m_commandLineVariables.count("cmd"))
		jsobObj[JSON_KEY_APP_command] = web::json::value::string(m_commandLineVariables["cmd"].as<std::string>());
	if (m_commandLineVariables.count("shell_mode"))
		jsobObj[JSON_KEY_APP_shell_mode] = web::json::value::boolean(true);
	if (m_commandLineVariables.count("init"))
		jsobObj[JSON_KEY_APP_init_command] = web::json::value::string(m_commandLineVariables["init"].as<std::string>());
	if (m_commandLineVariables.count("fini"))
		jsobObj[JSON_KEY_APP_fini_command] = web::json::value::string(m_commandLineVariables["fini"].as<std::string>());
	if (m_commandLineVariables.count("health_check"))
		jsobObj[JSON_KEY_APP_health_check_cmd] = web::json::value::string(m_commandLineVariables["health_check"].as<std::string>());
	if (m_commandLineVariables.count("perm"))
		jsobObj[JSON_KEY_APP_owner_permission] = web::json::value::number(m_commandLineVariables["perm"].as<int>());
	if (m_commandLineVariables.count("workdir"))
		jsobObj[JSON_KEY_APP_working_dir] = web::json::value::string(m_commandLineVariables["workdir"].as<std::string>());
	if (m_commandLineVariables.count("status"))
		jsobObj[JSON_KEY_APP_status] = web::json::value::number(m_commandLineVariables["status"].as<bool>() ? 1 : 0);
	if (m_commandLineVariables.count(JSON_KEY_APP_metadata))
		jsobObj[JSON_KEY_APP_metadata] = web::json::value::string(m_commandLineVariables[JSON_KEY_APP_metadata].as<std::string>());
	if (m_commandLineVariables.count("docker_image"))
		jsobObj[JSON_KEY_APP_docker_image] = web::json::value::string(m_commandLineVariables["docker_image"].as<std::string>());
	if (m_commandLineVariables.count("start_time"))
		jsobObj[JSON_KEY_SHORT_APP_start_time] = web::json::value::string(m_commandLineVariables["start_time"].as<std::string>());
	if (m_commandLineVariables.count("end_time"))
		jsobObj[JSON_KEY_SHORT_APP_end_time] = web::json::value::string(m_commandLineVariables["end_time"].as<std::string>());
	if (m_commandLineVariables.count("interval"))
		jsobObj[JSON_KEY_SHORT_APP_start_interval_seconds] = web::json::value::string(m_commandLineVariables["interval"].as<std::string>());
	if (m_commandLineVariables.count("extra_time"))
		jsobObj[JSON_KEY_SHORT_APP_start_interval_timeout] = web::json::value::string(m_commandLineVariables["extra_time"].as<std::string>());
	if (m_commandLineVariables.count("stdout_cache_size"))
		jsobObj[JSON_KEY_APP_stdout_cache_size] = web::json::value::number(m_commandLineVariables["stdout_cache_size"].as<int>());
	if (m_commandLineVariables.count("keep_running"))
		jsobObj[JSON_KEY_PERIOD_APP_keep_running] = web::json::value::boolean(true);
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
		if (m_commandLineVariables.count("memory"))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_memory_mb] = web::json::value::number(m_commandLineVariables["memory"].as<int>());
		if (m_commandLineVariables.count("virtual_memory"))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb] = web::json::value::number(m_commandLineVariables["virtual_memory"].as<int>());
		if (m_commandLineVariables.count("cpu_shares"))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_cpu_shares] = web::json::value::number(m_commandLineVariables["cpu_shares"].as<int>());
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
	if (m_commandLineVariables.count("pid"))
		jsobObj[JSON_KEY_APP_pid] = web::json::value::number(m_commandLineVariables["pid"].as<int>());
	std::string restPath = std::string("/appmesh/app/") + m_commandLineVariables["name"].as<std::string>();
	auto resp = requestHttp(true, methods::PUT, restPath, jsobObj);
	std::cout << Utility::prettyJson(resp.extract_json(true).get().serialize()) << std::endl;
}

void ArgumentParser::processUnReg()
{
	po::options_description desc("Unregister and remove an application");
	desc.add_options()
		("help,h", "Prints command usage to stdout and exits")
		COMMON_OPTIONS
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
			std::string restPath = std::string("/appmesh/app/") + appName;
			auto response = requestHttp(true, methods::DEL, restPath);
			std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
		}
		else
		{
			throw std::invalid_argument(Utility::stringFormat("No such application <%s>", appName.c_str()));
		}
	}
}

void ArgumentParser::processView()
{
	po::options_description desc("List application[s]");
	desc.add_options()
		("help,h", "Prints command usage to stdout and exits")
		COMMON_OPTIONS
		("name,n", po::value<std::string>(), "view application by name.")
		("long,l", "display the complete information without reduce")
		("output,o", "view the application output")
		("stdout_index,O", po::value<int>(), "application output index");

	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	bool reduce = !(m_commandLineVariables.count("long"));
	if (m_commandLineVariables.count("name") > 0)
	{
		if (!m_commandLineVariables.count("output"))
		{
			// view app info
			std::string restPath = std::string("/appmesh/app/") + m_commandLineVariables["name"].as<std::string>();
			auto resp = requestHttp(true, methods::GET, restPath);
			std::cout << Utility::prettyJson(resp.extract_json(true).get().serialize()) << std::endl;
		}
		else
		{
			// view app output
			int index = 0;
			bool keepHis = false;
			std::string restPath = std::string("/appmesh/app/") + m_commandLineVariables["name"].as<std::string>() + "/output";
			if (m_commandLineVariables.count("stdout_index"))
			{
				index = m_commandLineVariables["stdout_index"].as<int>();
			}
			std::map<std::string, std::string> query;
			query["keep_history"] = std::to_string(keepHis);
			query["stdout_index"] = std::to_string(index);
			auto response = requestHttp(true, methods::GET, restPath, query);
			auto bodyStr = response.extract_utf8string(true).get();
			std::cout << bodyStr;
		}
	}
	else
	{
		std::string restPath = "/appmesh/applications";
		auto response = requestHttp(true, methods::GET, restPath);
		printApps(response.extract_json(true).get(), reduce);
	}
}

void ArgumentParser::processResource()
{
	po::options_description desc("View host resource usage:");
	desc.add_options()
		COMMON_OPTIONS
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/resources";
	auto resp = requestHttp(true, methods::GET, restPath);
	std::cout << Utility::prettyJson(resp.extract_json(true).get().serialize()) << std::endl;
}

void ArgumentParser::processEnableDisable(bool start)
{
	po::options_description desc("Start application:");
	desc.add_options()
		("help,h", "Prints command usage to stdout and exits")
		COMMON_OPTIONS
		("all,a", "action for all applications")
		("name,n", po::value<std::vector<std::string>>(), "enable/disable application by name.");

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
		std::for_each(appMap.begin(), appMap.end(), [&appList, &start](const std::pair<std::string, bool> &pair) {
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
				throw std::invalid_argument(Utility::stringFormat("No such application <%s>", appName.c_str()));
			}
			appList.push_back(appName);
		}
	}
	for (auto app : appList)
	{
		std::string restPath = std::string("/appmesh/app/") + app + +"/" + (start ? HTTP_QUERY_KEY_action_start : HTTP_QUERY_KEY_action_stop);
		auto response = requestHttp(true, methods::POST, restPath);
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
		COMMON_OPTIONS
		("cmd,c", po::value<std::string>(), "full command line with arguments")
		("workdir,w", po::value<std::string>(), "working directory (default '/opt/appmesh/work')")
		("env,e", po::value<std::vector<std::string>>(), "environment variables (e.g., -e env1=value1 -e env2=value2)")
		("timeout,t", po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_TIMEOUT_SECONDS)), "timeout seconds for the shell command run. More than 0 means output will be fetch and print immediately, less than 0 means output will be print when process exited, support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').")
		("retention,r", po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_RETENTION_DURATION)), "retention duration after run finished (default 10s), app will be cleaned after the retention period, support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count("cmd") == 0 || m_commandLineVariables.count("help"))
	{
		std::cout << desc << std::endl;
		return;
	}

	std::map<std::string, std::string> query;
	int timeout = DurationParse().parse(m_commandLineVariables["timeout"].as<std::string>());
	if (m_commandLineVariables.count("timeout"))
		query[HTTP_QUERY_KEY_timeout] = std::to_string(timeout);

	web::json::value jsobObj;
	jsobObj[JSON_KEY_APP_shell_mode] = web::json::value::boolean(true);
	jsobObj[JSON_KEY_APP_command] = web::json::value::string(m_commandLineVariables["cmd"].as<std::string>());
	if (m_commandLineVariables.count("workdir"))
		jsobObj[JSON_KEY_APP_working_dir] = web::json::value::string(m_commandLineVariables["workdir"].as<std::string>());
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
		std::string restPath = "/appmesh/app/syncrun";
		auto response = requestHttp(true, methods::POST, restPath, query, &jsobObj);

		std::cout << GET_STD_STRING(response.extract_utf8string(true).get());
	}
	else
	{
		// Use run and output
		// /app/run?timeout=5
		if (m_commandLineVariables.count(HTTP_QUERY_KEY_retention))
			query[HTTP_QUERY_KEY_retention] = m_commandLineVariables[HTTP_QUERY_KEY_retention].as<std::string>();
		std::string restPath = "/appmesh/app/run";
		auto response = requestHttp(true, methods::POST, restPath, query, &jsobObj);
		auto result = response.extract_json(true).get();
		auto appName = result[JSON_KEY_APP_name].as_string();
		auto process_uuid = result[HTTP_QUERY_KEY_process_uuid].as_string();
		while (process_uuid.length())
		{
			// /app/testapp/run/output?process_uuid=ABDJDD-DJKSJDKF
			restPath = std::string("/appmesh/app/").append(appName).append("/run/output");
			query.clear();
			query[HTTP_QUERY_KEY_process_uuid] = process_uuid;
			response = requestHttp(true, methods::GET, restPath, query);
			std::cout << GET_STD_STRING(response.extract_utf8string(true).get());
			if (response.headers().has(HTTP_HEADER_KEY_exit_code) || response.status_code() != http::status_codes::OK)
			{
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}
	}
}

void SIGINT_Handler(int signo)
{
	// make sure we only process SIGINT here
	// SIGINT 	ctrl - c
	assert(signo == SIGINT);
	if (SIGINIT_BREAKING)
	{
		//std::cout << "You pressed SIGINT(Ctrl+C) twice, session will exit." << std::endl;
		auto restPath = std::string("/appmesh/app/").append(APPC_EXEC_APP_NAME);
		auto response = WORK_PARSE->requestHttp(false, methods::DEL, restPath);
		if (response.status_code() != status_codes::OK)
		{
			std::cout << response.extract_utf8string(true).get() << std::endl;
		}
		// if ctrl+c typed twice, just exit current
		ACE_OS::_exit(SIGINT);
	}
	else
	{
		//std::cout << "You pressed SIGINT(Ctrl+C)" << std::endl;
		SIGINIT_BREAKING = true;
		auto restPath = std::string("/appmesh/app/").append(APPC_EXEC_APP_NAME).append("/disable");
		auto response = WORK_PARSE->requestHttp(false, methods::POST, restPath);
	}
}

void ArgumentParser::regSignal()
{
	m_sigAction = std::make_shared<ACE_Sig_Action>();
	m_sigAction->handler(SIGINT_Handler);
	m_sigAction->register_action(SIGINT);
}

void ArgumentParser::unregSignal()
{
	if (m_sigAction)
		m_sigAction = nullptr;
}

void ArgumentParser::processExec()
{
	m_hostname = "localhost";
	// Get current session id (bash pid)
	auto bashId = getppid();
	// Get appmesh user
	auto appmeshUser = getAuthenUser();
	// Get current user name
	auto osUser = getOsUser();
	// Unique session id as appname
	APPC_EXEC_APP_NAME = appmeshUser + "_" + osUser + "_" + std::to_string(bashId);

	// Get current command line, use raw argv here
	std::string initialCmd;
	for (size_t i = 1; i < m_argc; i++)
	{
		initialCmd.append(m_argv[i]).append(" ");
	}

	// Get current ENV
	web::json::value objEnvs = web::json::value::object();
	for (char **var = environ; *var != NULL; var++)
	{
		std::string e = *var;
		auto vec = Utility::splitString(e, "=");
		if (vec.size() > 0)
		{
			objEnvs[vec[0]] = web::json::value::string(vec.size() > 1 ? vec[1] : std::string());
		}
	}

	char buff[MAX_COMMAND_LINE_LENGH] = {0};
	web::json::value jsobObj;
	jsobObj[JSON_KEY_APP_name] = web::json::value::string(APPC_EXEC_APP_NAME); // option, if not provide, UUID will be created
	jsobObj[JSON_KEY_APP_shell_mode] = web::json::value::boolean(true);
	jsobObj[JSON_KEY_APP_command] = web::json::value::string(initialCmd);
	jsobObj[JSON_KEY_APP_env] = objEnvs;
	jsobObj[JSON_KEY_APP_working_dir] = web::json::value::string(getcwd(buff, sizeof(buff)));

	std::string process_uuid;
	bool currentRunFinished = true; // one submitted run finished
	bool runOnce = false;			// if appc exec specify one cmd, then just run once
	SIGINIT_BREAKING = false;		// if ctrl + c is triggered, stop run and start read input from stdin
	if (initialCmd.length())
	{
		runOnce = true;
		std::map<std::string, std::string> query = {{HTTP_QUERY_KEY_timeout, std::to_string(-1)}}; // disable timeout
		std::string restPath = "/appmesh/app/run";
		auto response = requestHttp(false, methods::POST, restPath, query, &jsobObj);
		if (response.status_code() == http::status_codes::OK)
		{
			auto result = response.extract_json(true).get();
			process_uuid = result[HTTP_QUERY_KEY_process_uuid].as_string();
			currentRunFinished = false;
		}
		else
		{
			std::cout << response.extract_utf8string(true).get() << std::endl;
		}
	}
	else
	{
		// only capture SIGINT in continues mode
		this->regSignal();
		runOnce = false;
	}

	while (true)
	{
		// no need read stdin when run for once
		if (!runOnce && (SIGINIT_BREAKING || currentRunFinished))
		{
			SIGINIT_BREAKING = false;
			std::string input;
			while (std::getline(std::cin, input) && input.length() > 0)
			{
				process_uuid.clear();
				jsobObj[JSON_KEY_APP_command] = web::json::value::string(input);
				std::map<std::string, std::string> query = {{HTTP_QUERY_KEY_timeout, std::to_string(-1)}}; // disable timeout
				std::string restPath = "/appmesh/app/run";
				auto response = requestHttp(false, methods::POST, restPath, query, &jsobObj);
				if (response.status_code() == http::status_codes::OK)
				{
					auto result = response.extract_json(true).get();
					process_uuid = result[HTTP_QUERY_KEY_process_uuid].as_string();
					currentRunFinished = false;
				}
				else
				{
					std::cout << response.extract_utf8string(true).get() << std::endl;
					currentRunFinished = true;
					process_uuid.clear();
				}
				// always exit loop when get one input
				break;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
		// Process Read
		if (!process_uuid.empty())
		{
			std::map<std::string, std::string> query = {{HTTP_QUERY_KEY_process_uuid, process_uuid}};
			auto restPath = Utility::stringFormat("/appmesh/app/%s/run/output", APPC_EXEC_APP_NAME.c_str());
			auto response = requestHttp(false, methods::GET, restPath, query);
			std::cout << response.extract_utf8string(true).get();
			if (response.headers().has(HTTP_HEADER_KEY_exit_code) || response.status_code() != http::status_codes::OK)
			{
				currentRunFinished = true;
				process_uuid.clear();
				if (runOnce)
				{
					break;
				}
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	}
}

void ArgumentParser::processDownload()
{
	po::options_description desc("Download file:");
	desc.add_options()
		COMMON_OPTIONS
		("remote,r", po::value<std::string>(), "remote file path")
		("local,l", po::value<std::string>(), "save to local file path")
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count("remote") == 0 || m_commandLineVariables.count("local") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	std::string restPath = "/appmesh/file/download";
	auto file = m_commandLineVariables["remote"].as<std::string>();
	auto local = m_commandLineVariables["local"].as<std::string>();
	std::map<std::string, std::string> query, headers;
	headers[HTTP_HEADER_KEY_file_path] = file;
	auto response = requestHttp(true, methods::GET, restPath, query, nullptr, &headers);

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
		COMMON_OPTIONS
		("remote,r", po::value<std::string>(), "save to remote file path")
		("local,l", po::value<std::string>(), "local file path")
		("help,h", "Prints command usage to stdout and exits");
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
	auto length = static_cast<std::size_t>(fileStream.tell());
	fileStream.seek(0, std::ios::beg);

	std::map<std::string, std::string> query, header;
	header[HTTP_HEADER_KEY_file_path] = file;

	auto protocol = m_sslEnabled ? U("https://") : U("http://");
	auto restURL = (protocol + GET_STRING_T(m_hostname) + ":" + GET_STRING_T(std::to_string(m_listenPort)));
	// Create http_client to send the request.
	http_client_config config;
	config.set_timeout(std::chrono::seconds(200));
	config.set_validate_certificates(false);
	http_client client(restURL, config);
	std::string restPath = "/appmesh/file/upload";
	http_request request = createRequest(methods::POST, restPath, query, &header);

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
		COMMON_OPTIONS
		("view,v", "list labels")
		("add,a", "add labels")
		("remove,r", "remove labels")
		("label,l", po::value<std::vector<std::string>>(), "labels (e.g., -l os=linux -t arch=arm64)")
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::vector<std::string> inputTags;
	if (m_commandLineVariables.count("label"))
		inputTags = m_commandLineVariables["label"].as<std::vector<std::string>>();

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
				std::string restPath = std::string("/appmesh/label/").append(envVec.at(0));
				std::map<std::string, std::string> query = {{"value", envVec.at(1)}};
				requestHttp(true, methods::PUT, restPath, query, nullptr, nullptr);
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
			std::string restPath = std::string("/appmesh/label/").append(envVec.at(0));
			auto resp = requestHttp(true, methods::DEL, restPath);
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

	std::string restPath = "/appmesh/labels";
	http_response response = requestHttp(true, methods::GET, restPath);
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
		COMMON_OPTIONS
		("level,l", po::value<std::string>(), "log level (e.g., DEBUG,INFO,NOTICE,WARN,ERROR)")
		("help,h", "Prints command usage to stdout and exits");
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
	auto restPath = std::string("/appmesh/config");
	auto response = requestHttp(true, methods::POST, restPath, jsobObj);
	std::cout << "Log level set to : " << response.extract_json(true).get().at(JSON_KEY_LogLevel).as_string() << std::endl;
}

void ArgumentParser::processConfigView()
{
	po::options_description desc("View configurations:");
	desc.add_options()
		COMMON_OPTIONS
		("view,v", "view basic configurations")
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/config";
	http_response resp = requestHttp(true, methods::GET, restPath);
	std::cout << Utility::prettyJson(resp.extract_json(true).get().serialize()) << std::endl;
}

void ArgumentParser::processChangePwd()
{
	po::options_description desc("Change password:");
	desc.add_options()
		COMMON_OPTIONS
		("target,t", po::value<std::string>(), "target user to change passwd")
		("newpasswd,p", po::value<std::string>(), "new password")
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (!m_commandLineVariables.count("target") || !m_commandLineVariables.count("newpasswd"))
	{
		std::cout << desc << std::endl;
		return;
	}

	auto user = m_commandLineVariables["target"].as<std::string>();
	auto passwd = m_commandLineVariables["newpasswd"].as<std::string>();

	std::string restPath = std::string("/appmesh/user/") + user + "/passwd";
	std::map<std::string, std::string> query, headers;
	headers[HTTP_HEADER_JWT_new_password] = Utility::encode64(passwd);
	http_response response = requestHttp(true, methods::POST, restPath, query, nullptr, &headers);
	std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
}

void ArgumentParser::processLockUser()
{
	po::options_description desc("Manage users:");
	desc.add_options()
		COMMON_OPTIONS
		("target,t", po::value<std::string>(), "target user")
		("unlock,k", po::value<bool>(), "lock or unlock user")
		("help,h", "Prints command usage to stdout and exits");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (!m_commandLineVariables.count("target") || !m_commandLineVariables.count("unlock"))
	{
		std::cout << desc << std::endl;
		return;
	}

	auto user = m_commandLineVariables["target"].as<std::string>();
	auto lock = !m_commandLineVariables["lock"].as<bool>();

	std::string restPath = std::string("/appmesh/user/") + user + (lock ? "/lock" : "/unlock");
	http_response response = requestHttp(true, methods::POST, restPath);
	std::cout << GET_STD_STRING(response.extract_utf8string(true).get()) << std::endl;
}

void ArgumentParser::processEncryptUserPwd()
{
	std::vector<std::string> opts = po::collect_unrecognized(m_pasrsedOptions, po::include_positional);
	if (opts.size())
		opts.erase(opts.begin());

	std::string str;
	if (opts.size() == 0)
	{
		std::cin >> str;
		while (str.size())
		{
			std::cout << std::hash<std::string>()(str) << std::endl;
			std::cin >> str;
		}
	}
	else
	{
		for (auto optStr : opts)
		{
			std::cout << std::hash<std::string>()(optStr) << std::endl;
		}
	}
}

bool ArgumentParser::confirmInput(const char *msg)
{
	std::cout << msg << ":";
	std::string result;
	std::cin >> result;
	return result == "y";
}

http_response ArgumentParser::requestHttp(bool throwAble, const method &mtd, const std::string &path)
{
	std::map<std::string, std::string> query;
	return std::move(requestHttp(throwAble, mtd, path, query));
}

http_response ArgumentParser::requestHttp(bool throwAble, const method &mtd, const std::string &path, web::json::value &body)
{
	std::map<std::string, std::string> query;
	return std::move(requestHttp(throwAble, mtd, path, query, &body));
}

http_response ArgumentParser::requestHttp(bool throwAble, const method &mtd, const std::string &path, std::map<std::string, std::string> &query, web::json::value *body, std::map<std::string, std::string> *header)
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
	if (throwAble && response.status_code() != status_codes::OK)
	{
		throw std::invalid_argument(response.extract_utf8string(true).get());
	}
	return std::move(response);
}

http_request ArgumentParser::createRequest(const method &mtd, const std::string &path, std::map<std::string, std::string> &query, std::map<std::string, std::string> *header)
{
	// Build request URI and start the request.
	uri_builder builder(GET_STRING_T(path));
	std::for_each(query.begin(), query.end(), [&builder](const std::pair<std::string, std::string> &pair) {
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

bool ArgumentParser::isAppExist(const std::string &appName)
{
	static auto apps = getAppList();
	return apps.find(appName) != apps.end();
}

std::map<std::string, bool> ArgumentParser::getAppList()
{
	std::map<std::string, bool> apps;
	std::string restPath = "/appmesh/applications";
	auto response = requestHttp(true, methods::GET, restPath);
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
	std::string token;
	// 1. try to get from REST
	if (m_username.length() && m_userpwd.length())
	{
		token = requestToken(m_username, m_userpwd);
	}
	else
	{
		// 2. try to read from token file
		token = readAuthenToken();

		// 3. try to get get default token from REST
		if (token.empty())
		{
			token = requestToken(std::string(JWT_USER_NAME), std::string(JWT_USER_KEY));
		}
	}
	return token;
}

std::string ArgumentParser::getAuthenUser()
{
	std::string token;
	// 1. try to get from REST
	if (m_username.length())
	{
		return m_username;
	}
	else
	{
		// 2. try to read from token file
		token = readAuthenToken();
		// 3. try to get get default token from REST
		if (token.empty())
		{
			token = requestToken(std::string(JWT_USER_NAME), std::string(JWT_USER_KEY));
		}
		auto decoded_token = jwt::decode(token);
		if (decoded_token.has_payload_claim(HTTP_HEADER_JWT_name))
		{
			// get user info
			auto userName = decoded_token.get_payload_claim(HTTP_HEADER_JWT_name).as_string();
			return userName;
		}
		throw std::invalid_argument("Failed to get token");
	}
}

std::string ArgumentParser::getOsUser()
{
	std::string userName;
	struct passwd *pw_ptr;
	if ((pw_ptr = getpwuid(getuid())) != NULL)
	{
		userName = pw_ptr->pw_name;
	}
	else
	{
		throw std::runtime_error("Failed to get current user name");
	}
	return userName;
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

std::string ArgumentParser::requestToken(const std::string &user, const std::string &passwd)
{
	auto protocol = m_sslEnabled ? U("https://") : U("http://");
	auto restURL = (protocol + GET_STRING_T(m_hostname) + ":" + GET_STRING_T(std::to_string(m_listenPort)));
	http_client_config config;
	config.set_validate_certificates(false);
	http_client client(restURL, config);
	http_request requestLogin(web::http::methods::POST);
	uri_builder builder(GET_STRING_T("/appmesh/login"));
	requestLogin.set_request_uri(builder.to_uri());
	requestLogin.headers().add(HTTP_HEADER_JWT_username, Utility::encode64(user));
	requestLogin.headers().add(HTTP_HEADER_JWT_password, Utility::encode64(passwd));
	if (m_tokenTimeoutSeconds)
		requestLogin.headers().add(HTTP_HEADER_JWT_expire_seconds, std::to_string(m_tokenTimeoutSeconds));
	http_response response = client.request(requestLogin).get();
	if (response.status_code() != status_codes::OK)
	{
		throw std::invalid_argument(Utility::stringFormat("Login failed: %s", response.extract_utf8string(true).get().c_str()));
	}
	else
	{
		auto jwtContent = response.extract_json(true).get();
		return GET_JSON_STR_VALUE(jwtContent, HTTP_HEADER_JWT_access_token);
	}
}

void ArgumentParser::printApps(web::json::value json, bool reduce)
{
	boost::io::ios_all_saver guard(std::cout);
	// Title:
	std::cout << std::left;
	std::cout
		<< std::setw(3) << ("id")
		<< std::setw(12) << (JSON_KEY_APP_name)
		<< std::setw(6) << (JSON_KEY_APP_owner)
		<< std::setw(9) << (JSON_KEY_APP_status)
		<< std::setw(7) << (JSON_KEY_APP_health)
		<< std::setw(7) << (JSON_KEY_APP_pid)
		<< std::setw(8) << (JSON_KEY_APP_memory)
		<< std::setw(7) << (JSON_KEY_APP_return)
		<< std::setw(27) << (JSON_KEY_APP_last_start)
		<< (JSON_KEY_APP_command)
		<< std::endl;

	int index = 1;
	auto jsonArr = json.as_array();
	auto reduceFunc = std::bind(&ArgumentParser::reduceStr, this, std::placeholders::_1, std::placeholders::_2);
	std::for_each(jsonArr.begin(), jsonArr.end(), [&index, &reduceFunc, reduce](web::json::value &jobj) {
		const char *slash = "-";
		auto name = GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_name);
		if (reduce)
			name = reduceFunc(name, 12);
		else if (name.length() >= 12)
			name += " ";
		std::cout << std::setw(3) << index++;
		std::cout << std::setw(12) << name;
		std::cout << std::setw(6) << reduceFunc(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_owner), 6);
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
		std::cout << std::setw(27);
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

void ArgumentParser::shiftCommandLineArgs(po::options_description &desc)
{
	m_commandLineVariables.clear();
	std::vector<std::string> opts = po::collect_unrecognized(m_pasrsedOptions, po::include_positional);
	// remove [command] option and parse all others in m_commandLineVariables
	if (opts.size())
		opts.erase(opts.begin());
	po::store(po::command_line_parser(opts).options(desc).run(), m_commandLineVariables);
	po::notify(m_commandLineVariables);
}

std::string ArgumentParser::reduceStr(std::string source, int limit)
{
	if (source.length() >= (std::size_t)limit)
	{
		return std::move(source.substr(0, limit - 2).append("*"));
	}
	else
	{
		return source;
	}
}

std::size_t ArgumentParser::inputSecurePasswd(char **pw, std::size_t sz, int mask, FILE *fp)
{
	if (!pw || !sz || !fp)
		return -1; /* validate input   */
#ifdef MAXPW
	if (sz > MAXPW)
		sz = MAXPW;
#endif

	if (*pw == NULL)
	{
		/* reallocate if no address */
		void *tmp = realloc(*pw, sz * sizeof **pw);
		if (!tmp)
			return -1;
		memset(tmp, 0, sz); /* initialize memory to 0   */
		*pw = (char *)tmp;
	}

	std::size_t idx = 0; /* index, number of chars in read   */
	int c = 0;

	struct termios old_kbd_mode; /* orig keyboard settings   */
	struct termios new_kbd_mode;

	if (tcgetattr(0, &old_kbd_mode))
	{
		/* save orig settings   */
		fprintf(stderr, "%s() error: tcgetattr failed.\n", __func__);
		return -1;
	}
	/* copy old to new */
	memcpy(&new_kbd_mode, &old_kbd_mode, sizeof(struct termios));

	new_kbd_mode.c_lflag &= ~(ICANON | ECHO); /* new kbd flags */
	new_kbd_mode.c_cc[VTIME] = 0;
	new_kbd_mode.c_cc[VMIN] = 1;
	if (tcsetattr(0, TCSANOW, &new_kbd_mode))
	{
		fprintf(stderr, "%s() error: tcsetattr failed.\n", __func__);
		return -1;
	}

	/* read chars from fp, mask if valid char specified */
	while (((c = fgetc(fp)) != '\n' && c != EOF && idx < sz - 1) ||
		   (idx == sz - 1 && c == 127))
	{
		if (c != 127)
		{
			if (31 < mask && mask < 127) /* valid ascii char */
				fputc(mask, stdout);
			(*pw)[idx++] = c;
		}
		else if (idx > 0)
		{
			/* handle backspace (del)   */
			if (31 < mask && mask < 127)
			{
				fputc(0x8, stdout);
				fputc(' ', stdout);
				fputc(0x8, stdout);
			}
			(*pw)[--idx] = 0;
		}
	}
	(*pw)[idx] = 0; /* null-terminate   */

	/* reset original keyboard  */
	if (tcsetattr(0, TCSANOW, &old_kbd_mode))
	{
		fprintf(stderr, "%s() error: tcsetattr failed.\n", __func__);
		return -1;
	}

	if (idx == sz - 1 && c != '\n') /* warn if pw truncated */
		fprintf(stderr, " (%s() warning: truncated at %zu chars.)\n",
				__func__, sz - 1);

	return idx; /* number of chars in passwd    */
}

#include <atomic>
#include <chrono>
#include <csignal>
#include <thread>

#include <ace/Signal.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <boost/algorithm/string/join.hpp>
#include <boost/io/ios_state.hpp>
#include <boost/program_options.hpp>
#include <boost/regex.hpp>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <nlohmann/json.hpp>
#if defined(_WIN32)
#include <tlhelp32.h>
#include <windows.h>
#include <conio.h>
#include <direct.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#endif
#include <linenoise.h>

#include "../common/DateTime.h"
#include "../common/DurationParse.h"
#include "../common/Password.h"
#include "../common/RestClient.h"
#include "../common/Utility.h"
#include "../common/json.hpp"
#include "../common/os/linux.hpp"
#include "ArgumentParser.h"
#include "cmd_args.h"

#define CONNECTION_OPTIONS                                                      \
	po::options_description connection("Connection Options", BOOST_DESC_WIDTH); \
	connection.add_options()													\
	(HOST_URL_ARGS, po::value<std::string>(), (std::string("Server URL [default: ") + m_defaultUrl + "]").c_str())	\
	(FORWARD_TO_ARGS, po::value<std::string>(), "Forward requests to target host[:port]")	\
	(USERNAME_ARGS, po::value<std::string>(), "User name")						\
	(PASSWORD_ARGS, po::value<std::string>(), "User password")

#define OTHER_OPTIONS                                                 	\
	po::options_description other("Other Options", BOOST_DESC_WIDTH); 	\
	other.add_options()													\
	(VERBOSE_ARGS, "Enable verbose output")								\
	(HELP_ARGS, "Display command usage and exit")

#define GET_USER_NAME_PASS                                               	\
	if (m_commandLineVariables.count(USERNAME))                          	\
	{                                                                    	\
		m_username = m_commandLineVariables[USERNAME].as<std::string>(); 	\
		if (m_commandLineVariables.count(PASSWORD))						 	\
		{																 	\
			m_userpwd = m_commandLineVariables[PASSWORD].as<std::string>();	\
		}																	\
		else																\
		{																	\
			m_userpwd = inputPasswd(m_username);										\
		}																	\
	}                                                                    	\
	log4cpp::Category::getRoot().setPriority(m_commandLineVariables.count(VERBOSE) ? log4cpp::Priority::DEBUG : log4cpp::Priority::INFO);

#define HELP_ARG_CHECK_WITH_RETURN                                                                                                  \
	GET_USER_NAME_PASS                                                                                                              \
	if (m_commandLineVariables.count(HELP) > 0)                                                                                     \
	{                                                                                                                               \
		std::cout << desc << std::endl;                                                                                             \
		return;                                                                                                                     \
	}                                                                                                                               \
	m_currentUrl = m_commandLineVariables.count(HOST_URL) == 0 ? m_defaultUrl : m_commandLineVariables[HOST_URL].as<std::string>(); \
	m_forwardTo = m_commandLineVariables.count(FORWARD_TO) == 0 ? "" : m_commandLineVariables[FORWARD_TO].as<std::string>();
#define HELP_ARG_CHECK_WITH_RETURN_ZERO                                                                                             \
	GET_USER_NAME_PASS                                                                                                              \
	if (m_commandLineVariables.count(HELP) > 0)                                                                                     \
	{                                                                                                                               \
		std::cout << desc << std::endl;                                                                                             \
		return 0;                                                                                                                   \
	}                                                                                                                               \
	m_currentUrl = m_commandLineVariables.count(HOST_URL) == 0 ? m_defaultUrl : m_commandLineVariables[HOST_URL].as<std::string>(); \
	m_forwardTo = m_commandLineVariables.count(FORWARD_TO) == 0 ? "" : m_commandLineVariables[FORWARD_TO].as<std::string>();
// Each user should have its own token path
static std::string m_tokenFile = std::string(ACE_OS::getenv("HOME") ? ACE_OS::getenv("HOME") : ".") + "/.appmesh.config";
const static std::string m_shellHistoryFile = std::string(ACE_OS::getenv("HOME") ? ACE_OS::getenv("HOME") : ".") + "/.appmesh.shell.history";
extern char **environ;

// Global variable for appc exec
static std::atomic_bool g_interrupt(false);
static std::string APPC_EXEC_APP_NAME;
static ArgumentParser *WORK_PARSE = nullptr;
// command line help width
static size_t BOOST_DESC_WIDTH = 130;

ArgumentParser::ArgumentParser(int argc, char *argv[])
	: m_argc(argc), m_argv(argv), m_tokenTimeoutSeconds(DEFAULT_TOKEN_EXPIRE_SECONDS)
{
	const std::string posixTimeZone = ACE_OS::getenv(ENV_APPMESH_POSIX_TIMEZONE) ? ACE_OS::getenv(ENV_APPMESH_POSIX_TIMEZONE) : getPosixTimezone();
	Utility::initDateTimeZone(posixTimeZone, false);
}

void ArgumentParser::initArgs()
{
	WORK_PARSE = this;
	m_defaultUrl = this->getAppMeshUrl();
#if !defined(_WIN32)
	static std::atomic_flag flag = ATOMIC_FLAG_INIT;
	if (!flag.test_and_set(std::memory_order_acquire) && getuid() == 0 && getenv("SUDO_USER") && getpwnam(getenv("SUDO_USER")))
	{
		m_tokenFile = std::string(getpwnam(getenv("SUDO_USER"))->pw_dir) + "/.appmesh.config";
		int unused = seteuid(getpwnam(getenv("SUDO_USER"))->pw_uid);
		(void)unused;
	}
#endif
	po::options_description global("Global options", BOOST_DESC_WIDTH);
	global.add_options()("command", po::value<std::string>(), "Command to execute.")("subargs", po::value<std::vector<std::string>>(), "Arguments for command.");

	po::positional_options_description pos;
	pos.add("command", 1).add("subargs", -1);

	// parse [command] and all other arguments in [subargs]
	auto parsed = po::command_line_parser(m_argc, m_argv).options(global).positional(pos).allow_unregistered().run();
	m_parsedOptions = parsed.options;
	po::store(parsed, m_commandLineVariables);
	po::notify(m_commandLineVariables);
}

ArgumentParser::~ArgumentParser()
{
	unregSignal();
	WORK_PARSE = nullptr;
}

int ArgumentParser::parse()
{
	initArgs();
	int result = 0;
	if (m_commandLineVariables.size() == 0)
	{
		printMainHelp();
		return result;
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
	else if (cmd == "add" || cmd == "reg")
	{
		processAppAdd();
	}
	else if (cmd == "rm" || cmd == "remove" || cmd == "unreg")
	{
		processAppDel();
	}
	else if (cmd == "view" || cmd == "list" || cmd == "ls")
	{
		processAppView();
	}
	else if (cmd == "resource")
	{
		processResource();
	}
	else if (cmd == "enable")
	{
		processAppControl(true);
	}
	else if (cmd == "disable")
	{
		processAppControl(false);
	}
	else if (cmd == "restart")
	{
		auto tmpOpts = m_parsedOptions;
		processAppControl(false);
		m_parsedOptions = tmpOpts;
		processAppControl(true);
	}
	else if (cmd == "run")
	{
		return processAppRun();
	}
	else if (cmd == "exec" || cmd == "shell")
	{
		return processShell();
	}
	else if (cmd == "get")
	{
		processFileDownload();
	}
	else if (cmd == "put")
	{
		processFileUpload();
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
		processUserChangePwd();
	}
	else if (cmd == "mfa")
	{
		processUserMfa();
	}
	else if (cmd == "lock")
	{
		processUserLock();
	}
	else if (cmd == "user")
	{
		processUserManage();
	}
	else if (cmd == "appmgpwd")
	{
		processUserPwdEncrypt();
	}
	else if (cmd == "appmginit")
	{
		initRadomPassword();
	}
	else
	{
		printMainHelp();
	}
	return result;
}

void ArgumentParser::printMainHelp()
{
	std::cout << "App Mesh CLI - Command Line Interface" << std::endl;
	std::cout << "Usage: appc [COMMAND] [ARG...] [flags]" << std::endl
			  << std::endl;

	std::cout << "Authentication Commands:" << std::endl;
	std::cout << "  logon         Log in to App Mesh for a specified duration" << std::endl;
	std::cout << "  logoff        Clear current user session" << std::endl;
	std::cout << "  loginfo       Display current logged-in user" << std::endl;
	std::cout << "  passwd        Change user password" << std::endl;
	std::cout << "  lock          Lock or unlock a user" << std::endl;
	std::cout << "  user          View user information" << std::endl;
	std::cout << "  mfa           Manage two-factor authentication" << std::endl
			  << std::endl;

	std::cout << "Application Management:" << std::endl;
	std::cout << "  view          List all applications" << std::endl;
	std::cout << "  add           Add a new application" << std::endl;
	std::cout << "  rm            Remove an application" << std::endl;
	std::cout << "  enable        Enable an application" << std::endl;
	std::cout << "  disable       Disable an application" << std::endl;
	std::cout << "  restart       Restart an application" << std::endl
			  << std::endl;

	std::cout << "Execution Commands:" << std::endl;
	std::cout << "  run           Execute commands or applications and retrieve output" << std::endl;
	std::cout << "  shell         Execute commands with shell context emulation" << std::endl
			  << std::endl;

	std::cout << "System Management:" << std::endl;
	std::cout << "  resource      Show host resources" << std::endl;
	std::cout << "  label         Manage host labels" << std::endl;
	std::cout << "  config        Manage configurations" << std::endl;
	std::cout << "  log           Set log level" << std::endl
			  << std::endl;

	std::cout << "File Operations:" << std::endl;
	std::cout << "  get           Download a remote file" << std::endl;
	std::cout << "  put           Upload a local file to server" << std::endl
			  << std::endl;

	std::cout << "Additional Information:" << std::endl;
	std::cout << "  - Remote CLI use '-H [ --host-url ]' (e.g., -H https://127.0.0.1:6060)" << std::endl;
	std::cout << "  - Use '-h [ --help ]' flag for detailed usage" << std::endl
			  << std::endl;
}

void ArgumentParser::processLogon()
{
	po::options_description desc("Login to App Mesh \nUsage: appc logon [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description authenticate("Authentication Options", BOOST_DESC_WIDTH);
	authenticate.add_options()
	(TIMEOUT_ARGS, po::value<std::string>()->default_value(std::to_string(DEFAULT_TOKEN_EXPIRE_SECONDS)), "Session duration in seconds or ISO 8601 format [default: PT7D]")
	(AUDIENCE_ARGS, po::value<std::string>()->default_value(HTTP_HEADER_JWT_Audience_appmesh), "JWT Audience [default: 'appmesh-service']");
	OTHER_OPTIONS;
	desc.add(connection).add(authenticate).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	m_tokenTimeoutSeconds = DurationParse::parse(m_commandLineVariables[TIMEOUT].as<std::string>());
	m_audience = m_commandLineVariables[AUDIENCE].as<std::string>();
	if (!m_commandLineVariables.count(USERNAME))
	{
		while (m_username.length() == 0)
		{
			std::cout << "User: ";
			std::cin >> m_username;
			m_username = Utility::stdStringTrim(m_username);
		}
	}
	else
	{
		m_username = m_commandLineVariables[USERNAME].as<std::string>();
	}

	{
		if (!m_commandLineVariables.count(USERNAME))
		{
			std::cin.clear();
			std::cin.ignore(1024, '\n');
		}
		if (m_userpwd.empty())
		{
			m_userpwd = inputPasswd(m_username);
		}
	}

	// get token from REST
	m_jwtToken = getAuthenToken();

	// write token to disk
	if (m_jwtToken.length())
	{
		persistAuthToken(parseUrlHost(m_currentUrl), m_jwtToken);
		std::cout << "User <" << m_username << "> logon to <" << m_currentUrl << "> success." << std::endl;
	}
}

void ArgumentParser::processLogoff()
{
	po::options_description desc("Logoff to App Mesh \nUsage: appc logoff [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	OTHER_OPTIONS;
	desc.add(connection).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/self/logoff";
	auto response = requestHttp(true, web::http::methods::POST, restPath);
	if (response->status_code == web::http::status_codes::OK)
	{
		persistAuthToken(parseUrlHost(m_currentUrl), std::string());
		std::cout << "User logoff from " << m_currentUrl << " success." << std::endl;
	}
}

void ArgumentParser::processLoginfo()
{
	po::options_description desc("Print current login user \nUsage: appc loginfo [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	OTHER_OPTIONS;
	desc.add(connection).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::cout << getLoginUser() << std::endl;
}

std::string ArgumentParser::getLoginUser()
{
	std::string userName;
	auto token = getAuthenToken();
	if (token.length())
	{
		auto decodedToken = jwt::decode(token);
		if (decodedToken.has_subject())
		{
			// get user info
			userName = decodedToken.get_subject();
		}
	}
	return userName;
}

// appName is null means this is a normal application (not a shell application)
void ArgumentParser::processAppAdd()
{
	po::options_description desc("Register a new application \nUsage: appc add [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description basic("Basic Configuration Options", BOOST_DESC_WIDTH);
	basic.add_options()
	(APP_ARGS, po::value<std::string>(), "Application name (required)")
	(COMMAND_ARGS, po::value<std::string>(), "Command line with arguments (required)")
	(WORKING_DIR_ARGS, po::value<std::string>(), "Working directory path")
	(DESC_ARGS, po::value<std::string>(), "Application description")
	(STATUS_ARGS, po::value<bool>()->default_value(true), "Initial status (true=enabled, false=disabled)");
	po::options_description runtime("Runtime Options", BOOST_DESC_WIDTH);
	runtime.add_options()
	(SHELL_ARGS, "Enable shell mode for multiple commands")
	(SESSION_LOGIN_ARGS, "Execute with session login context")
	(HEALTHCHECK_ARGS, po::value<std::string>(), "Health check command (returns 0 for healthy)")
	(DOCKER_IMAGE_ARGS, po::value<std::string>(), "Docker image for containerized execution")
	(PID_ARGS, po::value<int>(), "Attach to existing process ID");
	po::options_description schedule("Schedule Options", BOOST_DESC_WIDTH);
	schedule.add_options()
	(BEGIN_TIME_ARGS, po::value<std::string>(), "Start time (ISO8601: '2020-10-11T09:22:05')")
	(END_TIME_ARGS, po::value<std::string>(), "End time (ISO8601: '2020-10-11T10:22:05')")
	(DAILY_BEGIN_ARGS, po::value<std::string>(), "Daily start time ('09:00:00+08')")
	(DAILY_END_ARGS, po::value<std::string>(), "Daily end time ('20:00:00+08')")
	(INTERVAL_ARGS, po::value<std::string>(), "Start interval (ISO8601 duration or cron: 'P1Y2M3DT4H5M6S', '* */5 * * * *')")
	(CRON_ARGS, "Use cron expression for interval");
	po::options_description resource("Resource Limits Options", BOOST_DESC_WIDTH);
	resource.add_options()
	(MEMORY_LIMIT_ARGS, po::value<int>(), "Memory limit (MB)")
	(VIRTUAL_MEMORY_ARGS, po::value<int>(), "Virtual memory limit (MB)")
	(CPU_SHARES_ARGS, po::value<int>(), "CPU shares (relative weight)")
	(LOG_CACHE_SIZE_ARGS, po::value<int>()->default_value(3), "Number of stdout cache files");
	po::options_description advanced("Advanced Options", BOOST_DESC_WIDTH);
	advanced.add_options()
	(PERMISSION_ARGS, po::value<int>(), "Permission bits [group & other] (1=deny, 2=read, 3=write)")
	(METADATA_ARGS, po::value<std::string>(), "Metadata string/JSON (stdin input, '@' for file input)")
	(ENV_ARGS, po::value<std::vector<std::string>>(), "Environment variables (-e env1=value1 -e env2=value2, APP_DOCKER_OPTS env is used to input docker run parameters)")
	(SECURITY_ENV_ARGS, po::value<std::vector<std::string>>(), "Encrypted environment variables in server side with application owner's cipher")
	(STOP_TIMEOUT_ARGS, po::value<std::string>(), "Process stop timeout (ISO8601 duration: 'P1Y2M3DT4H5M6S')")
	(EXIT_ARGS, po::value<std::string>()->default_value(JSON_KEY_APP_behavior_standby), "Exit behavior [restart|standby|keepalive|remove]")
	(CONTROL_ARGS, po::value<std::vector<std::string>>(), "Exit code behaviors (--control CODE:ACTION, overrides default value 0:standby)")
	(STDIN_ARGS, po::value<std::string>(), "Read YAML from stdin ('std') or file");
	OTHER_OPTIONS;
	other.add_options()
	(FORCE_ARGS, "Skip confirmation prompts");
	desc.add(connection).add(basic).add(runtime).add(schedule).add(resource).add(advanced).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	const std::string default_control_string = "0:standby";
	if (m_commandLineVariables.count(STDIN) == 0 && (m_commandLineVariables.count(APP) == 0 ||
													 (m_commandLineVariables.count(DOCKER_IMAGE) == 0 && m_commandLineVariables.count(COMMAND) == 0)))
	{
		std::cout << desc << std::endl;
		return;
	}

	if (m_commandLineVariables.count(INTERVAL) > 0 && m_commandLineVariables.count(STOP_TIMEOUT) > 0)
	{
		if (DurationParse::parse(m_commandLineVariables[INTERVAL].as<std::string>()) <=
			DurationParse::parse(m_commandLineVariables[STOP_TIMEOUT].as<std::string>()))
		{
			std::cout << "The stop-timeout seconds must less than interval." << std::endl;
			return;
		}
	}
	nlohmann::json jsonObj;
	if (m_commandLineVariables.count(STDIN))
	{
		const auto inputJson = m_commandLineVariables[STDIN].as<std::string>();
		std::string inputContent;
		if (inputJson == "std")
			inputContent = Utility::readStdin2End();
		else
			inputContent = Utility::readFileCpp(inputJson);
		// parse yaml
		jsonObj = Utility::yamlToJson(YAML::Load(inputContent));
	}

	std::string appName;
	if (m_commandLineVariables.count(STDIN))
	{
		if (!HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_name))
		{
			std::cout << "Can not find application name" << std::endl;
			return;
		}
		appName = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_name);
	}
	else
	{
		if (m_commandLineVariables.count(APP) == 0)
		{
			std::cout << "Can not find application name" << std::endl;
			return;
		}
		appName = m_commandLineVariables[APP].as<std::string>();
	}

	if (isAppExist(appName))
	{
		if (m_commandLineVariables.count(FORCE) == 0 && (m_commandLineVariables.count(STDIN) == 0 || m_commandLineVariables[STDIN].as<std::string>() != "std"))
		{
			std::cout << "Application already exist, are you sure you want to update the application <" << appName << ">?" << std::endl;
			if (!confirmInput("[y/n]:"))
			{
				return;
			}
		}
	}

	if (m_commandLineVariables.count(EXIT))
	{
		auto hebavior = m_commandLineVariables[EXIT].as<std::string>();
		if (hebavior == JSON_KEY_APP_behavior_standby ||
			hebavior == JSON_KEY_APP_behavior_restart ||
			hebavior == JSON_KEY_APP_behavior_keepalive ||
			hebavior == JSON_KEY_APP_behavior_remove)
		{
			nlohmann::json jsonBehavior;
			jsonBehavior[JSON_KEY_APP_behavior_exit] = std::string(hebavior);
			jsonObj[JSON_KEY_APP_behavior] = jsonBehavior;
		}
		else
		{
			throw std::invalid_argument(Utility::stringFormat("invalid behavior <%s> for <exit> event", hebavior.c_str()));
		}
	}
	if (m_commandLineVariables.count(CONTROL))
	{
		auto controls = m_commandLineVariables[CONTROL].as<std::vector<std::string>>();
		if (controls.size() == 0)
			controls.push_back(default_control_string);
		nlohmann::json objControl = nlohmann::json::object();
		for (const auto &control : controls)
		{
			auto find = control.find_first_of(':');
			if (find != std::string::npos)
			{
				auto code = Utility::stdStringTrim(control.substr(0, find));
				auto hebavior = Utility::stdStringTrim(control.substr(find + 1));
				if (hebavior == JSON_KEY_APP_behavior_standby ||
					hebavior == JSON_KEY_APP_behavior_restart ||
					hebavior == JSON_KEY_APP_behavior_keepalive ||
					hebavior == JSON_KEY_APP_behavior_remove)
				{
					objControl[code] = std::string(hebavior);
				}
				else
				{
					throw std::invalid_argument(Utility::stringFormat("invalid behavior <%s> for <exit> event", hebavior.c_str()));
				}
			}
		}
		jsonObj[JSON_KEY_APP_behavior][JSON_KEY_APP_behavior_control] = objControl;
	}
	if (m_commandLineVariables.count(APP))
		jsonObj[JSON_KEY_APP_name] = std::string(m_commandLineVariables[APP].as<std::string>());
	if (m_commandLineVariables.count(COMMAND))
		jsonObj[JSON_KEY_APP_command] = std::string(m_commandLineVariables[COMMAND].as<std::string>());
	if (m_commandLineVariables.count(DESC))
		jsonObj[JSON_KEY_APP_description] = std::string(m_commandLineVariables[DESC].as<std::string>());
	jsonObj[JSON_KEY_APP_shell_mode] = (m_commandLineVariables.count(SHELL) > 0);
	jsonObj[JSON_KEY_APP_session_login] = (m_commandLineVariables.count(SESSION_LOGIN) > 0);
	if (m_commandLineVariables.count(HEALTHCHECK))
		jsonObj[JSON_KEY_APP_health_check_cmd] = std::string(m_commandLineVariables[HEALTHCHECK].as<std::string>());
	if (m_commandLineVariables.count(PERMISSION))
		jsonObj[JSON_KEY_APP_owner_permission] = (m_commandLineVariables[PERMISSION].as<int>());
	if (m_commandLineVariables.count(WORKING_DIR))
		jsonObj[JSON_KEY_APP_working_dir] = std::string(m_commandLineVariables[WORKING_DIR].as<std::string>());
	if (m_commandLineVariables.count(STATUS))
		jsonObj[JSON_KEY_APP_status] = (m_commandLineVariables[STATUS].as<bool>() ? 1 : 0);
	if (m_commandLineVariables.count(METADATA))
	{
		auto metaData = m_commandLineVariables[METADATA].as<std::string>();
		if (metaData.length())
		{
			if (metaData[0] == '@')
			{
				auto fileName = metaData.substr(1);
				if (!Utility::isFileExist(fileName))
				{
					throw std::invalid_argument(Utility::stringFormat("input file %s does not exist", fileName.c_str()));
				}
				metaData = Utility::readFile(fileName);
			}
			try
			{
				// try to load as JSON first
				jsonObj[JSON_KEY_APP_metadata] = nlohmann::json::parse(metaData);
			}
			catch (...)
			{
				// use text field in case of not JSON format
				jsonObj[JSON_KEY_APP_metadata] = std::string(metaData);
			}
		}
	}
	if (m_commandLineVariables.count(DOCKER_IMAGE))
		jsonObj[JSON_KEY_APP_docker_image] = std::string(m_commandLineVariables[DOCKER_IMAGE].as<std::string>());
	if (m_commandLineVariables.count(BEGIN_TIME))
		jsonObj[JSON_KEY_SHORT_APP_start_time] = (std::chrono::duration_cast<std::chrono::seconds>(DateTime::parseISO8601DateTime(m_commandLineVariables[BEGIN_TIME].as<std::string>()).time_since_epoch()).count());
	if (m_commandLineVariables.count(END_TIME))
		jsonObj[JSON_KEY_SHORT_APP_end_time] = (std::chrono::duration_cast<std::chrono::seconds>(DateTime::parseISO8601DateTime(m_commandLineVariables[END_TIME].as<std::string>()).time_since_epoch()).count());
	if (m_commandLineVariables.count(INTERVAL))
	{
		jsonObj[JSON_KEY_SHORT_APP_start_interval_seconds] = std::string(m_commandLineVariables[INTERVAL].as<std::string>());
		jsonObj[JSON_KEY_SHORT_APP_cron_interval] = (m_commandLineVariables.count(CRON) > 0);
	}
	if (m_commandLineVariables.count(STOP_TIMEOUT))
		jsonObj[JSON_KEY_APP_retention] = std::string(m_commandLineVariables[STOP_TIMEOUT].as<std::string>());
	if (m_commandLineVariables.count(LOG_CACHE_SIZE))
		jsonObj[JSON_KEY_APP_stdout_cache_num] = (m_commandLineVariables[LOG_CACHE_SIZE].as<int>());
	if (m_commandLineVariables.count(DAILY_BEGIN) && m_commandLineVariables.count(DAILY_END))
	{
		nlohmann::json objDailyLimitation = nlohmann::json::object();
		objDailyLimitation[JSON_KEY_DAILY_LIMITATION_daily_start] = (DateTime::parseDayTimeUtcDuration(m_commandLineVariables[DAILY_BEGIN].as<std::string>()).total_seconds());
		objDailyLimitation[JSON_KEY_DAILY_LIMITATION_daily_end] = (DateTime::parseDayTimeUtcDuration(m_commandLineVariables[DAILY_END].as<std::string>()).total_seconds());
		jsonObj[JSON_KEY_APP_daily_limitation] = objDailyLimitation;
	}

	if (m_commandLineVariables.count(MEMORY_LIMIT) || m_commandLineVariables.count(VIRTUAL_MEMORY) ||
		m_commandLineVariables.count(CPU_SHARES))
	{
		nlohmann::json objResourceLimitation = nlohmann::json::object();
		if (m_commandLineVariables.count(MEMORY_LIMIT))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_memory_mb] = (m_commandLineVariables[MEMORY_LIMIT].as<int>());
		if (m_commandLineVariables.count(VIRTUAL_MEMORY))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb] = (m_commandLineVariables[VIRTUAL_MEMORY].as<int>());
		if (m_commandLineVariables.count(CPU_SHARES))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_cpu_shares] = (m_commandLineVariables[CPU_SHARES].as<int>());
		jsonObj[JSON_KEY_APP_resource_limit] = objResourceLimitation;
	}

	if (m_commandLineVariables.count(ENV))
	{
		std::vector<std::string> envs = m_commandLineVariables[ENV].as<std::vector<std::string>>();
		if (envs.size())
		{
			nlohmann::json objEnvs = nlohmann::json::object();
			for (auto &env : envs)
			{
				auto find = env.find_first_of('=');
				if (find != std::string::npos)
				{
					auto key = Utility::stdStringTrim(env.substr(0, find));
					auto val = Utility::stdStringTrim(env.substr(find + 1));
					objEnvs[key] = std::string(val);
				}
				else
				{
					throw std::invalid_argument(Utility::stringFormat("Invalid environment variable format: %s", env.c_str()));
				}
			}
			jsonObj[JSON_KEY_APP_env] = objEnvs;
		}
	}
	if (m_commandLineVariables.count(SECURITY_ENV))
	{
		std::vector<std::string> envs = m_commandLineVariables[SECURITY_ENV].as<std::vector<std::string>>();
		if (envs.size())
		{
			nlohmann::json objEnvs = nlohmann::json::object();
			for (auto &env : envs)
			{
				auto find = env.find_first_of('=');
				if (find != std::string::npos)
				{
					auto key = Utility::stdStringTrim(env.substr(0, find));
					auto val = Utility::stdStringTrim(env.substr(find + 1));
					objEnvs[key] = std::string(val);
				}
			}
			jsonObj[JSON_KEY_APP_sec_env] = objEnvs;
		}
	}
	if (m_commandLineVariables.count(PID))
		jsonObj[JSON_KEY_APP_pid] = (m_commandLineVariables[PID].as<int>());
	std::string restPath = std::string("/appmesh/app/") + appName;
	auto resp = requestHttp(true, web::http::methods::PUT, restPath, &jsonObj);
	std::cout << Utility::jsonToYaml(nlohmann::json::parse(resp->text)) << std::endl;
}

void ArgumentParser::processAppDel()
{
	po::options_description desc("Remove an application \nUsage: appc rm [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description app("Application Options", BOOST_DESC_WIDTH);
	app.add_options()
	(APP_ARGS, po::value<std::vector<std::string>>(), "One or more application names to remove");
	OTHER_OPTIONS;
	other.add_options()
	(FORCE_ARGS, "Skip confirmation prompts");
	desc.add(connection).add(app).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count(APP) == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	auto appNames = m_commandLineVariables[APP].as<std::vector<std::string>>();
	for (auto &appName : appNames)
	{
		if (isAppExist(appName))
		{
			if (m_commandLineVariables.count(FORCE) == 0)
			{
				std::string msg = std::string("Are you sure you want to remove the application <") + appName + "> ? [y/n]";
				if (confirmInput(msg.c_str()))
				{
					std::string restPath = std::string("/appmesh/app/") + appName;
					auto response = requestHttp(true, web::http::methods::DEL, restPath);
					std::cout << parseOutputMessage(response) << std::endl;
				}
			}
		}
		else
		{
			throw std::invalid_argument(Utility::stringFormat("No such application <%s>", appName.c_str()));
		}
	}
}

void ArgumentParser::processAppView()
{
	po::options_description desc("List applications \nUsage: appc ls [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description display("Display Options", BOOST_DESC_WIDTH);
	display.add_options()
	(LONG_ARGS, "Show detailed information")
	(SHOW_OUTPUT_ARGS, "View application output")
	(PSTREE_ARGS, "Display process tree");
	po::options_description filtering("Filtering Options", BOOST_DESC_WIDTH);
	filtering.add_options()
	(APP_ARGS, po::value<std::string>(), "Application name")
	(LOG_INDEX_ARGS, po::value<int>(), "Specify output log index");
	po::options_description output("Output Options", BOOST_DESC_WIDTH);
	output.add_options()
	(FOLLOW_ARGS, "Follow output in real-time")
	(JSON_ARGS, "Output in JSON format");
	OTHER_OPTIONS;
	desc.add(connection).add(display).add(filtering).add(output).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	bool reduce = !(m_commandLineVariables.count(LONG));
	if (m_commandLineVariables.count(APP) > 0)
	{
		if (!m_commandLineVariables.count(SHOW_OUTPUT))
		{
			std::string restPath = std::string("/appmesh/app/") + m_commandLineVariables[APP].as<std::string>();
			auto resp = nlohmann::json::parse(requestHttp(true, web::http::methods::GET, restPath)->text);
			if (m_commandLineVariables.count(PSTREE))
			{
				// view app process tree
				if (HAS_JSON_FIELD(resp, JSON_KEY_APP_pstree))
				{
					std::cout << resp.at(JSON_KEY_APP_pstree).get<std::string>() << std::endl;
				}
			}
			else
			{
				Utility::addExtraAppTimeReferStr(resp);
				if (m_commandLineVariables.count(JJSON))
					std::cout << JSON::dumpToLocalEncoding(resp, 2) << std::endl;
				else
					std::cout << Utility::jsonToYaml(resp) << std::endl;
			}
		}
		else
		{
			// view app output
			int index = 0;
			std::string restPath = std::string("/appmesh/app/") + m_commandLineVariables[APP].as<std::string>() + "/output";
			if (m_commandLineVariables.count(LOG_INDEX))
			{
				index = m_commandLineVariables[LOG_INDEX].as<int>();
			}
			long outputPosition = 0;
			bool exit = false;
			std::map<std::string, std::string> query;
			query[HTTP_QUERY_KEY_stdout_index] = std::to_string(index);
			query[HTTP_QUERY_KEY_stdout_timeout] = std::to_string(1);
			while (!exit)
			{
				query[HTTP_QUERY_KEY_stdout_position] = std::to_string(outputPosition);
				auto response = requestHttp(true, web::http::methods::GET, restPath, nullptr, {}, query);
				std::cout << response->text << std::flush;
				if (m_commandLineVariables.count(FOLLOW) == 0)
					break;
				outputPosition = response->header.count(HTTP_HEADER_KEY_output_pos) ? std::atol(response->header.find(HTTP_HEADER_KEY_output_pos)->second.c_str()) : outputPosition;
				// check continues failure
				exit = response->header.count(HTTP_HEADER_KEY_exit_code);
			}
		}
	}
	else
	{
		std::string restPath = "/appmesh/applications";
		auto response = requestHttp(true, web::http::methods::GET, restPath);
		printApps(nlohmann::json::parse(response->text), reduce);
	}
}

void ArgumentParser::processResource()
{
	po::options_description desc("View host resource \nUsage: appc resource [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	OTHER_OPTIONS;
	desc.add(connection).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/resources";
	auto resp = requestHttp(true, web::http::methods::GET, restPath);
	std::cout << JSON::dumpToLocalEncoding(nlohmann::json::parse(resp->text), 2) << std::endl;
}

void ArgumentParser::processAppControl(bool start)
{
	std::string action = start ? "Enable" : "Disable";
	po::options_description desc(action + " applications \nUsage: appc enable/disable [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description app("Application Options", BOOST_DESC_WIDTH);
	app.add_options()
	(APP_ARGS, po::value<std::vector<std::string>>(), "One or more application names to remove")
	(ALL_ARGS, "Apply to all applications.");
	OTHER_OPTIONS;
	desc.add(connection).add(app).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	if (m_commandLineVariables.empty() || (!m_commandLineVariables.count(ALL) && !m_commandLineVariables.count(APP)))
	{
		std::cout << desc << std::endl;
		return;
	}
	std::vector<std::string> appList;
	bool all = m_commandLineVariables.count(ALL);
	if (all)
	{
		auto appMap = this->getAppList();
		std::for_each(appMap.begin(), appMap.end(), [&appList, &start](const std::pair<std::string, bool> &pair)
					  {
			if (start != pair.second)
			{
				appList.push_back(pair.first);
			} });
	}
	else
	{
		auto appNames = m_commandLineVariables[APP].as<std::vector<std::string>>();
		for (auto &appName : appNames)
		{
			if (!isAppExist(appName))
			{
				throw std::invalid_argument(Utility::stringFormat("No such application <%s>", appName.c_str()));
			}
			appList.push_back(appName);
		}
	}
	for (auto &app : appList)
	{
		std::string restPath = std::string("/appmesh/app/") + app + "/" + (start ? HTTP_QUERY_KEY_action_start : HTTP_QUERY_KEY_action_stop);
		auto response = requestHttp(true, web::http::methods::POST, restPath);
		std::cout << parseOutputMessage(response) << std::endl;
	}
	if (appList.size() == 0)
	{
		std::cout << "No application processed." << std::endl;
	}
}

int ArgumentParser::processAppRun()
{
	po::options_description desc("Run commands or applications \nUsage: appc run [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description application("Application Options", BOOST_DESC_WIDTH);
	application.add_options()
	(APP_ARGS, po::value<std::string>(), "Existing application name to run, or specify a name for a new run; defaults to a random name if empty.")
	(DESC_ARGS, po::value<std::string>(), "Application description.")
	(COMMAND_ARGS, po::value<std::string>(), "Full command line with arguments (not needed for running an application).")
	(WORKING_DIR_ARGS, po::value<std::string>(), "Working directory (default '/opt/appmesh/work').")
	(METADATA_ARGS, po::value<std::string>(), "Metadata string/JSON (input for application, passed to process stdin), '@' allowed to read from file.")
	(ENV_ARGS, po::value<std::vector<std::string>>(), "Environment variables (e.g., -e env1=value1 -e env2=value2).");
	po::options_description execution("Execution Options", BOOST_DESC_WIDTH);
	execution.add_options()
	(SHELL_ARGS, "Use shell mode; cmd can be multiple shell commands in string format.")
	(SESSION_LOGIN_ARGS, "Run with session login.")
	(LIFETIME_ARGS, po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_LIFECYCLE_SECONDS)), "Maximum lifecycle time (in seconds) for the command run. Default is 12 hours; supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').")
	(TIMEOUT_ARGS, po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_TIMEOUT_SECONDS)), "Maximum time (in seconds) for the command run. Greater than 0 means output can be printed repeatedly, less than 0 means output will be printed until the process exits; supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').");
	OTHER_OPTIONS;
	desc.add(connection).add(application).add(execution).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN_ZERO;

	int returnCode = 0;
	if (m_commandLineVariables.count(HELP) || (m_commandLineVariables.count(APP) == 0 && m_commandLineVariables.count(COMMAND) == 0))
	{
		std::cout << desc << std::endl;
		return returnCode;
	}

	std::map<std::string, std::string> query;
	int timeout = DurationParse::parse(m_commandLineVariables[TIMEOUT].as<std::string>());
	int lifecycle = DurationParse::parse(m_commandLineVariables[LIFETIME].as<std::string>());
	query[HTTP_QUERY_KEY_timeout] = std::to_string(std::abs(timeout));
	query[HTTP_QUERY_KEY_lifecycle] = std::to_string(std::abs(lifecycle));

	nlohmann::json jsonObj;
	nlohmann::json jsonBehavior;
	jsonBehavior[JSON_KEY_APP_behavior_exit] = std::string(JSON_KEY_APP_behavior_remove);
	jsonObj[JSON_KEY_APP_behavior] = std::move(jsonBehavior);
	if (m_commandLineVariables.count(COMMAND))
		jsonObj[JSON_KEY_APP_command] = std::string(m_commandLineVariables[COMMAND].as<std::string>());
	if (m_commandLineVariables.count(DESC))
		jsonObj[JSON_KEY_APP_description] = std::string(m_commandLineVariables[DESC].as<std::string>());
	jsonObj[JSON_KEY_APP_shell_mode] = (m_commandLineVariables.count(SHELL) > 0);
	jsonObj[JSON_KEY_APP_session_login] = (m_commandLineVariables.count(SESSION_LOGIN) > 0);
	if (m_commandLineVariables.count(APP))
		jsonObj[JSON_KEY_APP_name] = std::string(m_commandLineVariables[APP].as<std::string>());
	if (m_commandLineVariables.count(METADATA))
	{
		auto metaData = m_commandLineVariables[METADATA].as<std::string>();
		if (metaData.length())
		{
			if (metaData[0] == '@')
			{
				auto fileName = metaData.substr(1);
				if (!Utility::isFileExist(fileName))
				{
					throw std::invalid_argument(Utility::stringFormat("input file %s does not exist", fileName.c_str()));
				}
				metaData = Utility::readFile(fileName);
			}
			try
			{
				// try to load as JSON first
				jsonObj[JSON_KEY_APP_metadata] = nlohmann::json::parse(metaData);
			}
			catch (...)
			{
				// use text field in case of not JSON format
				jsonObj[JSON_KEY_APP_metadata] = std::string(metaData);
			}
		}
	}
	if (m_commandLineVariables.count(WORKING_DIR))
		jsonObj[JSON_KEY_APP_working_dir] = std::string(m_commandLineVariables[WORKING_DIR].as<std::string>());
	if (m_commandLineVariables.count(ENV))
	{
		std::vector<std::string> envs = m_commandLineVariables[ENV].as<std::vector<std::string>>();
		if (envs.size())
		{
			nlohmann::json objEnvs = nlohmann::json::object();
			for (auto &env : envs)
			{
				auto find = env.find_first_of('=');
				if (find != std::string::npos)
				{
					auto key = Utility::stdStringTrim(env.substr(0, find));
					auto val = Utility::stdStringTrim(env.substr(find + 1));
					objEnvs[key] = std::string(val);
				}
			}
			jsonObj[JSON_KEY_APP_env] = objEnvs;
		}
	}

	if (timeout < 0)
	{
		// Use syncrun directly
		// /app/syncrun?timeout=5
		std::string restPath = "/appmesh/app/syncrun";
		auto response = requestHttp(true, web::http::methods::POST, restPath, &jsonObj, {}, query);
		std::cout << response->text << std::flush;
		returnCode = response->header.count(HTTP_HEADER_KEY_exit_code) ? std::atoi(response->header.find(HTTP_HEADER_KEY_exit_code)->second.c_str()) : returnCode;
	}
	else
	{
		returnCode = runAsyncApp(jsonObj, timeout, lifecycle);
	}
	return returnCode;
}

int ArgumentParser::runAsyncApp(nlohmann::json &jsonObj, int timeoutSeconds, int lifeCycleSeconds)
{
	std::map<std::string, std::string> query;
	query[HTTP_QUERY_KEY_timeout] = std::to_string(timeoutSeconds);
	query[HTTP_QUERY_KEY_lifecycle] = std::to_string(lifeCycleSeconds);
	int returnCode = -99;
	if (1)
	{
		// Use run and output
		// /app/run?timeout=5
		std::string restPath = "/appmesh/app/run";
		auto response = requestHttp(true, web::http::methods::POST, restPath, &jsonObj, {}, query);
		auto result = nlohmann::json::parse(response->text);
		auto appName = result[JSON_KEY_APP_name].get<std::string>();
		auto process_uuid = result[HTTP_QUERY_KEY_process_uuid].get<std::string>();
		long outputPosition = 0;
		while (process_uuid.length())
		{
			// /app/testapp/output?process_uuid=ABDJDD-DJKSJDKF
			restPath = std::string("/appmesh/app/").append(appName).append("/output");
			query.clear();
			query[HTTP_QUERY_KEY_process_uuid] = process_uuid;
			query[HTTP_QUERY_KEY_stdout_position] = std::to_string(outputPosition);
			query[HTTP_QUERY_KEY_stdout_timeout] = std::to_string(1); // wait max 1 second in server side
			response = requestHttp(false, web::http::methods::GET, restPath, nullptr, {}, query);
			std::cout << JSON::utf8ToLocalEncoding(response->text) << std::flush;
			outputPosition = response->header.count(HTTP_HEADER_KEY_output_pos) ? std::atol(response->header.find(HTTP_HEADER_KEY_output_pos)->second.c_str()) : outputPosition;
			returnCode = response->header.count(HTTP_HEADER_KEY_exit_code) ? std::atoi(response->header.find(HTTP_HEADER_KEY_exit_code)->second.c_str()) : returnCode;

			if (response->header.count(HTTP_HEADER_KEY_exit_code) || response->status_code != web::http::status_codes::OK)
			{
				break;
			}
		}
		// delete
		restPath = std::string("/appmesh/app/").append(appName);
		requestHttp(false, web::http::methods::DEL, restPath);
	}
	return returnCode;
}

std::string ArgumentParser::parseOutputMessage(std::shared_ptr<CurlResponse> &resp)
{
	if (!resp)
	{
		return std::string();
	}
	try
	{
		auto output = resp->text;
		if (output.empty() && resp->status_code != web::http::status_codes::OK)
			return resp->text;
		if (output.empty())
			return std::string();
		auto respJson = nlohmann::json::parse(resp->text);
		if (respJson.contains(REST_TEXT_MESSAGE_JSON_KEY))
		{
			return respJson.at(REST_TEXT_MESSAGE_JSON_KEY).get<std::string>();
		}
		else
		{
			return respJson.dump(2);
		}
	}
	catch (...)
	{
	}
	return resp->text;
}

#if defined(_WIN32)
BOOL WINAPI CrossPlatformSignalHandler(DWORD ctrlType)
{
	if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT)
#else
void CrossPlatformSignalHandler(int signo)
{
	if (signo == SIGINT)
#endif
	{
		if (!g_interrupt.exchange(true))
		{
			g_interrupt = true;

			const auto restPath = std::string("/appmesh/app/").append(APPC_EXEC_APP_NAME);
			WORK_PARSE->requestHttp(false, web::http::methods::DEL, restPath);
		}
#if defined(_WIN32)
		return TRUE;
#endif
	}
#if defined(_WIN32)
	return FALSE;
#endif
}

void ArgumentParser::regSignal()
{
#if defined(_WIN32)
	SetConsoleCtrlHandler(CrossPlatformSignalHandler, TRUE);
#else
	std::signal(SIGINT, CrossPlatformSignalHandler);
#endif
}

void ArgumentParser::unregSignal()
{
#if defined(_WIN32)
	SetConsoleCtrlHandler(NULL, FALSE);
#else
	std::signal(SIGINT, SIG_DFL);
#endif
}

static bool is_shell_process(const std::string &exeNameLower)
{
	// Accept common shells across platforms
	static const char *shells[] = {
		"bash", "sh", "dash",
		"cmd.exe", "powershell.exe", "pwsh.exe",
		"bash.exe", "sh.exe"};
	for (auto &shell : shells)
	{
		if (exeNameLower == shell)
			return true;
	}
	return false;
}

pid_t get_bash_pid()
{
	pid_t pid = ACE_OS::getpid();

	// VSCode uses an integrated terminal that spawns its own Bash shell process.
	// This shell process remains persistent across terminal sessions,
	// meaning that the same Bash process is reused for all the commands executed in that terminal
	// until you explicitly close the terminal or VSCode.
	if (ACE_OS::getenv("VSCODE_PID"))
	{
		return pid;
	}

#if defined(_WIN32)

	pid_t ppid = ACE_OS::getppid();
	while (ppid != 0 && ppid != 4) // 4 is "System"
	{
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE)
			return pid;

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);
		pid_t next_ppid = 0;
		bool found = false;

		if (Process32First(hSnap, &pe))
		{
			do
			{
				if (pe.th32ProcessID == (DWORD)ppid)
				{
					std::string exeName = pe.szExeFile;
					if (is_shell_process(Utility::strTolower(exeName)))
					{
						CloseHandle(hSnap);
						return ppid;
					}
					next_ppid = pe.th32ParentProcessID;
					found = true;
					break;
				}
			} while (Process32Next(hSnap, &pe));
		}

		CloseHandle(hSnap);
		if (!found)
			break;
		ppid = next_ppid;
	}
	return pid;

#else // Linux / Unix

	pid_t ppid = ACE_OS::getppid();
	while (ppid != 1) // 1 is init
	{
		std::string proc_path = "/proc/" + std::to_string(ppid) + "/comm";
		std::ifstream comm_file(proc_path);
		std::string comm;
		std::getline(comm_file, comm);

		if (is_shell_process(Utility::strTolower(comm)))
			return ppid;

		// Move up process tree
		proc_path = "/proc/" + std::to_string(ppid) + "/stat";
		std::ifstream stat_file(proc_path);
		std::string stat_line;
		std::getline(stat_file, stat_line);

		// Extract parent PID from stat file
		size_t pos = stat_line.find(')');
		if (pos != std::string::npos)
		{
			int parent_pid = 0;
			sscanf(stat_line.c_str() + pos + 2, "%*c %d", &parent_pid);
			ppid = parent_pid;
		}
		else
			return ppid; // Error reading
	}
	return ppid;

#endif
}

int ArgumentParser::processShell()
{
	po::options_description desc("Remote Shell Execution \nUsage: appc shell [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description execute("Execution Options", BOOST_DESC_WIDTH);
	execute.add_options()
	(RETRY_ARGS, "Retry command until success.")
	(SESSION_LOGIN_ARGS, "With session login.")
	(LIFETIME_ARGS, po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_LIFECYCLE_SECONDS)), "Maximum lifecycle time (in seconds) for the command run. Default is 12 hours; supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').")
	(TIMEOUT_ARGS, po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_TIMEOUT_SECONDS)), "Maximum time (in seconds) for the command run. Greater than 0 means output can be printed repeatedly, less than 0 means output will be printed until the process exits; supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').");
	OTHER_OPTIONS;
	desc.add(connection).add(execute).add(other);
	shiftCommandLineArgs(desc, true);
	HELP_ARG_CHECK_WITH_RETURN_ZERO;

	bool retry = m_commandLineVariables.count(RETRY);
	int returnCode = 0;

	// Get current session id (bash pid)
	auto bashId = get_bash_pid();
	// Get appmesh user
	auto appmeshUser = getAuthenUser();
	// Get current user name
	auto osUser = os::getUsernameByUid();
	// Unique session id as appname
	APPC_EXEC_APP_NAME = appmeshUser + "_" + osUser + "_" + std::to_string(bashId);

	// Collect Unrecognized options as initial commands
	std::vector<std::string> opts = po::collect_unrecognized(m_parsedOptions, po::include_positional);
	if (opts.size())
		opts.erase(opts.begin()); // remove [command] option and parse all others
	auto parsed = po::command_line_parser(opts).options(desc).allow_unregistered().run();
	std::vector<std::string> unrecognized = po::collect_unrecognized(parsed.options, po::include_positional);
	std::string initialCmd = boost::algorithm::join(unrecognized, " ");

	// Get current ENV
	nlohmann::json objEnvs = nlohmann::json::object();
	for (char **var = environ; *var != nullptr; var++)
	{
		std::string e = *var;
		auto vec = Utility::splitString(e, "=");
		if (vec.size() > 0)
		{
			objEnvs[vec[0]] = std::string(vec.size() > 1 ? vec[1] : std::string());
		}
	}

	char buff[MAX_COMMAND_LINE_LENGTH] = {0};
	nlohmann::json jsonObj;
	jsonObj[JSON_KEY_APP_name] = std::string(APPC_EXEC_APP_NAME);
	jsonObj[JSON_KEY_APP_shell_mode] = (true);
	jsonObj[JSON_KEY_APP_session_login] = m_commandLineVariables.count(SESSION_LOGIN) > 0;
	jsonObj[JSON_KEY_APP_command] = std::string(initialCmd);
	jsonObj[JSON_KEY_APP_description] = std::string("App Mesh exec environment");
	jsonObj[JSON_KEY_APP_env] = objEnvs;
	jsonObj[JSON_KEY_APP_working_dir] = std::string(getcwd(buff, sizeof(buff)));
	nlohmann::json behavior;
	behavior[JSON_KEY_APP_behavior_exit] = std::string(JSON_KEY_APP_behavior_remove);
	jsonObj[JSON_KEY_APP_behavior] = behavior;
	std::map<std::string, std::string> query;
	int timeout = DurationParse::parse(m_commandLineVariables[TIMEOUT].as<std::string>());
	int lifecycle = DurationParse::parse(m_commandLineVariables[LIFETIME].as<std::string>());

	auto sleepSeconds = [](int sec) -> bool
	{ACE_OS::sleep(sec);	return true; };
	g_interrupt = false; // if ctrl + c is triggered, stop run and start read input from stdin
	this->regSignal();	 // capture SIGINT
	// clean
	requestHttp(false, web::http::methods::DEL, std::string("/appmesh/app/").append(APPC_EXEC_APP_NAME));
	if (unrecognized.size())
	{
		// run once
		do
		{
			returnCode = runAsyncApp(jsonObj, timeout, lifecycle);
		} while (retry && returnCode != 0 && !g_interrupt.load() && sleepSeconds(1));
	}
	else
	{
		// shell interactive
		auto response = requestHttp(true, web::http::methods::GET, std::string("/appmesh/user/self"));
		auto execUser = nlohmann::json::parse(response->text)[JSON_KEY_USER_exec_user].get<std::string>();
		std::cout << "Connected to <" << appmeshUser << "@" << m_currentUrl << "> as exec user <" << execUser << ">" << std::endl;

		linenoiseSetMultiLine(1);
    	linenoiseHistoryLoad(m_shellHistoryFile.c_str());

		const static char *prompt = "appmesh> ";
		while (true)
		{
			char *input = linenoise(prompt);
			if (input == nullptr)
			{
				// NULL means either EOF (Ctrl+D) or we got interrupted
				std::cout << "End of input (Ctrl+D pressed)" << std::endl;
				continue;
			}
			std::string cmd(input);
			free(input);
			cmd = Utility::stdStringTrim(cmd);
			if (cmd.length())
			{
				static std::string lastCmd;
				if (lastCmd != cmd)
				{
					lastCmd = cmd;
					linenoiseHistoryAdd(cmd.c_str());
					linenoiseHistorySave(m_shellHistoryFile.c_str());
				}

				if (cmd == "exit" || cmd == "q")
				{
					break;
				}
				if (cmd == "clear" || cmd == "cls")
				{
					// Clear screen command
					linenoiseClearScreen();
					continue;
				}
				g_interrupt = false;
				jsonObj[JSON_KEY_APP_command] = cmd;
				do
				{
					returnCode = runAsyncApp(jsonObj, timeout, lifecycle);
				} while (retry && !g_interrupt && sleepSeconds(1));
			}
		}
	}

	return returnCode;
}

void ArgumentParser::processFileDownload()
{
	po::options_description desc("Download file \nUsage: appc get [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description download("Download Options", BOOST_DESC_WIDTH);
	download.add_options()
	(REMOTE_ARGS, po::value<std::string>(), "Remote file path to download.")
	(LOCAL_ARGS, po::value<std::string>(), "Local file path to save.")
	(COPY_ATTR_ARGS, "Copy file attributes.");
	OTHER_OPTIONS;
	desc.add(connection).add(download).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count(REMOTE) == 0 || m_commandLineVariables.count(LOCAL) == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	std::string restPath = REST_PATH_DOWNLOAD;
	auto file = m_commandLineVariables[REMOTE].as<std::string>();
	auto local = m_commandLineVariables[LOCAL].as<std::string>();

	// header
	std::map<std::string, std::string> header;
	header.insert({HTTP_HEADER_KEY_file_path, Utility::encodeURIComponent(file)});
	header.insert({HTTP_HEADER_JWT_Authorization, std::string(HTTP_HEADER_JWT_BearerSpace) + getAuthenToken()});
	auto response = RestClient::download(m_currentUrl, restPath, file, local, header);

	if (m_commandLineVariables.count(COPY_ATTR))
		Utility::applyFilePermission(local, response->header);
	if (response->status_code == web::http::status_codes::OK)
		std::cout << "Download remote file <" << file << "> to local <" << local << "> size <" << Utility::humanReadableSize(std::ifstream(local).seekg(0, std::ios::end).tellg()) << ">" << std::endl;
	else
		throw std::invalid_argument(parseOutputMessage(response));
}

void ArgumentParser::processFileUpload()
{
	po::options_description desc("Upload file \nUsage: appc put [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description upload("Upload Options", BOOST_DESC_WIDTH);
	upload.add_options()
	(REMOTE_ARGS, po::value<std::string>(), "Remote file path to save.")
	(LOCAL_ARGS, po::value<std::string>(), "Local file to upload.")
	(COPY_ATTR_ARGS, "Not copy file attributes.");
	OTHER_OPTIONS;
	desc.add(connection).add(upload).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count(REMOTE) == 0 || m_commandLineVariables.count(LOCAL) == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	auto file = m_commandLineVariables[REMOTE].as<std::string>();
	auto local = m_commandLineVariables[LOCAL].as<std::string>();

	if (!Utility::isFileExist(local))
	{
		std::cout << "local file not exist" << std::endl;
		return;
	}
	local = boost::filesystem::canonical(local).string();
	std::string restPath = REST_PATH_UPLOAD;

	// header
	std::map<std::string, std::string> header;
	header.insert({HTTP_HEADER_KEY_file_path, Utility::encodeURIComponent(file)});
	header.insert({HTTP_HEADER_JWT_Authorization, std::string(HTTP_HEADER_JWT_BearerSpace) + getAuthenToken()});
	if (m_commandLineVariables.count(COPY_ATTR))
	{
		auto fileInfo = os::fileStat(local);
		header.insert({HTTP_HEADER_KEY_file_mode, std::to_string(std::get<0>(fileInfo))});
		header.insert({HTTP_HEADER_KEY_file_user, std::to_string(std::get<1>(fileInfo))});
		header.insert({HTTP_HEADER_KEY_file_group, std::to_string(std::get<2>(fileInfo))});
	}

	auto response = RestClient::upload(m_currentUrl, restPath, local, header);
	if (response->status_code == web::http::status_codes::OK)
		std::cout << "Uploaded file <" << local << ">" << std::endl;
	else
		throw std::invalid_argument(parseOutputMessage(response));
}

void ArgumentParser::processTags()
{
	po::options_description desc("Manage labels \nUsage: appc label [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description label("Label Options", BOOST_DESC_WIDTH);
	label.add_options()
	(VIEW_ARGS, "List labels.")
	(ADD_ARGS, "Add labels.")
	(DELETE_ARGS, "Remove labels.")
	(LABEL_ARGS, po::value<std::vector<std::string>>(), "Labels (e.g., -l os=linux -l arch=arm64).");
	OTHER_OPTIONS;
	desc.add(connection).add(label).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::vector<std::string> inputTags;
	if (m_commandLineVariables.count(LABEL))
		inputTags = m_commandLineVariables[LABEL].as<std::vector<std::string>>();

	if (m_commandLineVariables.count(ADD) &&
		!m_commandLineVariables.count(DELETE) && !m_commandLineVariables.count(VIEW))
	{
		// Process add
		if (inputTags.empty())
		{
			std::cout << "No label specified" << std::endl;
			return;
		}
		for (auto &str : inputTags)
		{
			std::vector<std::string> envVec = Utility::splitString(str, "=");
			if (envVec.size() == 2)
			{
				std::string restPath = std::string("/appmesh/label/").append(envVec.at(0));
				std::map<std::string, std::string> query = {{"value", envVec.at(1)}};
				requestHttp(true, web::http::methods::PUT, restPath, nullptr, {}, query);
			}
		}
	}
	else if (m_commandLineVariables.count(DELETE) &&
			 !m_commandLineVariables.count(ADD) && !m_commandLineVariables.count(VIEW))
	{
		// Process remove
		if (inputTags.empty())
		{
			std::cout << "No label specified" << std::endl;
			return;
		}
		for (auto &str : inputTags)
		{
			std::vector<std::string> envVec = Utility::splitString(str, "=");
			std::string restPath = std::string("/appmesh/label/").append(envVec.at(0));
			auto resp = requestHttp(true, web::http::methods::DEL, restPath);
		}
	}
	else if (m_commandLineVariables.count(VIEW) &&
			 !m_commandLineVariables.count(DELETE) && !m_commandLineVariables.count(ADD))
	{
		// view
	}
	else
	{
		std::cout << desc << std::endl;
		return;
	}

	std::string restPath = "/appmesh/labels";
	auto response = requestHttp(true, web::http::methods::GET, restPath);
	// Finally print current
	auto tags = nlohmann::json::parse(response->text);
	for (auto &tag : tags.items())
	{
		std::cout << tag.key() << "=" << tag.value().get<std::string>() << std::endl;
	}
}

void ArgumentParser::processLoglevel()
{
	po::options_description desc("Set log level \nUsage: appc log [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description log("Log Options", BOOST_DESC_WIDTH);
	log.add_options()
	(LEVEL_ARGS, po::value<std::string>(), "Log level (e.g., DEBUG, INFO, NOTICE, WARN, ERROR).");
	OTHER_OPTIONS;
	desc.add(connection).add(log).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.size() == 0 || m_commandLineVariables.count(LEVEL) == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	auto level = m_commandLineVariables[LEVEL].as<std::string>();

	nlohmann::json jsonObj = {
		{JSON_KEY_BaseConfig, {{JSON_KEY_LogLevel, level}}}};
	// /app-manager/config
	auto restPath = std::string("/appmesh/config");
	auto response = requestHttp(true, web::http::methods::POST, restPath, &jsonObj);
	std::cout << "Log level set to: " << nlohmann::json::parse(response->text).at(JSON_KEY_BaseConfig).at(JSON_KEY_LogLevel).get<std::string>() << std::endl;
}

void ArgumentParser::processConfigView()
{
	po::options_description desc("View configurations \nUsage: appc config [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description log("Configuration Options", BOOST_DESC_WIDTH);
	log.add_options()
	(VIEW_ARGS, "View basic configurations in JSON format.");
	OTHER_OPTIONS;
	desc.add(connection).add(log).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/config";
	auto resp = requestHttp(true, web::http::methods::GET, restPath);
	std::cout << JSON::dumpToLocalEncoding(nlohmann::json::parse(resp->text), 2) << std::endl;
}

void ArgumentParser::processUserChangePwd()
{
	po::options_description desc("Change password \nUsage: appc passwd [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description pwd("Password Options", BOOST_DESC_WIDTH);
	pwd.add_options()
	(TARGET_ARGS, po::value<std::string>()->default_value("self"), "Target user to change password.");
	OTHER_OPTIONS;
	desc.add(connection).add(pwd).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	auto user = m_commandLineVariables[TARGET].as<std::string>();
	if (user == "self")
	{
		user = getAuthenUser();
	}
	std::string restPath = std::string("/appmesh/user/") + user + "/passwd";

	nlohmann::json jsonObj;
	jsonObj[HTTP_BODY_KEY_OLD_PASSWORD] = Utility::encode64(inputPasswd("old password for " + user));
	jsonObj[HTTP_BODY_KEY_NEW_PASSWORD] = Utility::encode64(inputPasswd("new password for " + user));
	auto response = requestHttp(true, web::http::methods::POST, restPath, &jsonObj);
	std::cout << parseOutputMessage(response) << std::endl;
}

void ArgumentParser::processUserLock()
{
	po::options_description desc("Control user \nUsage: appc lock [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description useropt("Lock Options", BOOST_DESC_WIDTH);
	useropt.add_options()
	(TARGET_ARGS, po::value<std::string>(), "Target user.")
	(LOCK_ARGS, po::value<bool>(), "Lock or unlock user ('true' to lock, 'false' to unlock).");
	OTHER_OPTIONS;
	desc.add(connection).add(useropt).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (!m_commandLineVariables.count(TARGET) || !m_commandLineVariables.count(LOCK))
	{
		std::cout << desc << std::endl;
		return;
	}

	auto user = m_commandLineVariables[TARGET].as<std::string>();
	auto lock = m_commandLineVariables[LOCK].as<bool>();

	std::string restPath = std::string("/appmesh/user/") + user + (lock ? "/lock" : "/unlock");
	auto response = requestHttp(true, web::http::methods::POST, restPath);
	std::cout << parseOutputMessage(response) << std::endl;
}

void ArgumentParser::processUserManage()
{
	po::options_description desc("View/Add users \nUsage: appc user [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description user("User Options", BOOST_DESC_WIDTH);
	user.add_options()
	(JSON_ARGS, po::value<std::string>(), "Path to a JSON file containing a user definition.")
	(ALL_ARGS, "View all users.");
	OTHER_OPTIONS;
	other.add_options()
	(FORCE_ARGS, "Skip confirmation prompts");
	desc.add(connection).add(user).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count(JJSON) == 0)
	{
		// View user
		std::string restPath = m_commandLineVariables.count(ALL) ? "/appmesh/users" : "/appmesh/user/self";
		auto response = requestHttp(true, web::http::methods::GET, restPath);
		std::cout << parseOutputMessage(response) << std::endl;
	}
	else
	{
		// Add user
		auto fileName = m_commandLineVariables[JJSON].as<std::string>();
		if (!Utility::isFileExist(fileName))
		{
			throw std::invalid_argument(Utility::stringFormat("input file %s does not exist", fileName.c_str()));
		}

		auto jsonObj = nlohmann::json::parse(Utility::readFile(fileName));
		const std::string userName = jsonObj[JSON_KEY_USER_readonly_name].get<std::string>();

		if (m_commandLineVariables.count(FORCE) == 0)
		{
			std::string msg = std::string("Confirm to register user <") + userName + "> ? [y/n]";
			if (!confirmInput(msg.c_str()))
			{
				return;
			}
		}

		if (!HAS_JSON_FIELD(jsonObj, JSON_KEY_USER_key))
		{
			jsonObj[JSON_KEY_USER_key] = inputPasswd(userName);
		}

		std::string restPath = "/appmesh/user/" + userName;
		auto response = requestHttp(true, web::http::methods::PUT, restPath, &jsonObj);
		std::cout << parseOutputMessage(response) << std::endl;
	}
}

void ArgumentParser::processUserPwdEncrypt()
{
	std::vector<std::string> opts = po::collect_unrecognized(m_parsedOptions, po::include_positional);
	if (opts.size())
		opts.erase(opts.begin());

	std::string str;
	if (opts.size() == 0)
	{
		std::cin >> str;
		while (str.size())
		{
			std::cout << Utility::hash(str) << std::endl;
			std::cin >> str;
		}
	}
	else
	{
		for (auto &optStr : opts)
		{
			std::cout << Utility::hash(optStr) << std::endl;
		}
	}
}

void ArgumentParser::processUserMfa()
{
	po::options_description desc("Manage multi-factor authentication \nUsage: appc mfa [options]", BOOST_DESC_WIDTH);
	CONNECTION_OPTIONS;
	po::options_description user("User Options", BOOST_DESC_WIDTH);
	user.add_options()
	(ADD_ARGS, "Activate MFA.")
	(DELETE_ARGS, "Deactivate MFA.");
	OTHER_OPTIONS;
	desc.add(connection).add(user).add(other);
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string userName = getLoginUser();
	if (m_commandLineVariables.count(USERNAME))
	{
		userName = m_commandLineVariables[USERNAME].as<std::string>();
	}
	if (userName.empty())
	{
		std::cout << "No user name specified" << std::endl;
		return;
	}

	if (m_commandLineVariables.count(ADD))
	{
		std::string restPath = "/appmesh/user/self";
		auto resp = nlohmann::json::parse(requestHttp(true, web::http::methods::GET, restPath)->text);
		std::string msg = "Do you want active 2FA for <%s> [y/n]:";
		if (GET_JSON_BOOL_VALUE(resp, JSON_KEY_USER_mfa_enabled))
		{
			msg = "2FA already enabled, do you want re-active 2FA for <%s> [y/n]:";
		}
		if (this->confirmInput(Utility::stringFormat(msg, userName.c_str()).c_str()))
		{
			// Generate TOTP secret
			std::string restPath = std::string("/appmesh/totp/secret");
			auto response = requestHttp(true, web::http::methods::POST, restPath);
			auto result = nlohmann::json::parse(response->text);
			auto totpUri = Utility::decode64(result.at(HTTP_BODY_KEY_MFA_URI).get<std::string>());
			Utility::printQRcode(totpUri);

			// Input TOTP key for validation until success
			bool validating = true;
			do
			{
				std::string totp;
				std::cin.clear();
				std::cout << "Enter TOTP key: ";
				std::cin >> totp;

				// Setup TOTP
				restPath = "/appmesh/totp/setup";
				std::map<std::string, std::string> header;
				header.insert({HTTP_HEADER_JWT_totp, totp});
				try
				{
					response = requestHttp(true, web::http::methods::POST, restPath, nullptr, std::move(header));
					if (response->status_code == web::http::status_codes::OK)
					{
						validating = false;
						m_jwtToken = nlohmann::json::parse(response->text).at(HTTP_HEADER_JWT_access_token).get<std::string>();
						persistAuthToken(parseUrlHost(m_currentUrl), m_jwtToken);
						std::cout << "TOTP setup for " << userName << " success." << std::endl;
					}
				}
				catch (...)
				{
				}
			} while (validating);
		}
	}
	else if (m_commandLineVariables.count(DELETE))
	{
		if (this->confirmInput(Utility::stringFormat("Do you want deactive 2FA for <%s> [y/n]:", userName.c_str()).c_str()))
		{
			std::string restPath = std::string("/appmesh/totp/") + userName + "/disable";
			auto response = requestHttp(true, web::http::methods::POST, restPath);
			std::cout << parseOutputMessage(response) << std::endl;
		}
	}
	else
	{
		std::cout << desc << std::endl;
	}
}

void ArgumentParser::initRadomPassword()
{
	// only for root user generate password for admin user after installation
	if (ACE_OS::geteuid() != 0 && !Utility::runningInContainer())
	{
		std::cerr << "only root user can generate a initial password" << std::endl;
		return;
	}

	const auto flagFile = fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_APPMG_INIT_FLAG_FILE;
	if (Utility::isFileExist(flagFile.string()))
	{
		std::cerr << "The 'appc appmginit' should only run once." << std::endl;
		return;
	}
	std::ofstream(flagFile.string(), std::ios::trunc).close();

	auto configFile = YAML::LoadFile(Utility::getConfigFilePath(APPMESH_CONFIG_YAML_FILE));
	// check JWT enabled
	if (configFile[JSON_KEY_REST] && configFile[JSON_KEY_REST][JSON_KEY_JWT])
	{
		// update JWT salt
		configFile[JSON_KEY_REST][JSON_KEY_JWT][JSON_KEY_JWTSalt] = generatePassword(8, true, true, true, false);
		// use RS256 sign algorithm
		configFile[JSON_KEY_REST][JSON_KEY_JWT][JSON_KEY_JWTAlgorithm] = APPMESH_JWT_ALGORITHM_RS256;
		// serialize and save JSON config
		std::ofstream ofsCfg(Utility::getConfigFilePath(APPMESH_CONFIG_YAML_FILE, true), ios::trunc);
		if (ofsCfg.is_open())
		{
			ofsCfg << configFile;
			ofsCfg.close();
		}

		// check JWT configured as local JSON plugin
		if (configFile[JSON_KEY_REST][JSON_KEY_JWT][JSON_KEY_SECURITY_Interface].as<std::string>() == JSON_KEY_USER_key_method_local)
		{
			auto securityFile = YAML::LoadFile(Utility::getConfigFilePath(APPMESH_SECURITY_YAML_FILE));
			securityFile[JSON_KEY_SECURITY_EncryptKey] = true;
			// update with generated password
			const std::string genPassword = generatePassword(8, true, true, true, false);
			const std::string encryptPassword = Utility::hash(genPassword);
			securityFile[JSON_KEY_JWT_Users][JWT_ADMIN_NAME][JSON_KEY_USER_key] = encryptPassword;

			// serialize and save security JSON config
			std::ofstream ofsSec(Utility::getConfigFilePath(APPMESH_SECURITY_YAML_FILE, true), ios::trunc);
			if (ofsSec.is_open())
			{
				ofsSec << securityFile;
				ofsSec.close();
				std::cout << "!Important! This will only occure once, password for user <admin> is <" << genPassword << ">." << std::endl;
			}
		}
	}
}

bool ArgumentParser::confirmInput(const char *msg)
{
	std::cout << msg;
	std::string result;
	std::cin >> result;
	return result == "y";
}

std::shared_ptr<CurlResponse> ArgumentParser::requestHttp(bool shouldThrow, const web::http::method &mtd, const std::string &path, nlohmann::json *body, std::map<std::string, std::string> header, std::map<std::string, std::string> query)
{
	if (m_jwtToken.empty())
	{
		m_jwtToken = getAuthenToken();
	}
	header[HTTP_HEADER_JWT_Authorization] = std::string(HTTP_HEADER_JWT_BearerSpace) + m_jwtToken;
	if (m_forwardTo.length())
	{
		if (m_forwardTo.find(':') == std::string::npos)
			header[HTTP_HEADER_KEY_Forwarding_Host] = m_forwardTo + ":" + parseUrlPort(m_currentUrl);
		else
			header[HTTP_HEADER_KEY_Forwarding_Host] = m_forwardTo;
	}
	std::string bodyContent = body ? body->dump() : std::string();
	auto resp = RestClient::request(m_currentUrl, mtd, path, bodyContent, header, query);
	if (shouldThrow && resp->status_code != web::http::status_codes::OK)
	{
		throw std::invalid_argument(parseOutputMessage(resp));
	}
	return resp;
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
	auto response = requestHttp(true, web::http::methods::GET, restPath);
	auto jsonValue = nlohmann::json::parse(response->text);
	for (auto &item : jsonValue.items())
	{
		auto appJson = item.value();
		apps[appJson.at(JSON_KEY_APP_name).get<std::string>()] = (1 == appJson.at(JSON_KEY_APP_status).get<int>());
	}
	return apps;
}

std::string ArgumentParser::getAuthenToken()
{
	std::string token;
	// 1. try to get from REST
	if (m_username.length() && m_userpwd.length())
	{
		token = login(m_username, m_userpwd, m_currentUrl, m_audience);
	}
	else
	{
		// 2. try to read from token file
		token = readPersistAuthToken(parseUrlHost(m_currentUrl));

		// 3. try to get get default token from REST
		if (token.empty())
		{
			token = login(std::string(JWT_USER_NAME), std::string(JWT_USER_KEY), m_currentUrl, m_audience);
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
		token = readPersistAuthToken(parseUrlHost(m_currentUrl));
		// 3. try to get get default token from REST
		if (token.empty())
		{
			token = login(std::string(JWT_USER_NAME), std::string(JWT_USER_KEY), m_currentUrl, m_audience);
		}
		auto decodedToken = jwt::decode(token);
		if (decodedToken.has_subject())
		{
			// get user info
			auto userName = decodedToken.get_subject();
			return userName;
		}
		throw std::invalid_argument("Failed to get token");
	}
}

std::string ArgumentParser::readPersistAuthToken(const std::string &hostName)
{
	std::string jwtToken;
	if (Utility::isFileExist(m_tokenFile) && hostName.length())
	{
		try
		{
			auto configFile = Utility::readFile(m_tokenFile);
			if (configFile.length() > 0)
			{
				auto config = nlohmann::json::parse(configFile);
				if (config.contains("auths") && config["auths"].contains(hostName))
				{
					jwtToken = config.at("auths").at(hostName).at("auth").get<std::string>();
				}
			}
		}
		catch (const std::exception &e)
		{
			std::cerr << "failed to parse " << m_tokenFile << " as json format" << '\n';
		}
	}
	return jwtToken;
}

std::string ArgumentParser::readPersistLastHost(const std::string &defaultAddress)
{
	if (Utility::isFileExist(m_tokenFile))
	{
		try
		{
			auto configFile = Utility::readFile(m_tokenFile);
			if (configFile.length() > 0)
			{
				auto config = nlohmann::json::parse(configFile);
				if (config.contains("last_host"))
				{
					return config.at("last_host").get<std::string>();
				}
			}
		}
		catch (const std::exception &e)
		{
			std::cerr << "failed to parse " << m_tokenFile << " as json format" << '\n';
		}
	}
	return defaultAddress;
}

void ArgumentParser::persistAuthToken(const std::string &hostName, const std::string &token)
{
	nlohmann::json config;
	try
	{
		std::string configFile;
		if (Utility::isFileExist(m_tokenFile))
		{
			configFile = Utility::readFile(m_tokenFile);
		}
		if (configFile.length() > 0)
		{
			config = nlohmann::json::parse(configFile);
		}
	}
	catch (const std::exception &e)
	{
		std::cerr << "failed to parse " << m_tokenFile << " as json format" << '\n';
	}
	if (!config.contains("auths"))
		config["auths"] = nlohmann::json::object();

	if (token.length())
	{
		config["auths"][hostName] = nlohmann::json::object();
		config["auths"][hostName]["auth"] = std::string(token);
	}
	else if (config["auths"].contains(hostName))
	{
		config["auths"].erase(hostName);
	}
	config["last_host"] = std::string(hostName);

	std::ofstream ofs(m_tokenFile, std::ios::trunc);
	if (ofs.is_open())
	{
		ofs << config.dump(2);
		ofs.close();
		// only owner to read and write for token file
#if !defined(_WIN32)
		os::chmod(m_tokenFile, 600);
#endif
	}
	else
	{
		std::cerr << "Failed to write config file " << m_tokenFile << std::endl;
	}
}

std::string ArgumentParser::login(const std::string &user, const std::string &passwd, std::string targetHost, std::string audience)
{
	auto url = Utility::stdStringTrim(targetHost, '/');
	// header
	std::map<std::string, std::string> header;
	header.insert({HTTP_HEADER_JWT_Authorization, std::string(HTTP_HEADER_Auth_BasicSpace) + Utility::encode64(user + ":" + passwd)});
	header.insert({HTTP_HEADER_JWT_expire_seconds, std::to_string(m_tokenTimeoutSeconds)});
	header.insert({HTTP_HEADER_JWT_audience, audience});

	auto response = RestClient::request(url, web::http::methods::POST, "/appmesh/login", "", std::move(header), {});
	if (response->status_code == web::http::status_codes::OK)
	{
		m_currentUrl = url;
		m_jwtToken = nlohmann::json::parse(response->text).at(HTTP_HEADER_JWT_access_token).get<std::string>();
		return m_jwtToken;
	}
	else if (response->status_code == web::http::status_codes::Unauthorized && nlohmann::json::parse(response->text).contains(REST_TEXT_TOTP_CHALLENGE_JSON_KEY))
	{
		auto totpChallenge = nlohmann::json::parse(response->text).at(REST_TEXT_TOTP_CHALLENGE_JSON_KEY).get<std::string>();
		// Input TOTP key for validation until success
		do
		{
			std::string totp;
			std::cin.clear();
			std::cout << "Enter TOTP key: ";
			std::cin >> totp;

			nlohmann::json body;
			body[HTTP_BODY_KEY_JWT_username] = user;
			body[HTTP_BODY_KEY_JWT_totp] = totp;
			body[HTTP_BODY_KEY_JWT_totp_challenge] = totpChallenge;
			body[HTTP_BODY_KEY_JWT_expire_seconds] = m_tokenTimeoutSeconds;
			response = RestClient::request(url, web::http::methods::POST, "/appmesh/totp/validate", body.dump(), {}, {});
			if (response->status_code == web::http::status_codes::OK)
			{
				m_currentUrl = url;
				m_jwtToken = nlohmann::json::parse(response->text).at(HTTP_HEADER_JWT_access_token).get<std::string>();
				return m_jwtToken;
			}
			else
				std::cout << parseOutputMessage(response) << std::endl;
		} while (true);
	}
	throw std::invalid_argument(Utility::stringFormat("Login failed: %s", parseOutputMessage(response).c_str()));
}

void ArgumentParser::printApps(const nlohmann::json &json, bool reduce)
{
	const int COLUMN_PADDING = 2;

	// Define columns with their properties
	struct Column
	{
		const std::string title;
		const std::string jsonKey;
		size_t width;												  // Single width field that will be calculated
		std::function<std::string(const nlohmann::json &)> formatter; // Function to format a value for this column

		Column(const std::string &title, const std::string &key, std::function<std::string(const nlohmann::json &)> formatter)
			: title(title), jsonKey(key), width(title.length()), formatter(formatter)
		{
			width += (title == "COMMAND" ? 0 : COLUMN_PADDING); // Add padding for all but COMMAND column
		}
	};

	// Create all column definitions with their formatters
	std::vector<Column> columns = {
		{"ID", "", [](const nlohmann::json &)
		 { return ""; }}, // Index is handled separately
		{"NAME", JSON_KEY_APP_name, [](const nlohmann::json &obj)
		 {
			 return GET_JSON_STR_VALUE(obj, JSON_KEY_APP_name);
		 }},
		{"OWNER", JSON_KEY_APP_owner, [](const nlohmann::json &obj)
		 {
			 std::string value = GET_JSON_STR_VALUE(obj, JSON_KEY_APP_owner);
			 return value.empty() ? EMPTY_PLACEHOLDER : value;
		 }},
		{"STATUS", JSON_KEY_APP_status, [](const nlohmann::json &obj)
		 {
			 return GET_STATUS_STR(GET_JSON_INT_VALUE(obj, JSON_KEY_APP_status));
		 }},
		{"HEALTH", JSON_KEY_APP_health, [](const nlohmann::json &obj)
		 {
			 return (0 == GET_JSON_INT_VALUE(obj, JSON_KEY_APP_health)) ? "OK" : EMPTY_PLACEHOLDER;
		 }},
		{"PID", JSON_KEY_APP_pid, [](const nlohmann::json &obj)
		 {
			 return HAS_JSON_FIELD(obj, JSON_KEY_APP_pid) ? std::to_string(GET_JSON_INT_VALUE(obj, JSON_KEY_APP_pid)) : EMPTY_PLACEHOLDER;
		 }},
		{"USER", JSON_KEY_APP_pid_user, [](const nlohmann::json &obj)
		 {
			 return HAS_JSON_FIELD(obj, JSON_KEY_APP_pid_user) ? GET_JSON_STR_VALUE(obj, JSON_KEY_APP_pid_user) : EMPTY_PLACEHOLDER;
		 }},
		{"MEMORY", JSON_KEY_APP_memory, [](const nlohmann::json &obj)
		 {
			 return HAS_JSON_FIELD(obj, JSON_KEY_APP_memory) ? Utility::humanReadableSize(GET_JSON_INT64_VALUE(obj, JSON_KEY_APP_memory)) : EMPTY_PLACEHOLDER;
		 }},
		{"%CPU", JSON_KEY_APP_cpu, [](const nlohmann::json &obj)
		 {
			 return HAS_JSON_FIELD(obj, JSON_KEY_APP_cpu) ? std::to_string(static_cast<int>(GET_JSON_DOUBLE_VALUE(obj, JSON_KEY_APP_cpu))) : EMPTY_PLACEHOLDER;
		 }},
		{"RETURN", JSON_KEY_APP_return, [](const nlohmann::json &obj)
		 {
			 return HAS_JSON_FIELD(obj, JSON_KEY_APP_return) ? std::to_string(GET_JSON_INT_VALUE(obj, JSON_KEY_APP_return)) : EMPTY_PLACEHOLDER;
		 }},
		{"AGE", JSON_KEY_APP_REG_TIME, [](const nlohmann::json &obj)
		 {
			 return HAS_JSON_FIELD(obj, JSON_KEY_APP_REG_TIME) ? Utility::humanReadableDuration(std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(obj, JSON_KEY_APP_REG_TIME))) : EMPTY_PLACEHOLDER;
		 }},
		{"DURATION", "", [](const nlohmann::json &obj)
		 {
			 if (HAS_JSON_FIELD(obj, JSON_KEY_APP_last_start) && HAS_JSON_FIELD(obj, JSON_KEY_APP_pid))
			 {
				 std::chrono::system_clock::time_point startTime = std::chrono::system_clock::from_time_t(
					 GET_JSON_INT64_VALUE(obj, JSON_KEY_APP_last_start));
				 std::chrono::system_clock::time_point endTime = HAS_JSON_FIELD(obj, JSON_KEY_APP_last_exit) ? std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(obj, JSON_KEY_APP_last_exit)) : std::chrono::system_clock::now();
				 return Utility::humanReadableDuration(startTime, endTime);
			 }
			 return std::string(EMPTY_PLACEHOLDER);
		 }},
		{"STARTS", JSON_KEY_APP_starts, [](const nlohmann::json &obj)
		 {
			 return HAS_JSON_FIELD(obj, JSON_KEY_APP_starts) ? std::to_string(GET_JSON_INT_VALUE(obj, JSON_KEY_APP_starts)) : EMPTY_PLACEHOLDER;
		 }},
		{"COMMAND", JSON_KEY_APP_command, [](const nlohmann::json &obj)
		 {
			 return HAS_JSON_FIELD(obj, JSON_KEY_APP_command) ? obj.at(JSON_KEY_APP_command).dump() : "";
		 }}};

	// Step 1: Prepare row data for analysis and later display
	std::vector<std::vector<std::string>> rows;
	int index = 1;
	for (const auto &item : json.items())
	{
		const auto &jsonObj = item.value();
		std::vector<std::string> row;

		// Handle ID column specially
		row.push_back(std::to_string(index++));

		// Format all other columns
		for (size_t i = 1; i < columns.size(); i++)
			row.push_back(columns[i].formatter(jsonObj));

		rows.push_back(row);
	}

	// Step 2: Calculate optimal column widths with padding
	for (const auto &row : rows)
	{
		for (size_t i = 0; i < columns.size() - 1; i++)
		{																					 // Skip the last (COMMAND) column
			columns[i].width = std::max(columns[i].width, row[i].length() + COLUMN_PADDING); // Add padding here as well
		}
	}

	// Step 3: Determine terminal width and adjust column display
	size_t terminalWidth = 80; // Default fallback width
#if defined(_WIN32)
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
	{
		terminalWidth = csbi.srWindow.Right - csbi.srWindow.Left;
	}
#else
	struct winsize w;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1)
	{
		terminalWidth = w.ws_col;
	}
#endif
	if (!reduce)
	{
		terminalWidth = 32767; // Max terminal width for none-reduce mode
	}

	// Calculate available columns that fit in terminal width
	size_t totalWidth = 0;

	size_t visibleColumns = 0; // Without counting COMMAND column
	for (size_t i = 0; i < columns.size() - 1; i++)
	{
		if (totalWidth + columns[i].width <= terminalWidth)
		{
			totalWidth += columns[i].width;
			visibleColumns++;
		}
		else
		{
			break;
		}
	}

	// Calculate COMMAND column width if there's space left
	size_t commandColWidth = 0;
	if (totalWidth + columns.back().width < terminalWidth)
	{
		commandColWidth = terminalWidth - totalWidth;
	}

	// Step 4: Print the table
	boost::io::ios_all_saver guard(std::cout);
	std::cout << std::left;

	// Print header
	for (size_t i = 0; i < visibleColumns; i++)
	{
		std::cout << std::setw(columns[i].width) << Utility::strToupper(columns[i].title);
	}
	if (commandColWidth > 0)
	{
		std::cout << Utility::strToupper(columns.back().title);
	}
	std::cout << std::endl;

	// Print data rows
	for (const auto &row : rows)
	{
		for (size_t i = 0; i < visibleColumns; i++)
		{
			std::string value = row[i];
			// Ensure value doesn't exceed column width
			if (value.length() > columns[i].width - COLUMN_PADDING)
			{
				value = value.substr(0, columns[i].width - COLUMN_PADDING);
			}
			std::cout << std::setw(columns[i].width) << value;
		}

		// Print COMMAND column if there's space
		if (commandColWidth > 0)
		{
			std::string command = row.back();
			if (command.length() > commandColWidth)
			{
				command = reduce ? reduceStr(command, commandColWidth) : command;
			}
			std::cout << command;
		}

		std::cout << std::endl;
	}
}

void ArgumentParser::shiftCommandLineArgs(po::options_description &desc, bool allowUnregistered)
{
	m_commandLineVariables.clear();
	std::vector<std::string> opts = po::collect_unrecognized(m_parsedOptions, po::include_positional);
	// remove [command] option and parse all others in m_commandLineVariables
	if (opts.size())
		opts.erase(opts.begin());
	if (allowUnregistered)
		po::store(po::command_line_parser(opts).options(desc).allow_unregistered().run(), m_commandLineVariables);
	else
		po::store(po::command_line_parser(opts).options(desc).run(), m_commandLineVariables);
	po::notify(m_commandLineVariables);
}

std::string ArgumentParser::reduceStr(std::string source, int limit)
{
	if (source.length() >= (std::size_t)limit)
	{
		if (source.back() == '"')
		{
			return source.substr(0, limit - 2).append("*\"");
		}
		else
		{
			return source.substr(0, limit - 1).append("*");
		}
	}
	else
	{
		return source;
	}
}

std::string ArgumentParser::inputPasswd(const std::string &userNameDesc)
{
	std::string passwd;
	while (passwd.empty())
	{
		std::cout << "Password(" << userNameDesc << "): ";
		char buffer[256] = {0};
		char *str = buffer;
		FILE *fp = stdin;
		inputSecurePasswd(&str, sizeof(buffer), '*', fp);
		passwd = buffer;
		std::cout << std::endl;
	}
	return passwd;
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

#if defined(_WIN32)
	/* Windows: use _getch() to read characters without echo */
	int ch = 0;
	while (true)
	{
		ch = _getch();
		if (ch == 0 || ch == 224)
		{
			/* handle function/special keys: read and ignore the next code */
			int next = _getch();
			(void)next;
			continue;
		}
		if (ch == 13 || ch == '\n') // Enter
			break;
		if ((ch == 3)) // Ctrl-C
		{
			/* emulate interruption: return 0 length */
			idx = 0;
			break;
		}
		if (ch == 8 || ch == 127) // Backspace / Delete
		{
			if (idx > 0)
			{
				if (31 < mask && mask < 127)
				{
					/* move cursor back, overwrite with space, move back */
					fputc(0x8, stdout);
					fputc(' ', stdout);
					fputc(0x8, stdout);
					fflush(stdout);
				}
				(*pw)[--idx] = 0;
			}
			continue;
		}
		/* regular character */
		if (idx < sz - 1)
		{
			(*pw)[idx++] = static_cast<char>(ch);
			if (31 < mask && mask < 127)
			{
				fputc(mask, stdout);
				fflush(stdout);
			}
		}
		else
		{
			/* if buffer full but user keeps typing, optionally ring bell */
			fputc('\a', stdout);
			fflush(stdout);
		}
	}
	(*pw)[idx] = 0; /* null-terminate   */

#else
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
#endif

	if (idx == sz - 1) /* warn if pw truncated */
		fprintf(stderr, " (%s() warning: truncated at %zu chars.)\n", __func__, sz - 1);

	return idx; /* number of chars in passwd    */
}

const std::string ArgumentParser::getAppMeshUrl()
{
	std::string url = APPMESH_LOCAL_HOST_URL;
	auto file = Utility::getConfigFilePath(APPMESH_CONFIG_YAML_FILE);
	if (file.length() > 0)
	{
		auto config = YAML::LoadFile(file);
		if (config[JSON_KEY_REST].IsDefined() && config[JSON_KEY_REST][JSON_KEY_RestListenPort].IsDefined())
		{
			auto port = config[JSON_KEY_REST][JSON_KEY_RestListenPort].as<int>();
			auto address = config[JSON_KEY_REST][JSON_KEY_RestListenAddress].Scalar();
			auto restConfig = config[JSON_KEY_REST];
			if (restConfig[JSON_KEY_SSL].IsDefined())
			{
				auto sslConfig = restConfig[JSON_KEY_SSL];
				ClientSSLConfig config;
				if (sslConfig[JSON_KEY_SSLVerifyClient].IsDefined())
					config.m_verify_client = sslConfig[JSON_KEY_SSLVerifyClient].as<bool>();
				if (sslConfig[JSON_KEY_SSLVerifyServer].IsDefined())
					config.m_verify_server = sslConfig[JSON_KEY_SSLVerifyServer].as<bool>();
				if (sslConfig[JSON_KEY_SSLClientCertificateFile].IsDefined())
					config.m_certificate = sslConfig[JSON_KEY_SSLClientCertificateFile].Scalar();
				if (sslConfig[JSON_KEY_SSLClientCertificateKeyFile].IsDefined())
					config.m_private_key = sslConfig[JSON_KEY_SSLClientCertificateKeyFile].Scalar();
				if (sslConfig[JSON_KEY_SSLCaPath].IsDefined())
					config.m_ca_location = sslConfig[JSON_KEY_SSLCaPath].Scalar();
				config.ResolveAbsolutePaths(Utility::getHomeDir());
				RestClient::defaultSslConfiguration(config);
			}
			url = Utility::stringFormat("https://%s:%d", readPersistLastHost(address).c_str(), port);
		}
	}
	return Utility::stringReplace(url, "0.0.0.0", "127.0.0.1");
}

const std::string ArgumentParser::getPosixTimezone()
{
	const auto file = Utility::getConfigFilePath(APPMESH_CONFIG_YAML_FILE);
	if (Utility::isFileExist(file))
	{
		return YAML::LoadFile(file)[JSON_KEY_BaseConfig][JSON_KEY_PosixTimezone].as<std::string>();
	}
	return "";
}

const std::string ArgumentParser::parseUrlHost(const std::string &url)
{
	// https://stackoverflow.com/questions/2616011/easy-way-to-parse-a-url-in-c-cross-platform
	std::string domain;
	boost::regex ex("(http|https)://([^/ :]+):?([^/ ]*)(/?[^ #?]*)\\x3f?([^ #]*)#?([^ ]*)");
	boost::cmatch what;
	if (boost::regex_match(url.c_str(), what, ex))
	{
		// std::string protocol = std::string(what[1].first, what[1].second);
		domain = std::string(what[2].first, what[2].second);
		// std::string port = std::string(what[3].first, what[3].second);
		// std::string path = std::string(what[4].first, what[4].second);
		// std::string query = std::string(what[5].first, what[5].second);
	}
	return domain;
}

const std::string ArgumentParser::parseUrlPort(const std::string &url)
{
	// https://stackoverflow.com/questions/2616011/easy-way-to-parse-a-url-in-c-cross-platform
	std::string port;
	boost::regex ex("(http|https)://([^/ :]+):?([^/ ]*)(/?[^ #?]*)\\x3f?([^ #]*)#?([^ ]*)");
	boost::cmatch what;
	if (boost::regex_match(url.c_str(), what, ex))
	{
		port = std::string(what[3].first, what[3].second);
	}
	return port;
}

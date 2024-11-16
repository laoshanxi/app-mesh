#include <atomic>
#include <chrono>
#include <termios.h>
#include <thread>
#include <unistd.h>

#include <ace/Signal.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/io/ios_state.hpp>
#include <boost/program_options.hpp>
#include <boost/regex.hpp>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <nlohmann/json.hpp>
#include <readline/history.h>
#include <readline/readline.h>

#include "../../common/DateTime.h"
#include "../../common/DurationParse.h"
#include "../../common/Password.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.hpp"
#include "ArgumentParser.h"

#define OPTION_URL \
	("url,b", po::value<std::string>()->default_value(m_defaultUrl), "Server URL") \
	("forward,z", po::value<std::string>()->default_value(""), "Target host (or with port) for request forwarding")

#define COMMON_OPTIONS                                                                                              \
	OPTION_URL                                                                                                      \
	("user,u", po::value<std::string>(), "User name") \
	("password,x", po::value<std::string>(), "User password") \
	("verbose,V", "Enable verbose output")

#define GET_USER_NAME_PASS                                                                \
	if (m_commandLineVariables.count("password") && m_commandLineVariables.count("user")) \
	{                                                                                     \
		m_username = m_commandLineVariables["user"].as<std::string>();                    \
		m_userpwd = m_commandLineVariables["password"].as<std::string>();                 \
	}                                                                                     \
	log4cpp::Category::getRoot().setPriority(m_commandLineVariables.count("verbose") ? log4cpp::Priority::DEBUG : log4cpp::Priority::INFO);

#define HELP_ARG_CHECK_WITH_RETURN                \
	GET_USER_NAME_PASS                            \
	if (m_commandLineVariables.count("help") > 0) \
	{                                             \
		std::cout << desc << std::endl;           \
		return;                                   \
	}                                             \
	m_currentUrl = m_commandLineVariables["url"].as<std::string>(); \
	m_forwardingHost = m_commandLineVariables["forward"].as<std::string>();
#define HELP_ARG_CHECK_WITH_RETURN_ZERO           \
	GET_USER_NAME_PASS                            \
	if (m_commandLineVariables.count("help") > 0) \
	{                                             \
		std::cout << desc << std::endl;           \
		return 0;                                 \
	}                                             \
	m_currentUrl = m_commandLineVariables["url"].as<std::string>(); \
	m_forwardingHost = m_commandLineVariables["forward"].as<std::string>();
// Each user should have its own token path
static std::string m_tokenFile = std::string(getenv("HOME") ? getenv("HOME") : ".") + "/.appmesh.config";
const static std::string m_shellHistoryFile = std::string(getenv("HOME") ? getenv("HOME") : ".") + "/.appmesh.shell.history";
extern char **environ;

// Global variable for appc exec
static bool SIGINIT_BREAKING = false;
static std::atomic_bool READING_LINE(false);
static std::string APPC_EXEC_APP_NAME;
static ArgumentParser *WORK_PARSE = nullptr;
// command line help width
static size_t BOOST_DESC_WIDTH = 130;

ArgumentParser::ArgumentParser(int argc, const char *argv[])
	: m_argc(argc), m_argv(argv), m_tokenTimeoutSeconds(DEFAULT_TOKEN_EXPIRE_SECONDS)
{
	const std::string posixTimeZone = ACE_OS::getenv(ENV_APPMESH_POSIX_TIMEZONE) ? ACE_OS::getenv(ENV_APPMESH_POSIX_TIMEZONE) : getPosixTimezone();
	Utility::initDateTimeZone(posixTimeZone, false);
}

void ArgumentParser::initArgs()
{
	WORK_PARSE = this;
	m_defaultUrl = this->getAppMeshUrl();
	static std::atomic_flag flag = ATOMIC_FLAG_INIT;
	if (!flag.test_and_set(std::memory_order_acquire) && getuid() == 0 && getenv("SUDO_USER") && getpwnam(getenv("SUDO_USER")))
	{
		m_tokenFile = std::string(getpwnam(getenv("SUDO_USER"))->pw_dir) + "/.appmesh.config";
		seteuid(getpwnam(getenv("SUDO_USER"))->pw_uid);
	}
	po::options_description global("Global options", BOOST_DESC_WIDTH);
	global.add_options()
	("command", po::value<std::string>(), "Command to execute.")
	("subargs", po::value<std::vector<std::string>>(), "Arguments for command.");

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
	else if (cmd == "cloud")
	{
		processCloudAppView();
	}
	else if (cmd == "nodes")
	{
		processCloudNodesView();
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
		processUserMfaActive();
	}
	else if (cmd == "lock")
	{
		processUserLock();
	}
	else if (cmd == "user")
	{
		processUserView();
	}
	else if (cmd == "join")
	{
		processCloudJoinMaster();
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
	std::cout << "  - Run 'appc COMMAND --help' for detailed command usage" << std::endl;
	std::cout << "  - Remote connection: Use '-b $server_url' (e.g., https://127.0.0.1:6060)" << std::endl;
	std::cout << "  - All commands support --help flag for detailed options" << std::endl
			  << std::endl;
}

void ArgumentParser::processLogon()
{
	po::options_description desc("Log in to App Mesh", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("timeout,t", po::value<std::string>()->default_value(std::to_string(DEFAULT_TOKEN_EXPIRE_SECONDS)), "Session duration in seconds or ISO 8601 format.")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	m_tokenTimeoutSeconds = DurationParse::parse(m_commandLineVariables["timeout"].as<std::string>());
	if (!m_commandLineVariables.count("user"))
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
		m_username = m_commandLineVariables["user"].as<std::string>();
	}

	if (!m_commandLineVariables.count("password"))
	{
		if (!m_commandLineVariables.count("user"))
		{
			std::cin.clear();
			std::cin.ignore(1024, '\n');
		}
		while (m_userpwd.length() == 0)
		{
			std::cout << "Password: ";
			char buffer[256] = {0};
			char *str = buffer;
			FILE *fp = stdin;
			inputSecurePasswd(&str, sizeof(buffer), '*', fp);
			m_userpwd = buffer;
			std::cout << std::endl;
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
	po::options_description desc("Logoff to App Mesh", BOOST_DESC_WIDTH);
	desc.add_options()
		OPTION_URL
		("help,h", "Display command usage and exit.");
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
	po::options_description desc("Print current user", BOOST_DESC_WIDTH);
	desc.add_options()
		OPTION_URL
		("help,h", "Display command usage and exit.");
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
		auto decoded_token = jwt::decode(token);
		if (decoded_token.has_payload_claim(HTTP_HEADER_JWT_name))
		{
			// get user info
			userName = decoded_token.get_payload_claim(HTTP_HEADER_JWT_name).as_string();
		}
	}
	return userName;
}

// appName is null means this is a normal application (not a shell application)
void ArgumentParser::processAppAdd()
{
	const std::string default_control_string = "0:standby";
	po::options_description desc("Register a new application", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("name,n", po::value<std::string>(), "Application name (required)")
		("desc,a", po::value<std::string>(), "Application description")
		("metadata,g", po::value<std::string>(), "Metadata string/JSON (stdin input, '@' for file input)")
		("perm", po::value<int>(), "Permission bits [group & other] (1=deny, 2=read, 3=write)")
		("cmd,c", po::value<std::string>(), "Command line with arguments (required)")
		("shell,S", "Enable shell mode for multiple commands")
		("session_login", "Execute with session login context")
		("health_check,l", po::value<std::string>(), "Health check command (returns 0 for healthy)")
		("docker_image,d", po::value<std::string>(), "Docker image for containerized execution")
		("workdir,w", po::value<std::string>(), "Working directory path")
		("status,s", po::value<bool>()->default_value(true), "Initial status (true=enabled, false=disabled)")
		("start_time,t", po::value<std::string>(), "Start time (ISO8601: '2020-10-11T09:22:05')")
		("end_time,E", po::value<std::string>(), "End time (ISO8601: '2020-10-11T10:22:05')")
		("daily_start,j", po::value<std::string>(), "Daily start time ('09:00:00+08')")
		("daily_end,y", po::value<std::string>(), "Daily end time ('20:00:00+08')")
		("memory,m", po::value<int>(), "Memory limit (MB)")
		("virtual_memory,v", po::value<int>(), "Virtual memory limit (MB)")
		("cpu_shares,r", po::value<int>(), "CPU shares (relative weight)")
		("pid,p", po::value<int>(), "Attach to existing process ID")
		("stdout_cache_num,O", po::value<int>()->default_value(3), "Number of stdout cache files")
		("env,e", po::value<std::vector<std::string>>(), "Environment variables (-e env1=value1 -e env2=value2, APP_DOCKER_OPTS env is used to input docker run parameters)")
		("sec_env", po::value<std::vector<std::string>>(), "Encrypted environment variables in server side with application owner's cipher")
		("interval,i", po::value<std::string>(), "Start interval (ISO8601 duration or cron: 'P1Y2M3DT4H5M6S', '* */5 * * * *')")
		("cron", "Use cron expression for interval")
		("retention,q", po::value<std::string>(), "Process stop timeout (ISO8601 duration: 'P1Y2M3DT4H5M6S')")
		("exit", po::value<std::string>()->default_value(JSON_KEY_APP_behavior_standby), "Exit behavior [restart|standby|keepalive|remove]")
		("control", po::value<std::vector<std::string>>(), "Exit code behaviors (--control CODE:ACTION, overrides default exit)")
		("force,f", "Skip confirmation prompts")
		("stdin", po::value<std::string>(), "Read YAML from stdin ('std') or file")
		("help,h", "Display command usage and exit");

	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;
	if (m_commandLineVariables.count("stdin") == 0 && (m_commandLineVariables.count("name") == 0 ||
		(m_commandLineVariables.count("docker_image") == 0 && m_commandLineVariables.count("cmd") == 0)))
	{
		std::cout << desc << std::endl;
		return;
	}

	if (m_commandLineVariables.count("interval") > 0 && m_commandLineVariables.count("retention") > 0)
	{
		if (DurationParse::parse(m_commandLineVariables["interval"].as<std::string>()) <=
			DurationParse::parse(m_commandLineVariables["retention"].as<std::string>()))
		{
			std::cout << "The retention seconds must less than interval." << std::endl;
			return;
		}
	}
	nlohmann::json jsonObj;
	if (m_commandLineVariables.count("stdin"))
	{
		const auto inputJson = m_commandLineVariables["stdin"].as<std::string>();
		std::string inputContent;
		if (inputJson == "std")
			inputContent = Utility::readStdin2End();
		else
			inputContent = Utility::readFileCpp(inputJson);
		// parse yaml
		jsonObj = Utility::yamlToJson(YAML::Load(inputContent));
	}

	std::string appName;
	if (m_commandLineVariables.count("stdin"))
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
		if (m_commandLineVariables.count("name") == 0)
		{
			std::cout << "Can not find application name" << std::endl;
			return;
		}
		appName = m_commandLineVariables["name"].as<std::string>();
	}

	if (isAppExist(appName))
	{
		if (m_commandLineVariables.count("force") == 0 && (m_commandLineVariables.count("stdin") == 0 || m_commandLineVariables["stdin"].as<std::string>() != "std"))
		{
			std::cout << "Application already exist, are you sure you want to update the application <" << appName << ">?" << std::endl;
			if (!confirmInput("[y/n]:"))
			{
				return;
			}
		}
	}

	if (m_commandLineVariables.count("exit"))
	{
		auto hebavior = m_commandLineVariables["exit"].as<std::string>();
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
	if (m_commandLineVariables.count(JSON_KEY_APP_behavior_control))
	{
		auto controls = m_commandLineVariables[JSON_KEY_APP_behavior_control].as<std::vector<std::string>>();
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
	if (m_commandLineVariables.count("name"))
		jsonObj[JSON_KEY_APP_name] = std::string(m_commandLineVariables["name"].as<std::string>());
	if (m_commandLineVariables.count("cmd"))
		jsonObj[JSON_KEY_APP_command] = std::string(m_commandLineVariables["cmd"].as<std::string>());
	if (m_commandLineVariables.count("desc"))
		jsonObj[JSON_KEY_APP_description] = std::string(m_commandLineVariables["desc"].as<std::string>());
	jsonObj[JSON_KEY_APP_shell_mode] = (m_commandLineVariables.count("shell") > 0);
	jsonObj[JSON_KEY_APP_session_login] = (m_commandLineVariables.count("session_login") > 0);
	if (m_commandLineVariables.count("health_check"))
		jsonObj[JSON_KEY_APP_health_check_cmd] = std::string(m_commandLineVariables["health_check"].as<std::string>());
	if (m_commandLineVariables.count("perm"))
		jsonObj[JSON_KEY_APP_owner_permission] = (m_commandLineVariables["perm"].as<int>());
	if (m_commandLineVariables.count("workdir"))
		jsonObj[JSON_KEY_APP_working_dir] = std::string(m_commandLineVariables["workdir"].as<std::string>());
	if (m_commandLineVariables.count("status"))
		jsonObj[JSON_KEY_APP_status] = (m_commandLineVariables["status"].as<bool>() ? 1 : 0);
	if (m_commandLineVariables.count(JSON_KEY_APP_metadata))
	{
		auto metaData = m_commandLineVariables[JSON_KEY_APP_metadata].as<std::string>();
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
	if (m_commandLineVariables.count("docker_image"))
		jsonObj[JSON_KEY_APP_docker_image] = std::string(m_commandLineVariables["docker_image"].as<std::string>());
	if (m_commandLineVariables.count("start_time"))
		jsonObj[JSON_KEY_SHORT_APP_start_time] = (std::chrono::duration_cast<std::chrono::seconds>(DateTime::parseISO8601DateTime(m_commandLineVariables["start_time"].as<std::string>()).time_since_epoch()).count());
	if (m_commandLineVariables.count("end_time"))
		jsonObj[JSON_KEY_SHORT_APP_end_time] = (std::chrono::duration_cast<std::chrono::seconds>(DateTime::parseISO8601DateTime(m_commandLineVariables["end_time"].as<std::string>()).time_since_epoch()).count());
	if (m_commandLineVariables.count("interval"))
	{
		jsonObj[JSON_KEY_SHORT_APP_start_interval_seconds] = std::string(m_commandLineVariables["interval"].as<std::string>());
		jsonObj[JSON_KEY_SHORT_APP_cron_interval] = (m_commandLineVariables.count("cron") > 0);
	}
	if (m_commandLineVariables.count(JSON_KEY_APP_retention))
		jsonObj[JSON_KEY_APP_retention] = std::string(m_commandLineVariables["retention"].as<std::string>());
	if (m_commandLineVariables.count("stdout_cache_num"))
		jsonObj[JSON_KEY_APP_stdout_cache_num] = (m_commandLineVariables["stdout_cache_num"].as<int>());
	if (m_commandLineVariables.count("daily_start") && m_commandLineVariables.count("daily_end"))
	{
		nlohmann::json objDailyLimitation = nlohmann::json::object();
		objDailyLimitation[JSON_KEY_DAILY_LIMITATION_daily_start] = (DateTime::parseDayTimeUtcDuration(m_commandLineVariables["daily_start"].as<std::string>()).total_seconds());
		objDailyLimitation[JSON_KEY_DAILY_LIMITATION_daily_end] = (DateTime::parseDayTimeUtcDuration(m_commandLineVariables["daily_end"].as<std::string>()).total_seconds());
		jsonObj[JSON_KEY_APP_daily_limitation] = objDailyLimitation;
	}

	if (m_commandLineVariables.count("memory") || m_commandLineVariables.count("virtual_memory") ||
		m_commandLineVariables.count("cpu_shares"))
	{
		nlohmann::json objResourceLimitation = nlohmann::json::object();
		if (m_commandLineVariables.count("memory"))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_memory_mb] = (m_commandLineVariables["memory"].as<int>());
		if (m_commandLineVariables.count("virtual_memory"))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb] = (m_commandLineVariables["virtual_memory"].as<int>());
		if (m_commandLineVariables.count("cpu_shares"))
			objResourceLimitation[JSON_KEY_RESOURCE_LIMITATION_cpu_shares] = (m_commandLineVariables["cpu_shares"].as<int>());
		jsonObj[JSON_KEY_APP_resource_limit] = objResourceLimitation;
	}

	if (m_commandLineVariables.count(JSON_KEY_APP_env))
	{
		std::vector<std::string> envs = m_commandLineVariables[JSON_KEY_APP_env].as<std::vector<std::string>>();
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
	if (m_commandLineVariables.count(JSON_KEY_APP_sec_env))
	{
		std::vector<std::string> envs = m_commandLineVariables[JSON_KEY_APP_sec_env].as<std::vector<std::string>>();
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
	if (m_commandLineVariables.count("pid"))
		jsonObj[JSON_KEY_APP_pid] = (m_commandLineVariables["pid"].as<int>());
	std::string restPath = std::string("/appmesh/app/") + appName;
	auto resp = requestHttp(true, web::http::methods::PUT, restPath, &jsonObj);
	std::cout << Utility::jsonToYaml(nlohmann::json::parse(resp->text)) << std::endl;
}

void ArgumentParser::processAppDel()
{
	po::options_description desc("Remove an application", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("name,n", po::value<std::vector<std::string>>(), "Application name(s).")
		("force,f", "force without confirm.")
		("help,h", "Display command usage and exit.");

	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count("name") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	auto appNames = m_commandLineVariables["name"].as<std::vector<std::string>>();
	for (auto &appName : appNames)
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
			auto response = requestHttp(true, web::http::methods::DEL, restPath);
			std::cout << parseOutputMessage(response) << std::endl;
		}
		else
		{
			throw std::invalid_argument(Utility::stringFormat("No such application <%s>", appName.c_str()));
		}
	}
}

void ArgumentParser::processAppView()
{
	po::options_description desc("List applications", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("name,n", po::value<std::string>(), "Application name.")
		("long,l", "Display complete information without reduction.")
		("output,o", "View application output.")
		("pstree,p", "View application process tree.")
		("stdout_index,O", po::value<int>(), "Application output index.")
		("tail,t", "Continuously view application output.")
		("json,j", "Display with JSON format.")
		("help,h", "Display command usage and exit.");

	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	bool reduce = !(m_commandLineVariables.count("long"));
	if (m_commandLineVariables.count("name") > 0)
	{
		if (!m_commandLineVariables.count("output"))
		{
			std::string restPath = std::string("/appmesh/app/") + m_commandLineVariables["name"].as<std::string>();
			auto resp = nlohmann::json::parse(requestHttp(true, web::http::methods::GET, restPath)->text);
			if (m_commandLineVariables.count("pstree"))
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
				if (m_commandLineVariables.count("json"))
					std::cout << Utility::prettyJson(resp.dump()) << std::endl;
				else
					std::cout << Utility::jsonToYaml(resp) << std::endl;
			}
		}
		else
		{
			// view app output
			int index = 0;
			std::string restPath = std::string("/appmesh/app/") + m_commandLineVariables["name"].as<std::string>() + "/output";
			if (m_commandLineVariables.count("stdout_index"))
			{
				index = m_commandLineVariables["stdout_index"].as<int>();
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
				if (m_commandLineVariables.count("tail") == 0)
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

void ArgumentParser::processCloudAppView()
{
	po::options_description desc("List cloud applications", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("name,n", po::value<std::string>(), "Application name.")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/cloud/applications";
	if (m_commandLineVariables.count("name") > 0)
	{
		restPath = std::string("/appmesh/cloud/app/").append(m_commandLineVariables["name"].as<std::string>());
	}
	auto resp = requestHttp(true, web::http::methods::GET, restPath);
	std::cout << Utility::prettyJson(resp->text) << std::endl;
}

void ArgumentParser::processCloudNodesView()
{
	po::options_description desc("List cluster nodes", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/cloud/nodes";
	auto resp = requestHttp(true, web::http::methods::GET, restPath);
	std::cout << Utility::prettyJson(resp->text) << std::endl;
}

void ArgumentParser::processResource()
{
	po::options_description desc("View host resource usage", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/resources";
	auto resp = requestHttp(true, web::http::methods::GET, restPath);
	std::cout << Utility::prettyJson(resp->text) << std::endl;
}

void ArgumentParser::processAppControl(bool start)
{
	po::options_description desc("Control application", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("all,a", "Apply to all applications.")
		("name,n", po::value<std::vector<std::string>>(), "Application name(s) to control.")
		("help,h", "Display command usage and exit.");

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
		std::string restPath = std::string("/appmesh/app/") + app + +"/" + (start ? HTTP_QUERY_KEY_action_start : HTTP_QUERY_KEY_action_stop);
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
	po::options_description desc("Run commands or applications", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("desc,a", po::value<std::string>(), "Application description.")
		("cmd,c", po::value<std::string>(), "Full command line with arguments (not needed for running an application).")
		("shell,S", "Use shell mode; cmd can be multiple shell commands in string format.")
		("session_login", "Run with session login.")
		("name,n", po::value<std::string>(), "Existing application name to run, or specify a name for a new run; defaults to a random name if empty.")
		("metadata,g", po::value<std::string>(), "Metadata string/JSON (input for application, passed to process stdin), '@' allowed to read from file.")
		("workdir,w", po::value<std::string>(), "Working directory (default '/opt/appmesh/work').")
		("env,e", po::value<std::vector<std::string>>(), "Environment variables (e.g., -e env1=value1 -e env2=value2).")
		("lifecycle,l", po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_LIFECYCLE_SECONDS)), "Maximum lifecycle time (in seconds) for the command run. Default is 12 hours; supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').")
		("timeout,t", po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_TIMEOUT_SECONDS)), "Maximum time (in seconds) for the command run. Greater than 0 means output can be printed repeatedly, less than 0 means output will be printed until the process exits; supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN_ZERO;

	int returnCode = 0;
	if (m_commandLineVariables.count("help") || (m_commandLineVariables.count("name") == 0 && m_commandLineVariables.count("cmd") == 0))
	{
		std::cout << desc << std::endl;
		return returnCode;
	}

	std::map<std::string, std::string> query;
	int timeout = DurationParse::parse(m_commandLineVariables["timeout"].as<std::string>());
	int lifecycle = DurationParse::parse(m_commandLineVariables["lifecycle"].as<std::string>());
	query[HTTP_QUERY_KEY_timeout] = std::to_string(std::abs(timeout));
	query[HTTP_QUERY_KEY_lifecycle] = std::to_string(std::abs(lifecycle));

	nlohmann::json jsonObj;
	nlohmann::json jsonBehavior;
	jsonBehavior[JSON_KEY_APP_behavior_exit] = std::string(JSON_KEY_APP_behavior_remove);
	jsonObj[JSON_KEY_APP_behavior] = std::move(jsonBehavior);
	if (m_commandLineVariables.count("cmd"))
		jsonObj[JSON_KEY_APP_command] = std::string(m_commandLineVariables["cmd"].as<std::string>());
	if (m_commandLineVariables.count("desc"))
		jsonObj[JSON_KEY_APP_description] = std::string(m_commandLineVariables["desc"].as<std::string>());
	jsonObj[JSON_KEY_APP_shell_mode] = (m_commandLineVariables.count("shell") > 0);
	jsonObj[JSON_KEY_APP_session_login] = (m_commandLineVariables.count("session_login") > 0);
	if (m_commandLineVariables.count(JSON_KEY_APP_name))
		jsonObj[JSON_KEY_APP_name] = std::string(m_commandLineVariables["name"].as<std::string>());
	if (m_commandLineVariables.count(JSON_KEY_APP_metadata))
	{
		auto metaData = m_commandLineVariables[JSON_KEY_APP_metadata].as<std::string>();
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
	if (m_commandLineVariables.count("workdir"))
		jsonObj[JSON_KEY_APP_working_dir] = std::string(m_commandLineVariables["workdir"].as<std::string>());
	if (m_commandLineVariables.count("env"))
	{
		std::vector<std::string> envs = m_commandLineVariables["env"].as<std::vector<std::string>>();
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
			std::cout << response->text << std::flush;
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

void SIGINT_Handler(int signo)
{
	std::cout << std::endl;
	// make sure we only process SIGINT here
	// SIGINT 	ctrl - c
	assert(signo == SIGINT);
	SIGINIT_BREAKING = true;
	const auto restPath = std::string("/appmesh/app/").append(APPC_EXEC_APP_NAME);
	WORK_PARSE->requestHttp(false, web::http::methods::DEL, restPath);
	if (READING_LINE.load())
	{
		rl_replace_line("", 0); // Clean up after the signal and redraw the prompt
		rl_on_new_line();		// Notify readline that we're on a new line
		rl_redisplay();			// Redisplay the prompt
	}
}

std::string ArgumentParser::parseOutputMessage(std::shared_ptr<CurlResponse> &resp)
{
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
			return Utility::prettyJson(resp->text);
		}
	}
	catch (...)
	{
	}
	return resp->text;
}

void ArgumentParser::regSignal()
{
	m_sigAction = std::make_unique<ACE_Sig_Action>();
	m_sigAction->handler(SIGINT_Handler);
	m_sigAction->register_action(SIGINT);
}

void ArgumentParser::unregSignal()
{
	if (m_sigAction)
		m_sigAction = nullptr;
}

pid_t get_bash_pid()
{
	pid_t pid = getpid();

	// VSCode uses an integrated terminal that spawns its own Bash shell process.
	// This shell process remains persistent across terminal sessions,
	// meaning that the same Bash process is reused for all the commands executed in that terminal
	// until you explicitly close the terminal or VSCode.
	if (getenv("VSCODE_PID"))
	{
		return pid;
	}

	pid_t ppid = getppid();

	while (ppid != 1) // 1 is the init process
	{
		std::string proc_path = "/proc/" + std::to_string(ppid) + "/comm";
		std::ifstream comm_file(proc_path);
		std::string comm;
		std::getline(comm_file, comm);

		if (comm == "bash")
			return ppid;

		// Move up the process tree
		pid = ppid;
		proc_path = "/proc/" + std::to_string(pid) + "/stat";
		std::ifstream stat_file(proc_path);
		std::string stat_line;
		std::getline(stat_file, stat_line);

		// Extract parent PID from stat file
		size_t pos = stat_line.find(')');
		if (pos != std::string::npos)
			sscanf(stat_line.c_str() + pos + 2, "%*c %d", &ppid);
		else
			return ppid; // Error
	}
	return ppid; // No bash found in the process tree
}

int ArgumentParser::processShell()
{
	po::options_description desc("Shell execute", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("retry,r", "Retry command until success.")
		("lifecycle,l", po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_LIFECYCLE_SECONDS)), "Maximum lifecycle time (in seconds) for the command run. Default is 12 hours; supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').")
		("timeout,t", po::value<std::string>()->default_value(std::to_string(DEFAULT_RUN_APP_TIMEOUT_SECONDS)), "Maximum time (in seconds) for the command run. Greater than 0 means output can be printed repeatedly, less than 0 means output will be printed until the process exits; supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc, true);
	HELP_ARG_CHECK_WITH_RETURN_ZERO;

	bool retry = m_commandLineVariables.count("retry");
	int returnCode = 0;
	// Get current session id (bash pid)
	auto bashId = get_bash_pid();
	// Get appmesh user
	auto appmeshUser = getAuthenUser();
	// Get current user name
	auto osUser = Utility::getUsernameByUid();
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
	jsonObj[JSON_KEY_APP_session_login] = (true);
	jsonObj[JSON_KEY_APP_command] = std::string(initialCmd);
	jsonObj[JSON_KEY_APP_description] = std::string("App Mesh exec environment");
	jsonObj[JSON_KEY_APP_env] = objEnvs;
	jsonObj[JSON_KEY_APP_working_dir] = std::string(getcwd(buff, sizeof(buff)));
	nlohmann::json behavior;
	behavior[JSON_KEY_APP_behavior_exit] = std::string(JSON_KEY_APP_behavior_remove);
	jsonObj[JSON_KEY_APP_behavior] = behavior;
	std::map<std::string, std::string> query;
	int timeout = DurationParse::parse(m_commandLineVariables["timeout"].as<std::string>());
	int lifecycle = DurationParse::parse(m_commandLineVariables["lifecycle"].as<std::string>());

	auto sleepSeconds = [](int sec) -> bool
	{ACE_OS::sleep(sec);	return true; };
	SIGINIT_BREAKING = false; // if ctrl + c is triggered, stop run and start read input from stdin
	this->regSignal();		  // capture SIGINT
	// clean
	requestHttp(false, web::http::methods::DEL, std::string("/appmesh/app/").append(APPC_EXEC_APP_NAME));
	if (unrecognized.size())
	{
		// run once
		do
		{
			returnCode = runAsyncApp(jsonObj, timeout, lifecycle);
		} while (retry && returnCode != 0 && !SIGINIT_BREAKING && sleepSeconds(1));
	}
	else
	{
		// shell interactive
		auto response = requestHttp(true, web::http::methods::GET, std::string("/appmesh/user/self"));
		auto execUser = nlohmann::json::parse(response->text)[JSON_KEY_USER_exec_user_override].get<std::string>();
		std::cout << "Connected to <" << appmeshUser << "@" << m_currentUrl << "> as exec user <" << execUser << ">" << std::endl;

		std::ofstream(m_shellHistoryFile, std::ios::trunc).close();
		using_history();
		read_history(m_shellHistoryFile.c_str());
		const static char *prompt = "appmesh> ";
		while (true)
		{
			READING_LINE.store(true);
			char *input = readline(prompt);
			READING_LINE.store(false);
			if (input == nullptr)
			{
				std::cout << "End of input (Ctrl+D pressed)" << std::endl;
				break;
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
					add_history(cmd.c_str());
					saveUserCmdHistory(cmd.c_str());
				}

				SIGINIT_BREAKING = false; // reset breaking to normal after read a input
				if (cmd == "exit" || cmd == "q")
				{
					break;
				}
				jsonObj[JSON_KEY_APP_command] = cmd;
				do
				{
					returnCode = runAsyncApp(jsonObj, timeout, lifecycle);
				} while (retry && returnCode != 0 && !SIGINIT_BREAKING && sleepSeconds(1));
			}
		}
	}
	return returnCode;
}

void ArgumentParser::saveUserCmdHistory(const char *input)
{
	std::ofstream outfile;
	outfile.open(m_shellHistoryFile, std::ios_base::app); // append instead of overwrite
	if (outfile.is_open())
	{
		outfile << input << std::endl;
		outfile.close();
	}
	else
	{
		std::cerr << "Unable to open history file: " << m_shellHistoryFile << std::endl;
	}
}

void ArgumentParser::processFileDownload()
{
	po::options_description desc("Download file", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("remote,r", po::value<std::string>(), "Remote file path to download.")
		("local,l", po::value<std::string>(), "Local file path to save.")
		("noattr,a", "Not copy file attributes.")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.count("remote") == 0 || m_commandLineVariables.count("local") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	std::string restPath = REST_PATH_DOWNLOAD;
	auto file = m_commandLineVariables["remote"].as<std::string>();
	auto local = m_commandLineVariables["local"].as<std::string>();

	// header
	std::map<std::string, std::string> header;
	header.insert({HTTP_HEADER_KEY_file_path, file});
	header.insert({HTTP_HEADER_JWT_Authorization, std::string(HTTP_HEADER_JWT_BearerSpace) + getAuthenToken()});
	auto response = RestClient::download(m_currentUrl, restPath, file, local, header);

	if (m_commandLineVariables.count("noattr") == 0)
		Utility::applyFilePermission(local, response->header);
	if (response->status_code == web::http::status_codes::OK)
		std::cout << "Download remote file <" << file << "> to local <" << local << "> size <" << Utility::humanReadableSize(std::ifstream(local).seekg(0, std::ios::end).tellg()) << ">" << std::endl;
	else
		throw std::invalid_argument(parseOutputMessage(response));
}

void ArgumentParser::processFileUpload()
{
	po::options_description desc("Upload file", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("remote,r", po::value<std::string>(), "Remote file path to save.")
		("local,l", po::value<std::string>(), "Local file to upload.")
		("noattr,a", "Not copy file attributes.")
		("help,h", "Display command usage and exit.");
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
	local = boost::filesystem::canonical(local).string();
	std::string restPath = REST_PATH_UPLOAD;

	// header
	std::map<std::string, std::string> header;
	header.insert({HTTP_HEADER_KEY_file_path, file});
	header.insert({HTTP_HEADER_JWT_Authorization, std::string(HTTP_HEADER_JWT_BearerSpace) + getAuthenToken()});
	if (m_commandLineVariables.count("noattr") == 0)
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
	po::options_description desc("Manage labels", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("view,v", "List labels.")
		("add,a", "Add labels.")
		("remove,r", "Remove labels.")
		("label,l", po::value<std::vector<std::string>>(), "Labels (e.g., -l os=linux -l arch=arm64).")
		("help,h", "Display command usage and exit.");
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
	else if (m_commandLineVariables.count("remove") &&
			 !m_commandLineVariables.count("add") && !m_commandLineVariables.count("view"))
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
	po::options_description desc("Set log level", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("level,l", po::value<std::string>(), "Log level (e.g., DEBUG, INFO, NOTICE, WARN, ERROR).")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.size() == 0 || m_commandLineVariables.count("level") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	auto level = m_commandLineVariables["level"].as<std::string>();

	nlohmann::json jsonObj = {
		{JSON_KEY_BaseConfig, {{JSON_KEY_LogLevel, level}}}};
	// /app-manager/config
	auto restPath = std::string("/appmesh/config");
	auto response = requestHttp(true, web::http::methods::POST, restPath, &jsonObj);
	std::cout << "Log level set to: " << nlohmann::json::parse(response->text).at(JSON_KEY_BaseConfig).at(JSON_KEY_LogLevel).get<std::string>() << std::endl;
}

void ArgumentParser::processCloudJoinMaster()
{
	po::options_description desc("Join App Mesh cluster", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("consul,c", po::value<std::string>(), "Consul URL (e.g., http://localhost:8500).")
		("main,m", "Join as main node.")
		("worker,w", "Join as worker node.")
		("proxy,r", po::value<std::string>()->default_value(""), "App Mesh proxy URL.")
		("user,u", po::value<std::string>()->default_value(""), "Basic auth user name for Consul REST.")
		("pass,p", po::value<std::string>()->default_value(""), "Basic auth user password for Consul REST.")
		("ttl,l", po::value<std::int16_t>()->default_value(30), "Consul session TTL in seconds.")
		("security,s", "Enable Consul security (security persist will use Consul storage).")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (m_commandLineVariables.size() == 0 || m_commandLineVariables.count("consul") == 0)
	{
		std::cout << desc << std::endl;
		return;
	}

	nlohmann::json jsonObj;
	nlohmann::json jsonConsul;
	jsonConsul[JSON_KEY_CONSUL_URL] = std::string(m_commandLineVariables["consul"].as<std::string>());
	jsonConsul[JSON_KEY_CONSUL_IS_MAIN] = (m_commandLineVariables.count("main"));
	jsonConsul[JSON_KEY_CONSUL_IS_WORKER] = (m_commandLineVariables.count("worker"));
	jsonConsul[JSON_KEY_CONSUL_APPMESH_PROXY_URL] = std::string(m_commandLineVariables["proxy"].as<std::string>());
	jsonConsul[JSON_KEY_CONSUL_SESSION_TTL] = (m_commandLineVariables["ttl"].as<std::int16_t>());
	jsonConsul[JSON_KEY_CONSUL_SECURITY] = (m_commandLineVariables.count("security"));
	jsonConsul[JSON_KEY_CONSUL_AUTH_USER] = std::string(m_commandLineVariables["user"].as<std::string>());
	jsonConsul[JSON_KEY_CONSUL_AUTH_PASS] = std::string(m_commandLineVariables["pass"].as<std::string>());
	jsonObj[JSON_KEY_CONSUL] = std::move(jsonConsul);

	// /app-manager/config
	auto restPath = std::string("/appmesh/config");
	auto response = requestHttp(true, web::http::methods::POST, restPath, &jsonObj);
	std::cout << "App Mesh will join cluster with parameter: " << std::endl
			  << nlohmann::json::parse(response->text).at(JSON_KEY_CONSUL).dump(2, ' ') << std::endl;
}

void ArgumentParser::processConfigView()
{
	po::options_description desc("View configurations", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("view,v", "View basic configurations in JSON format.")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = "/appmesh/config";
	auto resp = requestHttp(true, web::http::methods::GET, restPath);
	std::cout << Utility::prettyJson(resp->text) << std::endl;
}

void ArgumentParser::processUserChangePwd()
{
	po::options_description desc("Change password", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("target,t", po::value<std::string>(), "Target user to change password.")
		("newpasswd,p", po::value<std::string>(), "New password.")
		("help,h", "Display command usage and exit.");
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
	auto response = requestHttp(true, web::http::methods::POST, restPath, nullptr, headers, query);
	std::cout << parseOutputMessage(response) << std::endl;
}

void ArgumentParser::processUserLock()
{
	po::options_description desc("Manage user", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("target,t", po::value<std::string>(), "Target user.")
		("lock,k", po::value<bool>(), "Lock or unlock user ('true' to lock, 'false' to unlock).")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	if (!m_commandLineVariables.count("target") || !m_commandLineVariables.count("lock"))
	{
		std::cout << desc << std::endl;
		return;
	}

	auto user = m_commandLineVariables["target"].as<std::string>();
	auto lock = !m_commandLineVariables["lock"].as<bool>();

	std::string restPath = std::string("/appmesh/user/") + user + (lock ? "/lock" : "/unlock");
	auto response = requestHttp(true, web::http::methods::POST, restPath);
	std::cout << parseOutputMessage(response) << std::endl;
}

void ArgumentParser::processUserView()
{
	po::options_description desc("View users", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("all,a", "View all users.")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string restPath = m_commandLineVariables.count("all") ? "/appmesh/users" : "/appmesh/user/self";
	auto response = requestHttp(true, web::http::methods::GET, restPath);
	std::cout << parseOutputMessage(response) << std::endl;
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
			std::cout << std::hash<std::string>()(str) << std::endl;
			std::cin >> str;
		}
	}
	else
	{
		for (auto &optStr : opts)
		{
			std::cout << std::hash<std::string>()(optStr) << std::endl;
		}
	}
}

void ArgumentParser::processUserMfaActive()
{
	po::options_description desc("Manage 2 factor authentication", BOOST_DESC_WIDTH);
	desc.add_options()
		COMMON_OPTIONS
		("delete,d", "Deactivate MFA.")
		("help,h", "Display command usage and exit.");
	shiftCommandLineArgs(desc);
	HELP_ARG_CHECK_WITH_RETURN;

	std::string userName = getLoginUser();
	if (m_commandLineVariables.count("user"))
	{
		userName = m_commandLineVariables["user"].as<std::string>();
	}
	if (userName.empty())
	{
		std::cout << "No user name specified" << std::endl;
		return;
	}

	if (m_commandLineVariables.count("delete") == 0)
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
	else
	{
		if (this->confirmInput(Utility::stringFormat("Do you want deactive 2FA for <%s> [y/n]:", userName.c_str()).c_str()))
		{
			std::string restPath = std::string("/appmesh/totp/") + userName + "/disable";
			auto response = requestHttp(true, web::http::methods::POST, restPath);
			std::cout << parseOutputMessage(response) << std::endl;
		}
	}
}

void ArgumentParser::initRadomPassword()
{
	// only for root user generate password for admin user after installation
	if (geteuid() != 0 && !Utility::runningInContainer())
	{
		std::cerr << "only root user can generate a initial password" << std::endl;
		return;
	}

	const auto flagFile = fs::path(Utility::getParentDir()) / APPMESH_WORK_DIR / APPMESH_APPMG_INIT_FLAG_FILE;
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

std::shared_ptr<CurlResponse> ArgumentParser::requestHttp(bool throwAble, const web::http::method &mtd, const std::string &path, nlohmann::json *body, std::map<std::string, std::string> header, std::map<std::string, std::string> query)
{
	if (m_jwtToken.empty())
	{
		m_jwtToken = getAuthenToken();
	}
	header[HTTP_HEADER_JWT_Authorization] = std::string(HTTP_HEADER_JWT_BearerSpace) + m_jwtToken;
	if (m_forwardingHost.length())
	{
		if (m_forwardingHost.find(':') == std::string::npos)
			header[HTTP_HEADER_KEY_Forwarding_Host] = m_forwardingHost + ":" + parseUrlPort(m_currentUrl);
		else
			header[HTTP_HEADER_KEY_Forwarding_Host] = m_forwardingHost;
	}
	auto resp = RestClient::request(m_currentUrl, mtd, path, body, header, query);
	if (throwAble && resp->status_code != web::http::status_codes::OK)
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
		token = login(m_username, m_userpwd, m_currentUrl);
	}
	else
	{
		// 2. try to read from token file
		token = readPersistAuthToken(parseUrlHost(m_currentUrl));

		// 3. try to get get default token from REST
		if (token.empty())
		{
			token = login(std::string(JWT_USER_NAME), std::string(JWT_USER_KEY), m_currentUrl);
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
			token = login(std::string(JWT_USER_NAME), std::string(JWT_USER_KEY), m_currentUrl);
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
		ofs << Utility::prettyJson(config.dump());
		ofs.close();
		// only owner to read and write for token file
		os::chmod(m_tokenFile, 600);
	}
	else
	{
		std::cerr << "Failed to write config file " << m_tokenFile << std::endl;
	}
}

std::string ArgumentParser::login(const std::string &user, const std::string &passwd, std::string targetHost)
{
	auto url = Utility::stdStringTrim(targetHost, '/');
	// header
	std::map<std::string, std::string> header;
	header.insert({HTTP_HEADER_JWT_Authorization, std::string(HTTP_HEADER_Auth_BasicSpace) + Utility::encode64(user + ":" + passwd)});
	header.insert({HTTP_HEADER_JWT_expire_seconds, std::to_string(m_tokenTimeoutSeconds)});

	auto response = RestClient::request(url, web::http::methods::POST, "/appmesh/login", nullptr, std::move(header), {});
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

			std::map<std::string, std::string> header;
			header.insert({HTTP_HEADER_JWT_username, Utility::encode64(user)});
			header.insert({HTTP_HEADER_JWT_totp, totp});
			header.insert({HTTP_HEADER_JWT_totp_challenge, Utility::encode64(totpChallenge)});
			header.insert({HTTP_HEADER_JWT_expire_seconds, std::to_string(m_tokenTimeoutSeconds)});
			response = RestClient::request(url, web::http::methods::POST, "/appmesh/totp/validate", nullptr, std::move(header), {});
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

void ArgumentParser::printApps(nlohmann::json json, bool reduce)
{
	constexpr size_t NAME_COL_WIDTH = 15;
	boost::io::ios_all_saver guard(std::cout);
	// Title:
	std::cout << std::left;
	std::cout
		<< std::setw(4) << Utility::strToupper("id")
		<< std::setw(NAME_COL_WIDTH) << Utility::strToupper(JSON_KEY_APP_name)
		<< std::setw(6) << Utility::strToupper(JSON_KEY_APP_owner)
		<< std::setw(9) << Utility::strToupper(JSON_KEY_APP_status)
		<< std::setw(7) << Utility::strToupper(JSON_KEY_APP_health)
		<< std::setw(8) << Utility::strToupper(JSON_KEY_APP_pid)
		<< std::setw(6) << Utility::strToupper("user")	// JSON_KEY_APP_pid_user
		<< std::setw(9) << Utility::strToupper(JSON_KEY_APP_memory)
		<< std::setw(5) << std::string("%").append(Utility::strToupper(JSON_KEY_APP_cpu))
		<< std::setw(7) << Utility::strToupper("return") // JSON_KEY_APP_return
		<< std::setw(7) << Utility::strToupper("age")
		<< std::setw(9) << Utility::strToupper("duration")
		<< std::setw(7) << Utility::strToupper(JSON_KEY_APP_starts)
		<< Utility::strToupper(JSON_KEY_APP_command)
		<< std::endl;

	int index = 1;
	auto reduceFunc = std::bind(&ArgumentParser::reduceStr, this, std::placeholders::_1, std::placeholders::_2);
	for (auto &entity : json.items())
	{
		auto jsonObj = entity.value();
		const char *slash = "-";
		auto name = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_name);
		if (reduce)
			name = reduceFunc(name, NAME_COL_WIDTH);
		else if (name.length() >= NAME_COL_WIDTH)
			name += " ";
		std::cout << std::setw(4) << std::to_string(index++) + ' ';
		std::cout << std::setw(NAME_COL_WIDTH) << name;
		std::cout << std::setw(6);
		{
			const auto owner = reduceFunc(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_owner), 6);
			std::cout << (owner.empty() ? slash : owner.c_str());
		}
		std::cout << std::setw(9) << GET_STATUS_STR(GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_status));
		std::cout << std::setw(7) << ((0 == GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_health)) ? "OK" : slash);
		std::cout << std::setw(8);
		{
			if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_pid))
				std::cout << GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_pid);
			else
				std::cout << slash;
		}
		std::cout << std::setw(6);
		{
			if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_pid_user))
				std::cout << GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_pid_user);
			else
				std::cout << slash;
		}
		std::cout << std::setw(9);
		{
			if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_memory))
				std::cout << Utility::humanReadableSize(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_APP_memory));
			else
				std::cout << slash;
		}
		std::cout << std::setw(5);
		{
			if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_cpu))
			{
				std::stringstream ss;
				ss << (int)GET_JSON_DOUBLE_VALUE(jsonObj, JSON_KEY_APP_cpu);
				std::cout << ss.str();
			}
			else
				std::cout << slash;
		}
		std::cout << std::setw(7);
		{
			if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_return))
				std::cout << GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_return);
			else
				std::cout << slash;
		}
		std::cout << std::setw(7);
		{
			if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_REG_TIME))
				std::cout << Utility::humanReadableDuration(std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_APP_REG_TIME)));
			else
				std::cout << slash;
		}
		std::cout << std::setw(9);
		{
			if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_last_start) && HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_pid))
			{
				auto startTime = std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_APP_last_start));
				auto endTime = HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_last_exit) ? std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_APP_last_exit)) : std::chrono::system_clock::now();
				std::cout << Utility::humanReadableDuration(startTime, endTime);
			}
			else
				std::cout << slash;
		}
		std::cout << std::setw(7);
		{
			if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_starts))
				std::cout << GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_starts);
			else
				std::cout << slash;
		}
		if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_command))
		{
			if (reduce)
			{
				const int commandColMaxLength = 40;
				auto command = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_command);
				jsonObj[JSON_KEY_APP_command] = std::string(reduceFunc(command, commandColMaxLength));
			}
			std::cout << jsonObj.at(JSON_KEY_APP_command);
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
		return source.substr(0, limit - 2).append("*");
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

#pragma once

#include <string>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <vector>
#include <chrono>
#include <log4cpp/Category.hh>
#include <log4cpp/Priority.hh>

#define ARRAY_LEN(T) (sizeof(T) / sizeof(T[0]))

#define LOG_DBG log4cpp::Category::getRoot() << log4cpp::Priority::DEBUG
#define LOG_INF log4cpp::Category::getRoot() << log4cpp::Priority::INFO
#define LOG_WAR log4cpp::Category::getRoot() << log4cpp::Priority::WARN
#define LOG_ERR log4cpp::Category::getRoot() << log4cpp::Priority::ERROR

// Expand micro variable (microkey=microvalue)
#define __MICRO_KEY__(str) #str				  // No expand micro
#define __MICRO_VAR__(str) __MICRO_KEY__(str) // Expand micro

#define PRINT_VERSION()                                                                                                   \
	if (argc >= 2 && (std::string("version") == argv[1] || std::string("-v") == argv[1] || std::string("-V") == argv[1])) \
	{                                                                                                                     \
		std::cout << "Build: " << __MICRO_VAR__(BUILD_TAG) << std::endl;                                                  \
		return 0;                                                                                                         \
	}

#define GET_STRING_T(sstr) utility::conversions::to_string_t(std::string(sstr))
#define GET_STD_STRING(sstr) utility::conversions::to_utf8string(sstr)

#define SET_COMPARE(x, y)                                           \
	if ((x) != (y))                                                 \
	{                                                               \
		(x) = (y);                                                  \
		LOG_INF << fname << "Configuration value updated : " << #x; \
	}

#define REST_HEADER_PRINT                                                          \
	for (auto it = message.headers().begin(); it != message.headers().end(); it++) \
		LOG_DBG << "Header: " << it->first << " = " << it->second;
#define REST_INFO_PRINT                                                    \
	LOG_DBG                                                                \
		<< " fname: " << __FUNCTION__                                      \
		<< " Method: " << message.method()                                 \
		<< " URI: " << http::uri::decode(message.relative_uri().path())    \
		<< " Query: " << http::uri::decode(message.relative_uri().query()) \
		<< " Remote: " << message.remote_address();

// make_unique implementation for C++11, C++14 already support
#if (__cplusplus <= 201103L)
namespace std
{
	template <typename T, typename... Args>
	std::unique_ptr<T> make_unique(Args &&... args)
	{
		return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
	}
} // namespace std
#endif

#define MY_HOST_NAME ResourceCollection::instance()->getHostName()

// Get attribute from json Object
#define GET_JSON_STR_VALUE(jsonObj, key) Utility::stdStringTrim(GET_STD_STRING(GET_JSON_STR_T_VALUE(jsonObj, key)))
#define GET_JSON_STR_T_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(GET_STRING_T(key)).as_string() : GET_STRING_T(""))
#define GET_JSON_INT_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(GET_STRING_T(key)).as_integer() : 0)
#define GET_JSON_NUMBER_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(GET_STRING_T(key)).as_number().to_int64() : 0L)
#define SET_JSON_INT_VALUE(jsonObj, key, value) \
	if (HAS_JSON_FIELD(jsonObj, key))           \
		value = GET_JSON_INT_VALUE(jsonObj, key);
#define GET_JSON_BOOL_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(GET_STRING_T(key)).as_bool() : false)
#define SET_JSON_BOOL_VALUE(jsonObj, key, value) \
	if (HAS_JSON_FIELD(jsonObj, key))            \
		value = GET_JSON_BOOL_VALUE(jsonObj, key);
#define HAS_JSON_FIELD(jsonObj, key) (jsonObj.has_field(GET_STRING_T(key)) && !jsonObj.at(GET_STRING_T(key)).is_null())
#define ERASE_JSON_FIELD(jsonObj, key)    \
	if (HAS_JSON_FIELD(jsonObj, key))     \
	{                                     \
		jsonObj.erase(GET_STRING_T(key)); \
	}

#define DEFAULT_PROM_LISTEN_PORT 0
#define DEFAULT_REST_LISTEN_PORT 6060
#define DEFAULT_SCHEDULE_INTERVAL 2
#define DEFAULT_HTTP_THREAD_POOL_SIZE 6

#define JWT_USER_KEY "User123"
#define JWT_USER_NAME "user"
#define JWT_ADMIN_NAME "admin"
#define APPMESH_PASSWD_MIN_LENGTH 3
#define DEFAULT_RUN_APP_RETENTION_DURATION 10
#define DEFAULT_HEALTH_CHECK_INTERVAL 10
#define MAX_COMMAND_LINE_LENGTH 2048

#define DEFAULT_LABEL_HOST_NAME "HOST_NAME"
#define SNAPSHOT_FILE_NAME ".snapshot"
#define DEFAULT_WORKING_DIR "/opt/appmesh/work"

const char *GET_STATUS_STR(unsigned int status);

//////////////////////////////////////////////////////////////////////////
/// All common functions
//////////////////////////////////////////////////////////////////////////
class Utility
{
public:
	Utility();
	virtual ~Utility();

	// OS related
	static std::string getSelfFullPath();
	static std::string getSelfDir();
	static bool isDirExist(std::string path);
	static bool isFileExist(std::string path);
	static bool createDirectory(const std::string &path, mode_t mode = 0775);
	static bool createRecursiveDirectory(const std::string &path, mode_t mode = 0775);
	static bool removeDir(const std::string &path);
	static void removeFile(const std::string &path);

	// String functions
	static bool isNumber(const std::string &str);
	static std::string stdStringTrim(const std::string &str);
	static std::string stdStringTrim(const std::string &str, char trimChar, bool trimStart = true, bool trimEnd = true);
	static std::vector<std::string> splitString(const std::string &s, const std::string &c);
	static bool startWith(const std::string &str, const std::string &head);
	static bool endWith(const std::string &str, const std::string &end);
	static std::string stringReplace(const std::string &strBase, const std::string &strSrc, const std::string &strDst, int startPos = 0);
	static std::string humanReadableSize(long double bytesSize);
	static std::string prettyJson(const std::string &jsonStr);
	static std::string hash(const std::string &str);
	static std::string stringFormat(const std::string fmt_str, ...);

	static void initLogging();
	static bool setLogLevel(const std::string &level);

	// OS related
	static unsigned long long getThreadId();
	static bool getUid(std::string userName, unsigned int &uid, unsigned int &groupid);
	static void getEnvironmentSize(const std::map<std::string, std::string> &envMap, int &totalEnvSize, int &totalEnvArgs);

	// Base64
	static std::string encode64(const std::string &val);
	static std::string decode64(const std::string &val);

	// Read file to string
	static std::string readFile(const std::string &path);
	static std::string readFileCpp(const std::string &path);

	static std::string createUUID();
	static std::string runShellCommand(std::string cmd);
};

#define ENV_APP_MANAGER_LISTEN_PORT "APPMESH_OVERRIDE_LISTEN_PORT"
#define ENV_APP_MANAGER_LAUNCH_TIME "APP_MANAGER_LAUNCH_TIME"
#define ENV_APP_MANAGER_DOCKER_PARAMS "APP_DOCKER_OPTS"						  // used to pass docker extra parameters to docker startup cmd
#define ENV_APP_MANAGER_DOCKER_IMG_PULL_TIMEOUT "APP_DOCKER_IMG_PULL_TIMEOUT" // app manager pull docker image timeout seconds
#define DATE_TIME_FORMAT "%Y-%m-%dT%H:%M:%S"
#define DEFAULT_TOKEN_EXPIRE_SECONDS 7 * (60 * 60 * 24) // default 7 days
#define MAX_TOKEN_EXPIRE_SECONDS 30 * (60 * 60 * 24)	// max 30 days
#define DEFAULT_RUN_APP_TIMEOUT_SECONDS 10				// run app default timeout
#define MAX_RUN_APP_TIMEOUT_SECONDS 3 * (60 * 60 * 24)	// run app max timeout 3 days
#define MAX_APP_CACHED_LINES 1024
#define SECURIRE_USER_KEY "******"
#define CONSUL_SESSION_DEFAULT_TTL 30
#define DEFAULT_EXEC_USER "appmesh"

#define JSON_KEY_Description "Description"
#define JSON_KEY_DefaultExecUser "DefaultExecUser"
#define JSON_KEY_WorkingDirectory "WorkingDirectory"

#define JSON_KEY_REST "REST"
#define JSON_KEY_RestEnabled "RestEnabled"
#define JSON_KEY_RestListenPort "RestListenPort"
#define JSON_KEY_RestListenAddress "RestListenAddress"
#define JSON_KEY_PrometheusExporterListenPort "PrometheusExporterListenPort"

#define JSON_KEY_ScheduleIntervalSeconds "ScheduleIntervalSeconds"
#define JSON_KEY_LogLevel "LogLevel"
#define JSON_KEY_TimeFormatPosixZone "TimeFormatPosixZone"

#define JSON_KEY_SSL "SSL"
#define JSON_KEY_SSLEnabled "SSLEnabled"
#define JSON_KEY_SSLCertificateFile "SSLCertificateFile"
#define JSON_KEY_SSLCertificateKeyFile "SSLCertificateKeyFile"

#define JSON_KEY_Security "Security"

#define JSON_KEY_JWTEnabled "JWTEnabled"
#define JSON_KEY_HttpThreadPoolSize "HttpThreadPoolSize"
#define JSON_KEY_Roles "Roles"
#define JSON_KEY_Applications "Applications"
#define JSON_KEY_Labels "Labels"
#define JSON_KEY_JWTRedirectUrl "JWTRedirectUrl"
#define JSON_KEY_SECURITY_EncryptKey "EncryptKey"
#define JSON_KEY_CONSUL "Consul"
#define JSON_KEY_VERSION "Version"
#define JSON_KEY_CONSUL_URL "url"
#define JSON_KEY_CONSUL_IS_MAIN "is_main"
#define JSON_KEY_CONSUL_IS_NODE "is_node"
#define JSON_KEY_CONSUL_SESSION_NODE "session_node"
#define JSON_KEY_CONSUL_DATACENTER "datacenter"
#define JSON_KEY_CONSUL_SESSION_TTL "session_TTL"
#define JSON_KEY_CONSUL_SECURITY "enable_consul_security"
#define JSON_KEY_CONSUL_APPMESH_PROXY_URL "appmesh_proxy_url"
#define JSON_KEY_JWT_Users "Users"
#define JSON_KEY_APP_name "name"
#define JSON_KEY_APP_owner "owner"
#define JSON_KEY_APP_owner_permission "permission"
#define JSON_KEY_APP_metadata "metadata"
#define JSON_KEY_APP_shell_mode "shell_mode"
#define JSON_KEY_APP_command "command"
#define JSON_KEY_APP_init_command "init_command"
#define JSON_KEY_APP_fini_command "fini_command"
#define JSON_KEY_APP_stdout_cache_size "stdout_cache_size"
#define JSON_KEY_APP_stdout_cache_num "stdout_cache_num"
#define JSON_KEY_APP_initial_application_only "initial_application_only"
#define JSON_KEY_APP_onetime_application_only "onetime_application_only"
#define JSON_KEY_APP_health_check_cmd "health_check_cmd"
#define JSON_KEY_APP_working_dir "working_dir"
#define JSON_KEY_APP_REG_TIME "register_time"
#define JSON_KEY_APP_status "status"
#define JSON_KEY_APP_daily_limitation "daily_limitation"
#define JSON_KEY_APP_resource_limit "resource_limit"
#define JSON_KEY_APP_env "env"
#define JSON_KEY_APP_posix_timezone "posix_timezone"
#define JSON_KEY_APP_docker_image "docker_image"
// runtime attr
#define JSON_KEY_APP_pid "pid"
#define JSON_KEY_APP_return "return"
#define JSON_KEY_APP_id "id"
#define JSON_KEY_APP_memory "memory"
#define JSON_KEY_APP_last_start "last_start_time"
#define JSON_KEY_APP_container_id "container_id"
#define JSON_KEY_APP_health "health"
#define JSON_KEY_APP_version "version"
#define JSON_KEY_APP_SYSTEM_INTERNAL "system-internal"
#define JSON_KEY_APP_CLOUD_APP "cloud-app"

#define JSON_KEY_PERIOD_APP_keep_running "keep_running"

#define JSON_KEY_SHORT_APP_start_interval_seconds "start_interval_seconds"
#define JSON_KEY_SHORT_APP_start_time "start_time"
#define JSON_KEY_SHORT_APP_end_time "end_time"
#define JSON_KEY_SHORT_APP_start_interval_timeout "start_interval_timeout"
#define JSON_KEY_SHORT_APP_next_start_time "next_start_time"

#define JSON_KEY_DAILY_LIMITATION_daily_start "daily_start"
#define JSON_KEY_DAILY_LIMITATION_daily_end "daily_end"

#define JSON_KEY_RESOURCE_LIMITATION_memory_mb "memory_mb"
#define JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb "memory_virt_mb"
#define JSON_KEY_RESOURCE_LIMITATION_cpu_shares "cpu_shares"

#define JSON_KEY_USER_key "key"
#define JSON_KEY_USER_group "group"
#define JSON_KEY_USER_roles "roles"
#define JSON_KEY_USER_locked "locked"
#define JSON_KEY_USER_metadata "metadata"
#define JSON_KEY_USER_exec_user "exec_user"

#define HTTP_HEADER_JWT "JWT"
#define HTTP_HEADER_JWT_ISSUER "appmesh-auth0"
#define HTTP_HEADER_JWT_name "name"
#define HTTP_HEADER_JWT_Authorization "Authorization"
#define HTTP_HEADER_JWT_Bearer "Bearer"
#define HTTP_HEADER_JWT_BearerSpace "Bearer "
#define HTTP_HEADER_JWT_access_token "AccessToken"
#define HTTP_HEADER_JWT_expire_seconds "ExpireSeconds"
#define HTTP_HEADER_JWT_username "UserName"
#define HTTP_HEADER_JWT_password "Password"
#define HTTP_HEADER_JWT_new_password "NewPassword"
#define HTTP_HEADER_JWT_auth_permission "AuthPermission"
#define HTTP_HEADER_KEY_exit_code "ExitCode"
#define HTTP_HEADER_KEY_file_path "FilePath"
#define HTTP_HEADER_KEY_file_mode "FileMode"
#define HTTP_HEADER_KEY_file_user "FileUser"

#define HTTP_QUERY_KEY_keep_history "keep_history"
#define HTTP_QUERY_KEY_stdout_index "stdout_index"
#define HTTP_QUERY_KEY_process_uuid "process_uuid"
#define HTTP_QUERY_KEY_timeout "timeout"
#define HTTP_QUERY_KEY_action_start "enable"
#define HTTP_QUERY_KEY_action_stop "disable"
#define HTTP_QUERY_KEY_loglevel "level"
#define HTTP_QUERY_KEY_label_value "value"
#define HTTP_QUERY_KEY_retention "retention" // for async run, the output hold timeout in sever side

#define PERMISSION_KEY_view_app "app-view"
#define PERMISSION_KEY_view_app_output "app-output-view"
#define PERMISSION_KEY_view_all_app "app-view-all"
#define PERMISSION_KEY_view_host_resource "host-resource-view"
#define PERMISSION_KEY_app_reg "app-reg"
#define PERMISSION_KEY_app_control "app-control"
#define PERMISSION_KEY_app_delete "app-delete"
#define PERMISSION_KEY_run_app_async "app-run-async"
#define PERMISSION_KEY_run_app_sync "app-run-sync"
#define PERMISSION_KEY_run_app_async_output "app-run-async-output"
#define PERMISSION_KEY_file_download "file-download"
#define PERMISSION_KEY_file_upload "file-upload"
#define PERMISSION_KEY_label_view "label-view"
#define PERMISSION_KEY_label_set "label-set"
#define PERMISSION_KEY_label_delete "label-delete"
#define PERMISSION_KEY_loglevel "log-level"
#define PERMISSION_KEY_config_view "config-view"
#define PERMISSION_KEY_config_set "config-set"
#define PERMISSION_KEY_change_passwd "passwd-change"
#define PERMISSION_KEY_lock_user "user-lock"
#define PERMISSION_KEY_unlock_user "user-unlock"
#define PERMISSION_KEY_add_user "user-add"
#define PERMISSION_KEY_delete_user "user-delete"
#define PERMISSION_KEY_get_users "user-list"
#define PERMISSION_KEY_role_update "role-set"
#define PERMISSION_KEY_role_delete "role-delete"
#define PERMISSION_KEY_role_view "role-view"
#define PERMISSION_KEY_permission_list "permission-list"

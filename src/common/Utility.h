#pragma once

#include <chrono>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <log4cpp/Category.hh>
#include <log4cpp/Priority.hh>
#include <nlohmann/json.hpp>

#if __cplusplus >= 201703L
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
#endif

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

#define SET_COMPARE(x, y)                                           \
	if ((x) != (y))                                                 \
	{                                                               \
		(x) = (y);                                                  \
		LOG_INF << fname << "Configuration value updated : " << #x; \
	}

// make_unique implementation for C++11, C++14 already support
#if (__cplusplus <= 201103L)
namespace std
{
	template <typename T, typename... Args>
	std::unique_ptr<T> make_unique(Args &&...args)
	{
		return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
	}
} // namespace std
#endif

template <typename T>
std::shared_ptr<T> make_shared_array(size_t size)
{
	return std::shared_ptr<T>(new T[size], std::default_delete<T[]>());
}

#define MY_HOST_NAME ResourceCollection::instance()->getHostName()

// Get attribute from json Object
#define GET_JSON_STR_VALUE(jsonObj, key) Utility::stdStringTrim(HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).get<std::string>() : std::string(""))
#define GET_JSON_INT_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).get<int>() : 0)
#define GET_JSON_INT64_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).get<int64_t>() : 0L)
#define GET_JSON_DOUBLE_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).get<double>() : 0.0L)
#define SET_JSON_INT_VALUE(jsonObj, key, value) \
	if (HAS_JSON_FIELD(jsonObj, key))           \
		value = GET_JSON_INT_VALUE(jsonObj, key);
#define GET_JSON_BOOL_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).get<bool>() : false)
#define SET_JSON_BOOL_VALUE(jsonObj, key, value) \
	if (HAS_JSON_FIELD(jsonObj, key))            \
		value = GET_JSON_BOOL_VALUE(jsonObj, key);
#define HAS_JSON_FIELD(jsonObj, key) (jsonObj.contains(key) && !jsonObj.at(key).is_null())

#define CLOSE_ACE_HANDLER(handler)         \
	do                                     \
	{                                      \
		if (handler != ACE_INVALID_HANDLE) \
		{                                  \
			ACE_OS::close(handler);        \
			handler = ACE_INVALID_HANDLE;  \
		}                                  \
	} while (false)

#define CLOSE_STREAM(streamPtr)                           \
	do                                                    \
	{                                                     \
		if (streamPtr != nullptr && streamPtr->is_open()) \
		{                                                 \
			streamPtr->close();                           \
			streamPtr = nullptr;                          \
		}                                                 \
	} while (false)

#define GET_HTTP_HEADER(message, headerName) \
	message.m_headers.count(headerName) > 0 ? message.m_headers.find(headerName)->second : std::string()
#define APPMESH_CONFIG_JSON_FILE "config.json"
#define APPMESH_SECURITY_JSON_FILE "security.json"
#define APPMESH_SECURITY_LDAP_JSON_FILE "ldap.json"
#define DEFAULT_PROM_LISTEN_PORT 0
#define DEFAULT_REST_LISTEN_PORT 6060
#define DEFAULT_TCP_REST_LISTEN_PORT 6059
#define DEFAULT_SCHEDULE_INTERVAL 2
#define DEFAULT_HTTP_THREAD_POOL_SIZE 6
#define REST_REQUEST_TIMEOUT_SECONDS 60

#define JWT_USER_KEY "mesh123"
#define JWT_USER_NAME "mesh"
#define JWT_ADMIN_NAME "admin"
#define APPMESH_PASSWD_MIN_LENGTH 3
#define DEFAULT_HEALTH_CHECK_INTERVAL 10
#define MAX_COMMAND_LINE_LENGTH 2048
// The first 4 bytes of the protocol buffer data contains the size of the following body data.
constexpr size_t PROTOBUF_HEADER_LENGTH = 4;
constexpr size_t BLOCK_CHUNK_SIZE = 1024 * 4;
constexpr size_t MAX_TCP_BLOCK_SIZE = 10 * 1024 * 1024 * 8;

#define DEFAULT_LABEL_HOST_NAME "HOST_NAME"
#define SNAPSHOT_FILE_NAME ".snapshot"
#define APPMESH_LOCAL_HOST_URL "https://localhost:6060"
#define HTTP_USER_AGENT "appmeshsdk"
#define TCP_JSON_MSG_FILE "file"

const char *GET_STATUS_STR(unsigned int status);
const nlohmann::json EMPTY_STR_JSON(nullptr);
const nlohmann::json CLOUD_STR_JSON("APPMESH-CLOUD-APP-FLAG");

/// <summary>
/// All common functions
/// </summary>
class Utility
{
public:
	Utility();
	virtual ~Utility();

	// OS related
	static const std::string getSelfFullPath();
	static const std::string &getSelfDir();
	static const std::string &getParentDir();
	static const std::string getBinaryName();
	static bool isDirExist(const std::string &path);
	static bool isFileExist(const std::string &path);
	static bool createDirectory(const std::string &path, fs::perms perms = fs::perms::owner_all | fs::perms::group_all | fs::perms::others_read | fs::perms::others_exe);
	static bool createRecursiveDirectory(const std::string &path, fs::perms perms = fs::perms::owner_all | fs::perms::group_all | fs::perms::others_read | fs::perms::others_exe);
	static bool removeDir(const std::string &path);
	static void removeFile(const std::string &path);

	// String functions
	static bool isNumber(const std::string &str);
	static std::string stdStringTrim(const std::string &str);
	static std::string stdStringTrim(const std::string &str, char trimChar, bool trimStart = true, bool trimEnd = true);
	static std::string stdStringTrim(const std::string &str, const std::string &trimChars, bool trimStart = true, bool trimEnd = true);
	static std::vector<std::string> splitString(const std::string &s, const std::string &c);
	static bool startWith(const std::string &str, const std::string &head);
	static bool endWith(const std::string &str, const std::string &end);
	static size_t charCount(const std::string &str, const char &c);
	static std::string stringReplace(const std::string &strBase, const std::string &strSrc, const std::string &strDst, int startPos = 0);
	static std::string humanReadableSize(long double bytesSize);
	static std::string humanReadableDuration(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime = std::chrono::system_clock::now());
	static std::string prettyJson(const std::string &jsonStr);
	static std::string hash(const std::string &str);
	static std::string stringFormat(const std::string fmt_str, ...);
	static std::string strToupper(std::string s);
	static std::string strTolower(std::string s);
	static std::string unEscape(const std::string &str);
	static std::vector<std::string> str2argv(const std::string &commandLine);

	static void initLogging(const std::string &name);
	static bool setLogLevel(const std::string &level);

	// OS related
	static unsigned long long getThreadId();
	static bool getUid(std::string userName, unsigned int &uid, unsigned int &groupid);
	static std::string getOsUserName();
	static void getEnvironmentSize(const std::map<std::string, std::string> &envMap, int &totalEnvSize, int &totalEnvArgs);

	// Base64
	static std::string encode64(const std::string &val);
	static std::string decode64(const std::string &val);

	// Read file to string
	static std::string readFile(const std::string &path);
	static std::string readFileCpp(const std::string &path);
	static std::string readFileCpp(const std::string &path, long *position, long maxSize, bool readLine = false);

	static std::string createUUID();
	static bool createPidFile();
	static void appendStrTimeAttr(nlohmann::json &jsonObj, const std::string &key);
	static void appendStrDayTimeAttr(nlohmann::json &jsonObj, const std::string &key);
	static void addExtraAppTimeReferStr(nlohmann::json &jsonObj);
	static void initDateTimeZone(bool writeLog = false);

	static const std::string readStdin2End();
};

#define PID_FILE_PATH "/var/run/appmesh.pid"
#define ENV_LD_LIBRARY_PATH "LD_LIBRARY_PATH"
#define ENV_APPMESH_LAUNCH_TIME "APP_MANAGER_LAUNCH_TIME"
#define ENV_APPMESH_DOCKER_PARAMS "APP_DOCKER_OPTS"						  // used to pass docker extra parameters to docker startup cmd
#define ENV_APPMESH_DOCKER_IMG_PULL_TIMEOUT "APP_DOCKER_IMG_PULL_TIMEOUT" // app manager pull docker image timeout seconds
#define ENV_APPMESH_PREFIX "APPMESH_"
#define ENV_APPMESH_POSIX_TIMEZONE "APPMESH_POSIX_TIMEZONE"
#define DEFAULT_TOKEN_EXPIRE_SECONDS 7 * (60 * 60 * 24) // default 7 days
#define DEFAULT_RUN_APP_TIMEOUT_SECONDS 60				// run app default timeout
#define MAX_RUN_APP_TIMEOUT_SECONDS 1 * (60 * 60 * 24)	// run app max timeout 1 day
#define SECURIRE_USER_KEY "******"
#define CONSUL_SESSION_DEFAULT_TTL 30
#define APP_STD_OUT_MAX_FILE_SIZE 1024 * 1024 * 100	  // 100M
#define APP_STD_OUT_VIEW_DEFAULT_SIZE 1024 * 1024 * 3 // 3M
#define SEPARATE_REST_APP_NAME "apprest"
#define SEPARATE_AGENT_APP_NAME "agent"
#define SEPARATE_PYTHON_EXEC_APP_NAME "pyrun"
#define REST_ROOT_TEXT_MESSAGE "App Mesh"
#define REST_TEXT_MESSAGE_JSON_KEY "message"

#define JSON_KEY_Description "Description"
#define JSON_KEY_DefaultExecUser "DefaultExecUser"
#define JSON_KEY_DisableExecUser "DisableExecUser"
#define JSON_KEY_WorkingDirectory "WorkingDirectory"

#define JSON_KEY_REST "REST"
#define JSON_KEY_RestEnabled "RestEnabled"
#define JSON_KEY_RestListenPort "RestListenPort"
#define JSON_KEY_RestListenAddress "RestListenAddress"
#define JSON_KEY_RestTcpPort "RestTcpPort"
#define JSON_KEY_DockerProxyListenAddr "DockerProxyListenAddr"
#define JSON_KEY_PrometheusExporterListenPort "PrometheusExporterListenPort"

#define JSON_KEY_ScheduleIntervalSeconds "ScheduleIntervalSeconds"
#define JSON_KEY_LogLevel "LogLevel"

#define JSON_KEY_SSL "SSL"
#define JSON_KEY_VerifyPeer "VerifyPeer"
#define JSON_KEY_SSLCertificateFile "SSLCertificateFile"
#define JSON_KEY_SSLCertificateKeyFile "SSLCertificateKeyFile"

#define JSON_KEY_JWT "JWT"
#define JSON_KEY_JWTEnabled "JWTEnabled"
#define JSON_KEY_JWTSalt "JWTSalt"
#define JSON_KEY_SECURITY_Interface "SecurityInterface"

#define JSON_KEY_HttpThreadPoolSize "HttpThreadPoolSize"
#define JSON_KEY_Roles "Roles"
#define JSON_KEY_Groups "Groups"
#define JSON_KEY_Applications "Applications"
#define JSON_KEY_Labels "Labels"
#define JSON_KEY_JWTRedirectUrl "JWTRedirectUrl"
#define JSON_KEY_SECURITY_EncryptKey "EncryptKey"
#define JSON_KEY_CONSUL "Consul"
#define JSON_KEY_VERSION "Version"
#define JSON_KEY_CONSUL_URL "Url"
#define JSON_KEY_CONSUL_IS_MAIN "IsMainNode"
#define JSON_KEY_CONSUL_IS_WORKER "IsWorkerNode"
#define JSON_KEY_CONSUL_SESSION_TTL "SessionTTL"
#define JSON_KEY_CONSUL_AUTH_USER "User"
#define JSON_KEY_CONSUL_AUTH_PASS "Pass"
#define JSON_KEY_CONSUL_SECURITY "EnableConsulSecurity"
#define JSON_KEY_CONSUL_APPMESH_PROXY_URL "AppmeshProxyUrl"
#define JSON_KEY_JWT_Users "Users"
#define JSON_KEY_APP_name "name"
#define JSON_KEY_APP_owner "owner"
#define JSON_KEY_APP_owner_permission "permission"
#define JSON_KEY_APP_metadata "metadata"
#define JSON_KEY_APP_shell_mode "shell"
#define JSON_KEY_APP_command "command"
#define JSON_KEY_APP_description "description"
#define JSON_KEY_APP_stdout_cache_size "stdout_cache_size"
#define JSON_KEY_APP_stdout_cache_num "stdout_cache_num"
#define JSON_KEY_APP_health_check_cmd "health_check_cmd"
#define JSON_KEY_APP_working_dir "working_dir"
#define JSON_KEY_APP_REG_TIME "register_time"
#define JSON_KEY_APP_status "status"
#define JSON_KEY_APP_daily_limitation "daily_limitation"
#define JSON_KEY_APP_resource_limit "resource_limit"
#define JSON_KEY_APP_env "env"
#define JSON_KEY_APP_sec_env "sec_env"
#define JSON_KEY_APP_open_fd "fd" // open_file_descriptors
#define JSON_KEY_APP_pstree "pstree"
#define JSON_KEY_APP_docker_image "docker_image"
#define JSON_KEY_APP_last_error "last_error"
#define JSON_KEY_APP_from_recover "from_recover"
#define JSON_KEY_APP_starts "starts"

#define JSON_KEY_APP_behavior "behavior"
#define JSON_KEY_APP_behavior_exit "exit"
#define JSON_KEY_APP_behavior_control "control"
#define JSON_KEY_APP_behavior_restart "restart"
#define JSON_KEY_APP_behavior_keepalive "keepalive"
#define JSON_KEY_APP_behavior_standby "standby"
#define JSON_KEY_APP_behavior_remove "remove"

// runtime attr
#define JSON_KEY_APP_pid "pid"
#define JSON_KEY_APP_return "return"
#define JSON_KEY_APP_id "id"
#define JSON_KEY_APP_memory "memory"
#define JSON_KEY_APP_cpu "cpu"
#define JSON_KEY_APP_last_start "last_start_time"
#define JSON_KEY_APP_last_exit "last_exit_time"
#define JSON_KEY_APP_container_id "container_id"
#define JSON_KEY_APP_health "health"
#define JSON_KEY_APP_version "version"

#define JSON_KEY_APP_retention "retention" // extra timeout seconds for stopping current process
#define JSON_KEY_SHORT_APP_start_interval_seconds "start_interval_seconds"
#define JSON_KEY_SHORT_APP_start_time "start_time"
#define JSON_KEY_SHORT_APP_end_time "end_time"
#define JSON_KEY_SHORT_APP_cron_interval "cron" // start_interval_seconds will use cron format

#define JSON_KEY_SHORT_APP_next_start_time "next_start_time"

#define JSON_KEY_DAILY_LIMITATION_daily_start "daily_start"
#define JSON_KEY_DAILY_LIMITATION_daily_end "daily_end"

#define JSON_KEY_RESOURCE_LIMITATION_memory_mb "memory_mb"
#define JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb "memory_virt_mb"
#define JSON_KEY_RESOURCE_LIMITATION_cpu_shares "cpu_shares"

#define JSON_KEY_TIME_POSTTIX_STR "_ref_str"

#define JSON_KEY_USER_key "key"
#define JSON_KEY_USER_email "email"
#define JSON_KEY_USER_group "group"
#define JSON_KEY_USER_roles "roles"
#define JSON_KEY_USER_locked "locked"
#define JSON_KEY_USER_metadata "metadata"
#define JSON_KEY_USER_exec_user "exec_user"
#define JSON_KEY_USER_mfa_key "mfa_key"
#define JSON_KEY_USER_mfa_enabled "mfa_enabled"

#define JSON_KEY_USER_key_method_local "json"
#define JSON_KEY_USER_key_method_ldap "ldap"
#define JSON_KEY_USER_LDAP_ldap_uri "Uri"
#define JSON_KEY_USER_LDAP_ldap_LoginDN "LoginDN"
#define JSON_KEY_USER_LDAP_ldap_LoginPWD "LoginPWD"
#define JSON_KEY_USER_LDAP_ldap_SyncPeriodSeconds "SyncPeriodSeconds"
#define JSON_KEY_USER_LDAP_bind_dn "BindDN"
#define JSON_KEY_USER_LDAP_USER_REPLACE_HOLDER "{USER}"

#define HTTP_HEADER_JWT "JWT"
#define HTTP_HEADER_JWT_ISSUER "appmesh-auth0"
#define HTTP_HEADER_JWT_name "name"
#define HTTP_HEADER_JWT_user_group "group"
#define HTTP_HEADER_JWT_Authorization web::http::header_names::authorization
#define HTTP_HEADER_JWT_Bearer "Bearer"
#define HTTP_HEADER_JWT_BearerSpace "Bearer "
#define HTTP_HEADER_JWT_access_token "Access-Token"
#define HTTP_HEADER_JWT_expire_seconds "Expire-Seconds"
#define HTTP_HEADER_JWT_username "Username"
#define HTTP_HEADER_JWT_password "Password"
#define HTTP_HEADER_JWT_totp "Totp"
#define HTTP_HEADER_JWT_new_password "New-Password"
#define HTTP_HEADER_JWT_auth_permission "Auth-Permission"
#define HTTP_HEADER_KEY_exit_code "Exit-Code"
#define HTTP_HEADER_KEY_output_pos "Output-Position"
#define HTTP_HEADER_KEY_file_path "File-Path"
#define HTTP_HEADER_KEY_file_mode "File-Mode"
#define HTTP_HEADER_KEY_file_user "File-User"
#define HTTP_HEADER_KEY_file_group "File-Group"
#define HTTP_BODY_KEY_MFA_URI "Mfa-Uri"

#define HTTP_QUERY_KEY_stdout_position "stdout_position"
#define HTTP_QUERY_KEY_stdout_index "stdout_index"
#define HTTP_QUERY_KEY_stdout_maxsize "stdout_maxsize"
#define HTTP_QUERY_KEY_stdout_timeout "timeout"
#define HTTP_QUERY_KEY_process_uuid "process_uuid"
#define HTTP_QUERY_KEY_timeout "timeout"
#define HTTP_QUERY_KEY_action_start "enable"
#define HTTP_QUERY_KEY_action_stop "disable"
#define HTTP_QUERY_KEY_loglevel "level"
#define HTTP_QUERY_KEY_label_value "value"

#define PERMISSION_KEY_view_app "app-view"
#define PERMISSION_KEY_view_app_output "app-output-view"
#define PERMISSION_KEY_view_all_app "app-view-all"
#define PERMISSION_KEY_cloud_app_view "cloud-app-view"
#define PERMISSION_KEY_cloud_app_out_view "cloud-app-output-view"
#define PERMISSION_KEY_cloud_app_reg "cloud-app-reg"
#define PERMISSION_KEY_cloud_app_delete "cloud-app-delete"
#define PERMISSION_KEY_cloud_host_view "cloud-host-view"
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
#define PERMISSION_KEY_config_view "config-view"
#define PERMISSION_KEY_config_set "config-set"
#define PERMISSION_KEY_change_passwd "passwd-change"
#define PERMISSION_KEY_lock_user "user-lock"
#define PERMISSION_KEY_unlock_user "user-unlock"
#define PERMISSION_KEY_add_user "user-add"
#define PERMISSION_KEY_delete_user "user-delete"
#define PERMISSION_KEY_user_mfa_delete "user-mfa-delete"
#define PERMISSION_KEY_user_mfa_active "user-mfa-active"
#define PERMISSION_KEY_get_users "user-list"
#define PERMISSION_KEY_role_update "role-set"
#define PERMISSION_KEY_role_delete "role-delete"
#define PERMISSION_KEY_role_view "role-view"
#define PERMISSION_KEY_permission_list "permission-list"

namespace web
{
	namespace http
	{
		/// <summary>
		/// Predefined method strings for the standard HTTP methods mentioned in the
		/// HTTP 1.1 specification.
		/// </summary>
		typedef std::string method;

		/// <summary>
		/// Common HTTP methods.
		/// </summary>
		class methods
		{
		public:
#define _METHODS
#define DAT(a, b) const static method a;
#include "http_constants.dat"
#undef _METHODS
#undef DAT
		};

		typedef unsigned short status_code;

		/// <summary>
		/// Predefined values for all of the standard HTTP 1.1 response status codes.
		/// </summary>
		class status_codes
		{
		public:
#define _PHRASES
#define DAT(a, b, c) const static status_code a = b;
#include "http_constants.dat"
#undef _PHRASES
#undef DAT
		};

		/// <summary>
		/// Constants for the HTTP headers mentioned in RFC 2616.
		/// </summary>
		class header_names
		{
		public:
#define _HEADER_NAMES
#define DAT(a, b) const static std::string a;
#include "http_constants.dat"
#undef _HEADER_NAMES
#undef DAT
		};

		/// <summary>
		/// Constants for MIME types.
		/// </summary>
		class mime_types
		{
		public:
#define _MIME_TYPES
#define DAT(a, b) const static std::string a;
#include "http_constants.dat"
#undef _MIME_TYPES
#undef DAT
		};
	}
}

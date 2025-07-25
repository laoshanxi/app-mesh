#pragma once

#include <chrono>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <typeinfo>
#include <vector>

#include <ace/OS.h>
#include <boost/filesystem.hpp>
#include <log4cpp/Category.hh>
#include <log4cpp/Priority.hh>
#include <nlohmann/json.hpp>
#include <qrcodegen.hpp>
#include <yaml-cpp/yaml.h>
namespace fs = boost::filesystem;

#define ARRAY_LEN(T) (sizeof(T) / sizeof(T[0]))

template <typename TargetType, typename SourceType>
std::shared_ptr<TargetType> dynamic_pointer_cast_if(const std::shared_ptr<SourceType> &ptr)
{
	auto result = std::dynamic_pointer_cast<TargetType>(ptr);
	return result;
}

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
#if (__cplusplus <= 201103L) && !defined(WIN32)
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

#define PROCESS_MAP_TYPE ACE_Map_Manager<pid_t, AppProcess *, ACE_Recursive_Thread_Mutex>
#define APP_OUT_MULTI_MAP_TYPE ACE_Hash_Multi_Map_Manager<pid_t, std::shared_ptr<HttpRequestOutputView>, ACE_Hash<pid_t>, ACE_Equal_To<pid_t>, ACE_Recursive_Thread_Mutex>
#define MY_HOST_NAME ResourceCollection::instance()->getHostName()

// Get attribute from json Object
#define GET_JSON_STR_VALUE(jsonObj, key) Utility::stdStringTrim(HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).template get<std::string>() : std::string(""))
#define GET_JSON_INT_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).template get<int>() : 0)
#define GET_JSON_INT64_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).template get<int64_t>() : 0L)
#define GET_JSON_DOUBLE_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).template get<double>() : 0.0L)
#define SET_JSON_INT_VALUE(jsonObj, key, value) \
	if (HAS_JSON_FIELD(jsonObj, key))           \
		value = GET_JSON_INT_VALUE(jsonObj, key);
#define GET_JSON_BOOL_VALUE(jsonObj, key) (HAS_JSON_FIELD(jsonObj, key) ? jsonObj.at(key).template get<bool>() : false)
#define SET_JSON_BOOL_VALUE(jsonObj, key, value) \
	if (HAS_JSON_FIELD(jsonObj, key))            \
		value = GET_JSON_BOOL_VALUE(jsonObj, key);
#define HAS_JSON_FIELD(jsonObj, key) (jsonObj.contains(key) && !jsonObj.at(key).is_null())
#define GET_JSON_STR_INT_TEXT(jsonObj, key) Utility::stdStringTrim(HAS_JSON_FIELD(jsonObj, key) ? (jsonObj.at(key).is_string() ? jsonObj.at(key).template get<std::string>() : std::to_string(jsonObj.at(key).template get<int64_t>())) : std::string(""))

#define CLOSE_ACE_HANDLER(handler)                                \
	do                                                            \
	{                                                             \
		ACE_HANDLE target = handler.exchange(ACE_INVALID_HANDLE); \
		if (target != ACE_INVALID_HANDLE)                         \
		{                                                         \
			ACE_OS::close(target);                                \
		}                                                         \
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
#define APPMESH_CONFIG_YAML_FILE "config.yaml"
#define APPMESH_SECURITY_YAML_FILE "security.yaml"
#define APPMESH_SECURITY_LDAP_YAML_FILE "ldap.yaml"
#define APPMESH_CONSUL_API_CONFIG_FILE "consul.yaml"
#define APPMESH_OAUTH2_CONFIG_FILE "oauth2.yaml"
#define APPMESH_APPMG_INIT_FLAG_FILE ".appmginit"
#define APPMESH_APPLICATION_DIR "apps"
#define APPMESH_WORK_DIR "work"
#define APPMESH_WORK_TMP_DIR "tmp"
#define APPMESH_WORK_CONFIG_DIR "config"
#define APPMESH_JWT_RS256_PUBLIC_KEY_FILE "ssl/jwt-public.pem"
#define APPMESH_JWT_RS256_PRIVATE_KEY_FILE "ssl/jwt-private.pem"
#define APPMESH_JWT_ES256_PUBLIC_KEY_FILE "ssl/jwt-ec-public.pem"
#define APPMESH_JWT_ES256_PRIVATE_KEY_FILE "ssl/jwt-ec-private.pem"
#define APPMESH_JWT_ALGORITHM_RS256 "RS256"
#define APPMESH_JWT_ALGORITHM_HS256 "HS256"
#define APPMESH_JWT_ALGORITHM_ES256 "ES256"
#define DEFAULT_PROM_LISTEN_PORT 0
#define DEFAULT_REST_LISTEN_PORT 6060
#define DEFAULT_TCP_REST_LISTEN_PORT 6059
#define DEFAULT_SCHEDULE_INTERVAL 2
#define DEFAULT_HTTP_THREAD_POOL_SIZE 6
#define REST_REQUEST_TIMEOUT_SECONDS 60
#define STDOUT_FILE_SIZE_CHECK_INTERVAL 30

#define JWT_USER_KEY "mesh123"
#define JWT_USER_NAME "mesh"
#define JWT_ADMIN_NAME "admin"
#define APPMESH_PASSWD_MIN_LENGTH 6
#define DEFAULT_HEALTH_CHECK_INTERVAL 10
#define MAX_COMMAND_LINE_LENGTH 2048

constexpr size_t TCP_MESSAGE_HEADER_LENGTH = 8;			 // TCP header protocol: 4 bytes magic number + 4 bytes body length
constexpr uint32_t TCP_MESSAGE_MAGIC = 0x07C707F8;		 // Magic number for message validation (host byte order)
constexpr size_t TCP_CHUNK_BLOCK_SIZE = 16 * 1024 - 256; // Chunk block size 16KB (target with 256 bytes reserved for overhead)
constexpr size_t TCP_MAX_BLOCK_SIZE = 1024 * 1024 * 100; // Maximum allowed block size: 100 MB
constexpr auto TCP_SSL_VERSION_LIST = "tlsv1.2,tlsv1.3";

#define DEFAULT_LABEL_HOST_NAME "HOST_NAME"
#define SNAPSHOT_FILE_NAME ".snapshot"
#define APPMESH_LOCAL_HOST_URL "https://localhost:6060"

const char *GET_STATUS_STR(unsigned int status);
const nlohmann::json EMPTY_STR_JSON(nullptr);

/// <summary>
/// All common functions
/// </summary>
class Utility
{
public:
	Utility();
	virtual ~Utility();

	// OS related
	static const std::string getExecutablePath();
	static const std::string &getBinDir();
	static const std::string &getHomeDir();
	static const std::string getConfigFilePath(const std::string &configFile, bool write = false);
	static const std::string getBinaryName();
	static bool isDirExist(const std::string &path);
	static bool isFileExist(const std::string &path);
	static bool createDirectory(const std::string &path, fs::perms perms = fs::perms::owner_all | fs::perms::group_all | fs::perms::others_read | fs::perms::others_exe);
	static bool createRecursiveDirectory(const std::string &path, fs::perms perms = fs::perms::owner_all | fs::perms::group_all | fs::perms::others_read | fs::perms::others_exe);
	static bool removeDir(const std::string &path);
	static void removeFile(const std::string &path);
	static bool runningInContainer();

	// String functions
	static bool isNumber(const std::string &str);
	static bool isDouble(const std::string &str);
	static std::string stdStringTrim(const std::string &str);
	static std::string stdStringTrim(const std::string &str, char trimChar, bool leftTrim = true, bool rightTrim = true);
	static std::string stdStringTrim(const std::string &str, const std::string &trimChars, bool leftTrim = true, bool rightTrim = true);
	static std::vector<std::string> splitString(const std::string &s, const std::string &c);
	static bool startWith(const std::string &str, const std::string &head);
	static bool endWith(const std::string &str, const std::string &end);
	static size_t charCount(const std::string &str, const char &c);
	static std::string stringReplace(const std::string &strBase, const std::string &strSrc, const std::string &strDst, int startPos = 0);
	static std::string humanReadableSize(long double bytesSize);
	static std::string humanReadableDuration(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime = std::chrono::system_clock::now());
	static std::string prettyJson(const std::string &jsonStr);
	static std::string hash(const std::string &str);
	static std::string hashId();
	static std::string stringFormat(const std::string fmt_str, ...);
	static std::string strToupper(std::string s);
	static std::string strTolower(std::string s);
	static std::string htmlEntitiesDecode(const std::string &str);
	static std::vector<std::string> str2argv(const std::string &commandLine);
	static bool containsSpecialCharacters(const std::string &str);
	static std::string jsonToYaml(const nlohmann::json &j, std::shared_ptr<YAML::Emitter> out = nullptr);
	static nlohmann::json yamlToJson(const YAML::Node &node);
	static void printQRcode(const std::string &src);

	static void initLogging(const std::string &name);
	static bool setLogLevel(const std::string &level);

	// OS related
	static unsigned long long getThreadId();
	static bool getUid(const std::string &userName, unsigned int &uid, unsigned int &groupid);
	static std::string getUsernameByUid(uid_t uid = ACE_OS::getuid());
	static void getEnvironmentSize(const std::map<std::string, std::string> &envMap, int &totalEnvSize, int &totalEnvArgs);
	static void applyFilePermission(const std::string &file, const std::map<std::string, std::string> &headers);

	// Base64
	static std::string encode64(const std::string &val);
	static std::string decode64(const std::string &val);

	static std::string encodeURIComponent(const std::string &str);
	static std::string decodeURIComponent(const std::string &encoded);

	// Read file to string
	static std::string readFile(const std::string &path);
	static std::string readFileCpp(const std::string &path);
	static std::string readFileCpp(const std::string &path, long *position, long maxSize, bool readLine = false);

	static std::string createUUID();
	static bool createPidFile();
	static void appendStrTimeAttr(nlohmann::json &jsonObj, const std::string &key);
	static void appendStrDayTimeAttr(nlohmann::json &jsonObj, const std::string &key);
	static void addExtraAppTimeReferStr(nlohmann::json &jsonObj);
	static void initDateTimeZone(const std::string &posixTimezone, bool writeLog);

	static const std::string readStdin2End();
	static std::string escapeCommandLine(const std::string &input);
	static std::string maskSecret(const std::string &secret, size_t visibleChars = 2, const std::string &mask = "***");
};

#ifdef __linux__
#define ENV_LD_LIBRARY_PATH "LD_LIBRARY_PATH"
#elif defined(__APPLE__)
#define ENV_LD_LIBRARY_PATH "DYLD_LIBRARY_PATH"
#elif defined(_WIN32) || defined(_WIN64)
#define ENV_LD_LIBRARY_PATH "PATH"
#else
#define ENV_LD_LIBRARY_PATH "LD_LIBRARY_PATH" // Default to Linux style for other platforms
#endif
#define PID_FILE "appmesh.pid"
#define ENV_APPMESH_LAUNCH_TIME "APP_MANAGER_LAUNCH_TIME"
#define ENV_APPMESH_DOCKER_PARAMS "APP_DOCKER_OPTS"						  // used to pass docker extra parameters to docker startup cmd
#define ENV_APPMESH_DOCKER_IMG_PULL_TIMEOUT "APP_DOCKER_IMG_PULL_TIMEOUT" // app manager pull docker image timeout seconds
#define ENV_APPMESH_PREFIX "APPMESH_"
#define ENV_APPMESH_POSIX_TIMEZONE "APPMESH_POSIX_TIMEZONE"
#define DEFAULT_TOKEN_EXPIRE_SECONDS int(7 * (60 * 60 * 24))		// default 7 days // TODO: limit max token expire time
#define DEFAULT_RUN_APP_TIMEOUT_SECONDS int((60 * 60 * 24) * 2)		// run app default timeout 2 days
#define DEFAULT_RUN_APP_LIFECYCLE_SECONDS int((60 * 60 * 24) * 2.5) // run app max lifecycle 2.5 days
#define MAX_RUN_APP_TIMEOUT_SECONDS int((60 * 60 * 24) * 3)			// run app max timeout 3 days
#define SECURIRE_USER_KEY "******"
#define CONSUL_SESSION_DEFAULT_TTL 30
#define APP_STD_OUT_MAX_FILE_SIZE 1024 * 1024 * 100	  // 100M
#define APP_STD_OUT_VIEW_DEFAULT_SIZE 1024 * 1024 * 3 // 3M
#define SEPARATE_AGENT_APP_NAME "agent"
#define SEPARATE_PYTHON_EXEC_APP_NAME "pyrun"
#define REST_ROOT_TEXT_MESSAGE "<html>\n<head><title>App Mesh</title></head>\n<body>App Mesh</body>\n</html>\n"
#define REST_TEXT_MESSAGE_JSON_KEY "message"
#define REST_TEXT_TOTP_CHALLENGE_JSON_KEY "totp_challenge"
#define REST_TEXT_TOTP_CHALLENGE_EXPIRES_JSON_KEY "expires"

#define JSON_KEY_BaseConfig "BaseConfig"
#define JSON_KEY_Description "Description"
#define JSON_KEY_DefaultExecUser "DefaultExecUser"
#define JSON_KEY_DisableExecUser "DisableExecUser"
#define JSON_KEY_WorkingDirectory "WorkingDirectory"

#define JSON_KEY_REST "REST"
#define JSON_KEY_RestEnabled "RestEnabled"
#define JSON_KEY_RestListenPort "RestListenPort"
#define JSON_KEY_RestListenAddress "RestListenAddress"
#define JSON_KEY_RestTcpPort "RestTcpPort"
#define JSON_KEY_PrometheusExporterListenPort "PrometheusExporterListenPort"

#define JSON_KEY_ScheduleIntervalSeconds "ScheduleIntervalSeconds"
#define JSON_KEY_LogLevel "LogLevel"
#define JSON_KEY_PosixTimezone "PosixTimezone"

#define JSON_KEY_SSL "SSL"
#define JSON_KEY_SSLVerifyServer "VerifyServer"
#define JSON_KEY_SSLVerifyServerDelegate "VerifyServerDelegate"
#define JSON_KEY_SSLVerifyClient "VerifyClient"
#define JSON_KEY_SSLCertificateFile "SSLCertificateFile"
#define JSON_KEY_SSLCertificateKeyFile "SSLCertificateKeyFile"
#define JSON_KEY_SSLClientCertificateFile "SSLClientCertificateFile"
#define JSON_KEY_SSLClientCertificateKeyFile "SSLClientCertificateKeyFile"
#define JSON_KEY_SSLCaPath "SSLCaPath"

#define JSON_KEY_JWT "JWT"
#define JSON_KEY_JWTSalt "JWTSalt"
#define JSON_KEY_JWTAlgorithm "Algorithm"
#define JSON_KEY_JWTIssuer "Issuer"
#define JSON_KEY_JWTAudience "Audience"
#define JSON_KEY_SECURITY_Interface "SecurityInterface"
#define JSON_KEY_JWT_Keycloak "Keycloak"
#define JSON_KEY_JWT_Keycloak_URL "auth_server_url"
#define JSON_KEY_JWT_Keycloak_Realm "realm"
#define JSON_KEY_JWT_Keycloak_ClientID "client_id"
#define JSON_KEY_JWT_Keycloak_ClientSecret "client_secret"

#define JSON_KEY_HttpThreadPoolSize "HttpThreadPoolSize"
#define JSON_KEY_Roles "Roles"
#define JSON_KEY_Groups "Groups"
#define JSON_KEY_Labels "Labels"
#define JSON_KEY_JWTRedirectUrl "JWTRedirectUrl"
#define JSON_KEY_SECURITY_EncryptKey "EncryptKey"
#define JSON_KEY_VERSION "Version"
#define JSON_KEY_JWT_Users "Users"
#define JSON_KEY_APP_name "name"
#define JSON_KEY_APP_owner "owner"
#define JSON_KEY_APP_owner_permission "permission"
#define JSON_KEY_APP_metadata "metadata"
#define JSON_KEY_APP_shell_mode "shell"
#define JSON_KEY_APP_session_login "session_login"
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
#define REST_PATH_UPLOAD "/appmesh/file/upload"
#define REST_PATH_DOWNLOAD "/appmesh/file/download"

#define JSON_KEY_APP_behavior "behavior"
#define JSON_KEY_APP_behavior_exit "exit"
#define JSON_KEY_APP_behavior_control "control"
#define JSON_KEY_APP_behavior_restart "restart"
#define JSON_KEY_APP_behavior_keepalive "keepalive"
#define JSON_KEY_APP_behavior_standby "standby"
#define JSON_KEY_APP_behavior_remove "remove"

// runtime attr
#define JSON_KEY_APP_pid "pid"
#define JSON_KEY_APP_pid_user "pid_user"
#define JSON_KEY_APP_return "return_code"
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

#define JSON_KEY_TIME_POSTTIX_STR "_TEXT"
#define EMPTY_PLACEHOLDER "-"

#define JSON_KEY_USER_readonly_name "name"
#define JSON_KEY_USER_key "key"
#define JSON_KEY_USER_email "email"
#define JSON_KEY_USER_group "group"
#define JSON_KEY_USER_roles "roles"
#define JSON_KEY_USER_locked "locked"
#define JSON_KEY_USER_metadata "metadata"
#define JSON_KEY_USER_mfa_key "mfa_key"
#define JSON_KEY_USER_mfa_enabled "mfa_enabled"

#define JSON_KEY_USER_exec_user "exec_user"
#define JSON_KEY_USER_audience "audience"

#define JSON_KEY_USER_key_method_local "local"
#define JSON_KEY_USER_key_method_ldap "ldap"
#define JSON_KEY_USER_key_method_consul "consul"
#define JSON_KEY_USER_key_method_oauth2 "oauth2"
#define JSON_KEY_USER_LDAP_ldap_uri "Uri"
#define JSON_KEY_USER_LDAP_ldap_LoginDN "LoginDN"
#define JSON_KEY_USER_LDAP_ldap_LoginPWD "LoginPWD"
#define JSON_KEY_USER_LDAP_ldap_SyncPeriodSeconds "SyncPeriodSeconds"
#define JSON_KEY_USER_LDAP_bind_dn "BindDN"
#define JSON_KEY_USER_LDAP_USER_REPLACE_HOLDER "{USER}"

#define HTTP_HEADER_JWT "JWT"
#define HTTP_HEADER_JWT_Audience_appmesh "appmesh-service"
#define HTTP_HEADER_JWT_name "name"
#define HTTP_HEADER_JWT_user_group "group"
#define HTTP_HEADER_JWT_Authorization web::http::header_names::authorization
#define HTTP_HEADER_JWT_Bearer "Bearer"
#define HTTP_HEADER_JWT_BearerSpace "Bearer "
#define HTTP_HEADER_Auth_BasicSpace "Basic "
#define HTTP_HEADER_JWT_access_token "access_token"

#define HTTP_HEADER_JWT_expire_seconds "X-Expire-Seconds"
#define HTTP_HEADER_JWT_audience "X-Audience"
#define HTTP_HEADER_JWT_totp "X-Totp-Code"
#define HTTP_HEADER_JWT_auth_permission "X-Permission"
#define HTTP_HEADER_KEY_exit_code "X-Exit-Code"
#define HTTP_HEADER_KEY_output_pos "X-Output-Position"
#define HTTP_HEADER_KEY_file_path "X-File-Path"
#define HTTP_HEADER_KEY_file_mode "X-File-Mode"
#define HTTP_HEADER_KEY_file_user "X-File-User"
#define HTTP_HEADER_KEY_file_group "X-File-Group"
#define HTTP_HEADER_KEY_X_Send_File_Socket "X-Send-File-Socket"
#define HTTP_HEADER_KEY_X_Recv_File_Socket "X-Recv-File-Socket"
#define HTTP_HEADER_KEY_Forwarding_Host "X-Target-Host"

#define HTTP_BODY_KEY_MFA_URI "mfa_uri"
#define HTTP_BODY_KEY_OLD_PASSWORD "old_password"
#define HTTP_BODY_KEY_NEW_PASSWORD "new_password"
#define HTTP_BODY_KEY_JWT_username "user_name"
#define HTTP_BODY_KEY_JWT_totp "totp_code"
#define HTTP_BODY_KEY_JWT_totp_challenge "totp_challenge"
#define HTTP_BODY_KEY_JWT_expire_seconds "expire_seconds"

#define HTTP_QUERY_KEY_stdout_position "stdout_position"
#define HTTP_QUERY_KEY_stdout_index "stdout_index"
#define HTTP_QUERY_KEY_stdout_maxsize "stdout_maxsize"
#define HTTP_QUERY_KEY_stdout_timeout "timeout"
#define HTTP_QUERY_KEY_process_uuid "process_uuid"
#define HTTP_QUERY_KEY_html "html"
#define HTTP_QUERY_KEY_json "json"
#define HTTP_QUERY_KEY_timeout "timeout"
#define HTTP_QUERY_KEY_lifecycle "lifecycle"
#define HTTP_QUERY_KEY_action_start "enable"
#define HTTP_QUERY_KEY_action_stop "disable"
#define HTTP_QUERY_KEY_loglevel "level"
#define HTTP_QUERY_KEY_label_value "value"

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
#define PERMISSION_KEY_config_view "config-view"
#define PERMISSION_KEY_config_set "config-set"
#define PERMISSION_KEY_change_passwd_self "passwd-change-self"
#define PERMISSION_KEY_change_passwd_user "passwd-change-user"
#define PERMISSION_KEY_lock_user "user-lock"
#define PERMISSION_KEY_unlock_user "user-unlock"
#define PERMISSION_KEY_add_user "user-add"
#define PERMISSION_KEY_delete_user "user-delete"
#define PERMISSION_KEY_user_totp_disable "user-totp-disable"
#define PERMISSION_KEY_user_totp_active "user-totp-active"
#define PERMISSION_KEY_user_token_renew "user-token-renew"
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

class NotFoundException : public std::logic_error
{
public:
	explicit NotFoundException(const char *) noexcept;
	explicit NotFoundException(const std::string &) noexcept;
};
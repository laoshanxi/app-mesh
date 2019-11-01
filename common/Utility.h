#ifndef UTILITY_H
#define UTILITY_H

#include <string>
#include <cstring>
#include <iostream>
#include <map>
#include <vector>
#include <chrono>
#include <log4cpp/Category.hh>
#include <log4cpp/Priority.hh>

// Remove path name
#if	defined(WIN32)
#define DIRECTORY_SEPARATOR '\\'
#else
#define DIRECTORY_SEPARATOR '/'
#endif

#define ARRAY_LEN(T) (sizeof(T) / sizeof(T[0]))

#define __FILENAME__ (strrchr(__FILE__, DIRECTORY_SEPARATOR) ? strrchr(__FILE__, DIRECTORY_SEPARATOR) + 1 : __FILE__)
#define LOG_DBG    log4cpp::Category::getRoot() << log4cpp::Priority::DEBUG  // << __FILENAME__ << ":" << __LINE__ << ' '
#define LOG_INF    log4cpp::Category::getRoot() << log4cpp::Priority::INFO   // << __FILENAME__ << ":" << __LINE__ << ' '
#define LOG_WAR    log4cpp::Category::getRoot() << log4cpp::Priority::WARN   // << __FILENAME__ << ":" << __LINE__ << ' '
#define LOG_ERR    log4cpp::Category::getRoot() << log4cpp::Priority::ERROR  // << __FILENAME__ << ":" << __LINE__ << ' '

// Expand micro viriable (microkey=microvalue)
#define __MICRO_KEY__(str) #str                // No expand micro
#define __MICRO_VAR__(str) __MICRO_KEY__(str)  // Expand micro

#define PRINT_VERSION() if (argc >= 2 && (std::string("version") == argv[1] || std::string("-v") == argv[1] || std::string("-V") == argv[1])) \
                        { std::cout << "Build: " << __MICRO_VAR__(BUILD_TAG) << std::endl; return 0; }

#define GET_STRING_T(sstr) utility::conversions::to_string_t(std::string(sstr))
#define GET_STD_STRING(sstr)  utility::conversions::to_utf8string(sstr)

#define SET_COMPARE(x, y) if ((x) != (y)) (x) = (y)

// Get attribute from json Object
#define GET_JSON_STR_VALUE(jsonObj, key) Utility::stdStringTrim(GET_STD_STRING(GET_JSON_STR_T_VALUE(jsonObj, key)))
#define GET_JSON_STR_T_VALUE(jsonObj, key) (jsonObj.find(GET_STRING_T(key)) == jsonObj.end() ? GET_STRING_T("") : jsonObj.at(GET_STRING_T(key)).as_string())
#define GET_JSON_INT_VALUE(jsonObj, key) (jsonObj.find(GET_STRING_T(key)) == jsonObj.end() ? 0 : jsonObj.at(GET_STRING_T(key)).as_integer())
#define GET_JSON_NUMBER_VALUE(jsonObj, key) (jsonObj.find(GET_STRING_T(key)) == jsonObj.end() ? 0L : jsonObj.at(GET_STRING_T(key)).as_number().to_int64())
#define SET_JSON_INT_VALUE(jsonObj, key, value) if (HAS_JSON_FIELD(jsonObj, key)) value = GET_JSON_INT_VALUE(jsonObj, key);
#define GET_JSON_BOOL_VALUE(jsonObj, key) (jsonObj.find(GET_STRING_T(key)) == jsonObj.end() ? false : jsonObj.at(GET_STRING_T(key)).as_bool())
#define SET_JSON_BOOL_VALUE(jsonObj, key, value) if (HAS_JSON_FIELD(jsonObj, key)) value = GET_JSON_BOOL_VALUE(jsonObj, key);
#define HAS_JSON_FIELD(jsonObj, key) (jsonObj.find(GET_STRING_T(key)) == jsonObj.end() ? false : true)
#define ERASE_JSON_FIELD(jsonObj, key) if (jsonObj.find(GET_STRING_T(key)) != jsonObj.end()) jsonObj.erase(GET_STRING_T(key));

#define DEFAULT_REST_LISTEN_PORT 6060

#define JWT_ADMIN_KEY "app-mgr-admin-secret-key"
#define JWT_ADMIN_NAME "admin"

enum STATUS
{
	STOPPED = 0,
	ENABLED,
	DESTROYED
};
const char* GET_STATUS_STR(unsigned int status);

//////////////////////////////////////////////////////////////////////////
// All common functions
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
	static bool createDirectory(const std::string& path, mode_t mode = 0775);
	static bool createRecursiveDirectory(const std::string& path, mode_t mode = 0775);
	static bool removeDir(const std::string& path);

	// String related
	static bool isNumber(std::string s);
	static std::string stdStringTrim(const std::string& str);
	static std::string stdStringTrim(const std::string& str, char trimChar, bool trimStart = true, bool trimEnd = true);
	static std::vector<std::string> splitString(const std::string& s, const std::string& c);
	static bool startWith(const std::string& str, std::string head);
	static std::string stringReplace(const std::string& strBase, const std::string& strSrc, const std::string& strDst);
	static std::string humanReadableSize(long double bytesSize);
	static std::string prettyJson(const std::string& jsonStr);

	static void initLogging();
	static bool setLogLevel(const std::string& level);

	static unsigned long long getThreadId();
	static bool getUid(std::string userName, unsigned int& uid, unsigned int& groupid);

	static void getEnvironmentSize(const std::map<std::string, std::string>& envMap, int& totalEnvSize, int& totalEnvArgs);

	// %Y-%m-%d %H:%M:%S
	static std::chrono::system_clock::time_point convertStr2Time(const std::string& strTime);
	static std::string convertTime2Str(const std::chrono::system_clock::time_point& time);
	// %H:%M:%S
	static std::chrono::system_clock::time_point convertStr2DayTime(const std::string& strTime);
	static std::string convertDayTime2Str(const std::chrono::system_clock::time_point& time);
	// Timezone
	static std::string getSystemPosixTimeZone();
	// rfc3339 time
	static std::string getRfc3339Time(const std::chrono::system_clock::time_point& time);
	static std::string getFmtTimeSeconds(const std::chrono::system_clock::time_point& time, const char* fmt);

	// Base64
	static std::string encode64(const std::string& val);
	static std::string decode64(const std::string& val);

	// Read file to string
	static std::string readFile(const std::string& path);
	static std::string readFileCpp(const std::string& path);

	static std::string createUUID();
	static std::string runShellCommand(std::string cmd);
	static void trimLineBreak(std::string& str);
};

#define ENV_APP_MANAGER_LAUNCH_TIME "APP_MANAGER_LAUNCH_TIME"
#define DATE_TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define DATE_TIME_FORMAT_RFC3339 "%FT%TZ"	//= "%Y-%m-%dT%H:%M:%SZ"
#define DEFAULT_TOKEN_EXPIRE_SECONDS (60 * 60) // default 1 hour

#define JSON_KEY_Description "Description"
#define JSON_KEY_RestListenPort "RestListenPort"
#define JSON_KEY_RestListenAddress "RestListenAddress"
#define JSON_KEY_ScheduleIntervalSeconds "ScheduleIntervalSeconds"
#define JSON_KEY_LogLevel "LogLevel"
#define JSON_KEY_SSLEnabled "SSLEnabled"
#define JSON_KEY_RestEnabled "RestEnabled"
#define JSON_KEY_SSLCertificateFile "SSLCertificateFile"
#define JSON_KEY_SSLCertificateKeyFile "SSLCertificateKeyFile"
#define JSON_KEY_JWTEnabled "JWTEnabled"
#define JSON_KEY_HttpThreadPoolSize "HttpThreadPoolSize"
#define JSON_KEY_jwt "JWT"
#define JSON_KEY_Roles "Roles"
#define JSON_KEY_Applications "Applications"
#define JSON_KEY_Labels "Labels"
#define JSON_KEY_JWTRedirectUrl "JWTRedirectUrl"

#define JSON_KEY_APP_name "name"
#define JSON_KEY_APP_user "user"
#define JSON_KEY_APP_comments "comments"
#define JSON_KEY_APP_command "command"
#define JSON_KEY_APP_working_dir "working_dir"
#define JSON_KEY_APP_status "status"
#define JSON_KEY_APP_daily_limitation "daily_limitation"
#define JSON_KEY_APP_resource_limit "resource_limit"
#define JSON_KEY_APP_env "env"
#define JSON_KEY_APP_posix_timezone "posix_timezone"
#define JSON_KEY_APP_cache_lines "cache_lines"
#define JSON_KEY_APP_docker_image "docker_image"
// runtime attr
#define JSON_KEY_APP_pid "pid"
#define JSON_KEY_APP_return "return"
#define JSON_KEY_APP_memory "memory"
#define JSON_KEY_APP_last_start "last_start"
#define JSON_KEY_APP_container_id "container_id"

#define JSON_KEY_PERIOD_APP_keep_running "keep_running"

#define JSON_KEY_SHORT_APP_start_interval_seconds "start_interval_seconds"
#define JSON_KEY_SHORT_APP_start_time "start_time"
#define JSON_KEY_SHORT_APP_start_interval_timeout "start_interval_timeout"

#define JSON_KEY_DAILY_LIMITATION_daily_start "daily_start"
#define JSON_KEY_DAILY_LIMITATION_daily_end "daily_end"

#define JSON_KEY_RESOURCE_LIMITATION_memory_mb "memory_mb"
#define JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb "memory_virt_mb"
#define JSON_KEY_RESOURCE_LIMITATION_cpu_shares "cpu_shares"


#define JSON_KEY_USER_name "name"
#define JSON_KEY_USER_key "key"
#define JSON_KEY_USER_roles "roles"

#define HTTP_HEADER_JWT "JWT"
#define HTTP_HEADER_JWT_ISSUER "appmgr-auth0"
#define HTTP_HEADER_JWT_name "name"
#define HTTP_HEADER_JWT_Authorization "Authorization"
#define HTTP_HEADER_JWT_Bearer "Bearer"
#define HTTP_HEADER_JWT_BearerSpace "Bearer "
#define HTTP_HEADER_JWT_access_token "access_token"
#define HTTP_HEADER_JWT_expire_seconds "expire_seconds"
#define HTTP_HEADER_JWT_username "username"
#define HTTP_HEADER_JWT_password "password"
#define HTTP_HEADER_JWT_auth_permission "auth_permission"
#define HTTP_HEADER_JWT_redirect_from "redirect_from"
#define HTTP_HEADER_KEY_exit_code "exit_code"
#define HTTP_HEADER_KEY_file_path "file_path"
#define HTTP_HEADER_KEY_file_mode "file_mode"
#define HTTP_HEADER_KEY_file_user "file_user"

#define HTTP_QUERY_KEY_keep_history "keep_history"
#define HTTP_QUERY_KEY_process_uuid "process_uuid"
#define HTTP_QUERY_KEY_timeout "timeout"
#define HTTP_QUERY_KEY_action "action"
#define HTTP_QUERY_KEY_action_start "start"
#define HTTP_QUERY_KEY_action_stop "stop"
#define HTTP_QUERY_KEY_loglevel "level"
#define HTTP_QUERY_KEY_label_value "value"


#define PERMISSION_KEY_view_app					"view-app"
#define PERMISSION_KEY_view_app_output			"view-app-output"
#define PERMISSION_KEY_view_all_app				"view-all-app"
#define PERMISSION_KEY_view_host_resource		"view-host-resource"
#define PERMISSION_KEY_app_reg					"app-reg"
#define PERMISSION_KEY_app_reg_shell			"app-reg-shell"
#define PERMISSION_KEY_app_control				"app-control"
#define PERMISSION_KEY_app_delete				"app-delete"
#define PERMISSION_KEY_run_app_async			"run-app-async"
#define PERMISSION_KEY_run_app_sync				"run-app-sync"
#define PERMISSION_KEY_run_app_async_output		"run-app-async-output"
#define PERMISSION_KEY_file_download			"file-download"
#define PERMISSION_KEY_file_upload				"file-upload"
#define PERMISSION_KEY_label_view				"label-view"
#define PERMISSION_KEY_label_update				"label-update"
#define PERMISSION_KEY_label_set				"label-set"
#define PERMISSION_KEY_label_delete				"label-delete"
#define PERMISSION_KEY_loglevel  				"log-level"

#endif


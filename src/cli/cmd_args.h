#pragma once

#ifndef APP_MESH_CLI_ARGUMENTS_H
#define APP_MESH_CLI_ARGUMENTS_H

#define HOST_URL "host-url"
#define HOST_URL_ARGS "host-url,H"

#define FORWARD_TO "forward-to"
#define FORWARD_TO_ARGS "forward-to,F"

#define USERNAME "user"
#define USERNAME_ARGS "user,U"
#define PASSWORD "password"
#define PASSWORD_ARGS "password,X"

#define VERBOSE "verbose"
#define VERBOSE_ARGS "verbose,v"
#define HELP "help"
#define HELP_ARGS "help,h"
#define FORCE "force"
#define FORCE_ARGS "force,f"
#define TIMEOUT "timeout"
#define TIMEOUT_ARGS "timeout,t"
#define AUDIENCE "audience"
#define AUDIENCE_ARGS "audience,a"

#define APP "app"
#define APP_ARGS "app,a"
#define LONG "long"
#define LONG_ARGS "long,l"
#define SHOW_OUTPUT "show-output"
#define SHOW_OUTPUT_ARGS "show-output,o"
#define PSTREE "pstree"
#define PSTREE_ARGS "pstree,P"
#define LOG_INDEX "log-index"
#define LOG_INDEX_ARGS "log-index,i"
#define FOLLOW "follow"
#define FOLLOW_ARGS "follow,f"
#define JSON "json"
#define JSON_ARGS "json,j"

#define ALL "all"
#define ALL_ARGS "all,A"

#define DESC "description"
#define DESC_ARGS "description,d"
#define COMMAND "cmd"
#define COMMAND_ARGS "cmd,c"
#define SHELL "shell"
#define SHELL_ARGS "shell,u"
#define SESSION_LOGIN "session-login"
#define SESSION_LOGIN_ARGS "session-login,G"
#define METADATA "metadata"
#define METADATA_ARGS "metadata,m"
#define WORKING_DIR "working-dir"
#define WORKING_DIR_ARGS "working-dir,w"
#define ENV "env"
#define ENV_ARGS "env,e"
#define LIFETIME "lifetime"
#define LIFETIME_ARGS "lifetime,T"

#define PERMISSION "permission"
#define PERMISSION_ARGS "permission,p"
#define HEALTHCHECK "health-check"
#define HEALTHCHECK_ARGS "health-check,H"
#define DOCKER_IMAGE "docker-image"
#define DOCKER_IMAGE_ARGS "docker-image,I"
#define STATUS "status"
#define STATUS_ARGS "status,s"
#define BEGIN_TIME "begin-time"
#define BEGIN_TIME_ARGS "begin-time,b"
#define END_TIME "end-time"
#define END_TIME_ARGS "end-time,x"
#define DAILY_BEGIN "daily-begin"
#define DAILY_BEGIN_ARGS "daily-begin,S"
#define DAILY_END "daily-end"
#define DAILY_END_ARGS "daily-end,E"
#define MEMORY_LIMIT "memory-limit"
#define MEMORY_LIMIT_ARGS "memory-limit,M"
#define VIRTUAL_MEMORY "virtual-memory"
#define VIRTUAL_MEMORY_ARGS "virtual-memory,V"
#define CPU_SHARES "cpu-shares"
#define CPU_SHARES_ARGS "cpu-shares,C"
#define PID "pid"
#define PID_ARGS "pid,P"
#define LOG_CACHE_SIZE "log-cache-size"
#define LOG_CACHE_SIZE_ARGS "log-cache-size,N"
#define SECURITY_ENV "security-env"
#define SECURITY_ENV_ARGS "security-env,z"
#define INTERVAL "interval"
#define INTERVAL_ARGS "interval,i"
#define CRON "cron"
#define CRON_ARGS "cron,Y"
#define STOP_TIMEOUT "stop-timeout"
#define STOP_TIMEOUT_ARGS "stop-timeout,R"
#define EXIT "exit"
#define EXIT_ARGS "exit,Q"
#define CONTROL "control"
#define CONTROL_ARGS "control,T"
#define STDIN "stdin"
#define STDIN_ARGS "stdin,D"

#define RETRY "retry"
#define RETRY_ARGS "retry,r"

#define REMOTE "remote"
#define REMOTE_ARGS "remote,r"
#define LOCAL "local"
#define LOCAL_ARGS "local,l"
#define COPY_ATTR "no-attr"
#define COPY_ATTR_ARGS "no-attr,a"

#define VIEW "view"
#define VIEW_ARGS "view,v"
#define ADD "add"
#define ADD_ARGS "add,a"
#define DELETE "delete"
#define DELETE_ARGS "delete,d"
#define LABEL "label"
#define LABEL_ARGS "label,l"

#define LEVEL "level"
#define LEVEL_ARGS "level,L"

#define TARGET "target"
#define TARGET_ARGS "target,t"
#define LOCK "lock"
#define LOCK_ARGS "lock,k"
#define JSON "json"
#define JSON_ARGS "json,j"

#endif // APP_MESH_CLI_ARGUMENTS_H
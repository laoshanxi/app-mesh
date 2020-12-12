#pragma once
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

/*
* How to enable valgrind test :
*   - touch /opt/appmesh/appsvc.valgrind
* How to finish test :
*   - touch /opt/appmesh/appsvc.valgrind.stop
* Check valgrind report : 
*   - /opt/appmesh/appsvc.valgrind.$pid.log
*/

static char **CMD_ARGV = 0;
constexpr auto VALGRIND_CMD = "/usr/bin/valgrind";
constexpr auto VALGRIND_ENABLE_FILE = ".valgrind";
constexpr auto VALGRIND_STOP_FILE = ".valgrind.stop";
constexpr auto VALGRIND_CHILD_ENV_FLAG = "VALGRIND_PARENT_ENV_FLAG";
constexpr auto VALGRIND_ENV_RUN_ONCE = "VALGRIND_ENV_RUN_ONCE";

// 'argv' is argv from main()
//  set 0 if application have no arguments.
#define VALGRIND_ENTRYPOINT(argv) \
    CMD_ARGV = argv;              \
    valgrind_main();

// Use this for only want to run one time
static bool RUN_ONE_TIME = false;
#define VALGRIND_ENTRYPOINT_ONE_TIME(argv) \
    RUN_ONE_TIME = true;                   \
    VALGRIND_ENTRYPOINT(argv);

// program_name from errno.h
extern char *program_invocation_short_name;
std::string binaryName()
{
    return program_invocation_short_name;
}

std::string getSelfFullPath()
{
    std::string path;
    char buf[1024] = {0};
    int len = sizeof(buf);
    int rslt = readlink("/proc/self/exe", buf, len - 1);
    if (rslt < 0 || (rslt >= len - 1))
    {
        //return NULL;
    }
    else
    {
        path = buf;
    }
    return path;
}

std::string getFullCommandLine()
{
    auto path = getSelfFullPath();
    int i = 1;
    while (CMD_ARGV && CMD_ARGV[i])
    {
        path += " ";
        path += CMD_ARGV[i];
        ++i;
    }
    return path;
}
bool binaryExtentionExist(const char *fileSuffix)
{
    auto cmdPath = getSelfFullPath() + fileSuffix;
    if (access(cmdPath.c_str(), 0) == 0)
    {
        return true;
    }
    return false;
}

bool isValgrindEnabled()
{
    bool valgrindEnabled = binaryExtentionExist(VALGRIND_ENABLE_FILE);
    return (access(VALGRIND_CMD, 0) == 0 &&
            valgrindEnabled &&
            !binaryExtentionExist(VALGRIND_STOP_FILE));
}

void *valgrindStopMonitorThread(void *p)
{
    while (true)
    {
        if (binaryExtentionExist(VALGRIND_STOP_FILE))
        {
            exit(0);
        }
        sleep(1);
    }
}

void valgrind_main()
{
    if (!isValgrindEnabled())
        return;

    const char *childFlag = getenv(VALGRIND_CHILD_ENV_FLAG);
    if (!childFlag)
    {
        if (::access(VALGRIND_CMD, 0) != 0)
        {
            printf("no valgrind installed\n");
            return;
        }
        // 1. parent process will start a valgrind child process and wait here, valgrind will inherit environment from parent
        // valgrind --tool=memcheck --leak-check=full --error-limit=no --trace-children=yes --log-file=app_name.valgrind.%p.log
        std::string valgrindStartCmd = VALGRIND_CMD;
        valgrindStartCmd += " --tool=memcheck --leak-check=full --show-reachable=yes --error-limit=no --log-file=";
        valgrindStartCmd += binaryName();
        valgrindStartCmd += ".valgrind.%p.log ";
        valgrindStartCmd += getFullCommandLine();

        std::string env = std::string(VALGRIND_CHILD_ENV_FLAG) + "=" + VALGRIND_CHILD_ENV_FLAG;
        putenv(strdup(env.c_str()));
        if (RUN_ONE_TIME)
        {
            std::string runOnceEnv = std::string(VALGRIND_ENV_RUN_ONCE) + "=" + VALGRIND_ENV_RUN_ONCE;
            putenv(strdup(runOnceEnv.c_str()));
            puts(runOnceEnv.c_str());
        }
        puts(valgrindStartCmd.c_str());
        int pid = system(valgrindStartCmd.c_str());
        if (pid > 0)
        {
            waitpid(pid, NULL, 0);
        }
        exit(0);
    }
    else
    {
        // 2. valgrind process enter here, start a monitor thread and continue
        pthread_t t_id;
        pthread_create(&t_id, NULL, valgrindStopMonitorThread, NULL);
        if (getenv(VALGRIND_ENV_RUN_ONCE))
        {
            std::string valrindEnableFile = getSelfFullPath() + VALGRIND_ENABLE_FILE;
            unlink(valrindEnableFile.c_str());
            printf("Run for one time, remove : %s\n", valrindEnableFile.c_str());
        }
    }
}

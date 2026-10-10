// src/common/QuitHandler.cpp
#include "QuitHandler.h"

#include "StreamLogger.h"
#include "Utility.h"

#include <csignal>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#endif

namespace
{
#if defined(_WIN32)
    // Auto-reset event: waitForExit() blocks on it, the console handler signals it.
    HANDLE g_wakeEvent = nullptr;
#else
    // Self-pipe: the signal handler writes one byte, waitForExit() polls it.
    int g_wakePipe[2] = {-1, -1};
#endif

#if !defined(_WIN32)
    // A second signal means the graceful shutdown is stuck: force the process out.
    std::atomic<int> g_signalCount{0};

    // Async-signal-safe only: no allocation, no locks, no logging.
    void posixExitSignalHandler(int signum)
    {
        if (g_signalCount.fetch_add(1, std::memory_order_acq_rel) > 0)
        {
            const char message[] = "AppMesh: second signal received, forcing exit.\n";
            const ssize_t written = ::write(STDERR_FILENO, message, sizeof(message) - 1);
            (void)written;
            ::_exit(128 + signum);
        }
        QuitHandler::instance()->markExit();
    }
#else
    BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType)
    {
        switch (dwCtrlType)
        {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            QuitHandler::instance()->requestExit();
            return TRUE;
        default:
            return FALSE;
        }
    }
#endif
}

QuitHandler *QuitHandler::instance()
{
    static QuitHandler instance;
    return &instance;
}

bool QuitHandler::shouldExit() const
{
    return m_exit_flag.load(std::memory_order_relaxed);
}

void QuitHandler::markExit()
{
    m_exit_flag.store(true, std::memory_order_release);
#if defined(_WIN32)
    if (g_wakeEvent)
        SetEvent(g_wakeEvent);
#else
    if (g_wakePipe[1] >= 0)
    {
        const char byte = 1;
        const ssize_t written = ::write(g_wakePipe[1], &byte, 1);
        (void)written;
    }
#endif
}

void QuitHandler::requestExit()
{
    const static char fname[] = "QuitHandler::requestExit() ";

    if (!m_exit_flag.exchange(true, std::memory_order_acq_rel))
        LOG_INF << fname << "Exit requested.";
    markExit();
}

bool QuitHandler::waitForExit(std::chrono::milliseconds timeout)
{
    if (shouldExit())
        return true;

#if defined(_WIN32)
    if (g_wakeEvent)
        WaitForSingleObject(g_wakeEvent, static_cast<DWORD>(timeout.count()));
    else
        std::this_thread::sleep_for(timeout);
#else
    if (g_wakePipe[0] >= 0)
    {
        // Unrelated signals (SIGCHLD from managed apps) interrupt poll(); wait
        // out the remaining timeout instead of ending the schedule tick early.
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;)
        {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (remaining.count() <= 0)
                break;

            struct pollfd wakePoll;
            wakePoll.fd = g_wakePipe[0];
            wakePoll.events = POLLIN;
            wakePoll.revents = 0;
            const int ready = ::poll(&wakePoll, 1, static_cast<int>(remaining.count()));
            if (ready > 0)
            {
                char drain[64];
                while (::read(g_wakePipe[0], drain, sizeof(drain)) > 0)
                {
                }
                break;
            }
            if (ready == 0 || errno != EINTR)
                break;
        }
    }
    else
    {
        std::this_thread::sleep_for(timeout);
    }
#endif

    return shouldExit();
}

bool setupQuitHandler()
{
    const static char fname[] = "setupQuitHandler() ";

#if defined(_WIN32)
    g_wakeEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!g_wakeEvent)
    {
        LOG_ERR << fname << "Failed to create the wake event. Error: " << GetLastError();
        return false;
    }
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE))
    {
        LOG_ERR << fname << "Failed to register the Windows console handler. Error: " << GetLastError();
        return false;
    }
    LOG_DBG << fname << "Windows console handler registered.";
#else
    if (::pipe(g_wakePipe) != 0)
    {
        LOG_ERR << fname << "Failed to create the wake pipe: " << last_error_msg();
        return false;
    }
    for (const int fd : g_wakePipe)
    {
        ::fcntl(fd, F_SETFL, O_NONBLOCK); // the signal handler must never block
        ::fcntl(fd, F_SETFD, FD_CLOEXEC); // not inherited by spawned apps
    }

    struct sigaction action;
    action.sa_handler = posixExitSignalHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    for (const int signum : {SIGINT, SIGTERM, SIGQUIT})
    {
        if (::sigaction(signum, &action, nullptr) == -1)
        {
            LOG_ERR << fname << "Failed to register signal " << signum << ": " << last_error_msg();
            ::close(g_wakePipe[0]);
            ::close(g_wakePipe[1]);
            g_wakePipe[0] = g_wakePipe[1] = -1;
            return false;
        }
    }
    LOG_DBG << fname << "POSIX signal handlers registered.";
#endif

    return true;
}

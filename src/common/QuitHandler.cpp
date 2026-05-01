// src/common/QuitHandler.cpp
#include "QuitHandler.h"

#include "Utility.h"

#include <iostream>
#include <signal.h>

#if defined(_WIN32)
// For BOOL and DWORD (Windows data types)
#include <windows.h>
#endif

QuitHandler *QuitHandler::instance()
{
    static QuitHandler instance;
    return &instance;
}

bool QuitHandler::shouldExit() const
{
    // Use relaxed memory order for optimal lock-free check
    return m_exit_flag.load(std::memory_order_relaxed);
}

void QuitHandler::requestExit()
{
    const static char fname[] = "QuitHandler::requestExit() ";

    bool expected = false;
    if (m_exit_flag.compare_exchange_strong(expected, true))
    {
        LOG_INF << fname << "Exit requested.";
        if (auto r = reactor())
            r->end_reactor_event_loop();
    }
}

int QuitHandler::handle_signal(int signum, siginfo_t *, ucontext_t *)
{
    // Async-signal-safe only — spdlog locks a mutex, calling it from a signal
    // handler deadlocks. Main loop logs the shutdown.
    // Only exit signals trigger termination; reload-style signals (SIGHUP,
    // SIGUSR1/2) must be handled elsewhere and must NOT set the exit flag.
    switch (signum)
    {
    case SIGTERM:
    case SIGINT:
#ifdef SIGQUIT
    case SIGQUIT:
#endif
        break;
    default:
        return 0;
    }

    m_exit_flag.store(true, std::memory_order_release);
    if (auto r = reactor())
        r->end_reactor_event_loop();
    return 0;
}

QuitHandler::QuitHandler() : m_exit_flag(false) {}

// --- Windows Console Handler Wrapper (Windows-specific logic) ---

#if defined(_WIN32)
// This must be defined in the .cpp file as it is a helper function
BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        // Forward the control event to the Singleton
        QuitHandler::instance()->requestExit();
        return TRUE; // Signal handled
    default:
        return FALSE;
    }
}
#endif

// --- setupQuitHandler Implementation ---

bool setupQuitHandler(ACE_Reactor *reactor)
{
    const static char fname[] = "setupQuitHandler() ";

    QuitHandler::instance()->reactor(reactor);

    // Registration Logic
#if defined(_WIN32)
    // Windows: Register native console handler
    if (SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE)) // Success is TRUE
    {
        LOG_DBG << fname << "Windows Console Handler registered.";
    }
    else
    {
        LOG_ERR << fname << "Failed to register Windows Console Handler. Error: " << GetLastError();
        return false;
    }
#else
    // POSIX: Register signals with ACE_Reactor
    // Note: We pass the address (&) because instance() returns a reference
    if (reactor->register_handler(SIGINT, QuitHandler::instance()) == -1)
    {
        LOG_ERR << fname << "Failed to register SIGINT handler.";
        return false;
    }
    if (reactor->register_handler(SIGTERM, QuitHandler::instance()) == -1)
    {
        LOG_ERR << fname << "Failed to register SIGTERM handler.";
        return false;
    }

    LOG_DBG << fname << "POSIX Signal Handlers registered.";
#endif

    return true;
}
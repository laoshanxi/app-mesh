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
    // Atomically set the flag if it was false
    if (m_exit_flag.compare_exchange_strong(expected, true))
    {
        // Only log and wake the reactor on the first call
        LOG_INF << fname << "Exit requested.";

        // Wake up reactor if it's blocking in handle_events
        // This is crucial for applications that block in the reactor loop
        if (auto r = reactor())
            r->end_reactor_event_loop();
    }
}

int QuitHandler::handle_signal(int signum, siginfo_t *, ucontext_t *)
{
    const static char fname[] = "QuitHandler::handle_signal() ";

    LOG_INF << fname << "QuitHandler: Signal received:" << signum;
    requestExit();

    // Return 0 to stay registered, -1 to unregister (usually 0 is preferred)
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
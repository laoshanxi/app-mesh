// src/common/QuitHandler.cpp
#include "QuitHandler.h"

#include "Utility.h"

#include <iostream>
#include <signal.h>

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

// --- setupQuitHandler Implementation ---

bool setupQuitHandler(ACE_Reactor *reactor)
{
    const static char fname[] = "setupQuitHandler() ";

    QuitHandler::instance()->reactor(reactor);

    // Registration Logic
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

    return true;
}
// src/common/QuitHandler.h
#pragma once

#include <ace/Event_Handler.h>
#include <ace/Reactor.h>
#include <atomic>

/**
 * @class QuitHandler
 * @brief Singleton handler for application exit events (Signals/Console Events).
 * * Uses ACE_Event_Handler for POSIX signal integration and a separate
 * Windows console handler for Windows. The exit flag is atomic and lock-free.
 * Similar with <ace/Test_and_Set.h> but better performance
 */
class QuitHandler : public ACE_Event_Handler
{
public:
    static QuitHandler *instance();
    bool shouldExit() const; // Check if an exit has been requested (lock-free)
    void requestExit();      // Request to exit (sets flag and wakes up Reactor)

    /// Called when object is signaled by OS (either via UNIX signals or
    /// when a Win32 object becomes signaled).
    virtual int handle_signal(int signum, siginfo_t * = 0, ucontext_t * = 0) override;

private:
    QuitHandler(); // Private constructor/destructor for Singleton
    virtual ~QuitHandler() = default;

    // Delete copy/move
    QuitHandler(const QuitHandler &) = delete;
    QuitHandler &operator=(const QuitHandler &) = delete;

    std::atomic<bool> m_exit_flag;
};

/**
 * @brief Registers the necessary signal/console handlers for graceful exit.
 * @param reactor The ACE_Reactor instance to use for POSIX signals.
 * @return true on successful registration, false otherwise.
 */
bool setupQuitHandler(ACE_Reactor *reactor = ACE_Reactor::instance());

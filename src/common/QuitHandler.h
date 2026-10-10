// src/common/QuitHandler.h
#pragma once

#include <atomic>
#include <chrono>

/**
 * @class QuitHandler
 * @brief Process exit flag with the platform exit-signal plumbing.
 *
 * POSIX: sigaction handlers set the flag and wake a self-pipe (async-signal-safe,
 * no ACE reactor involved). Windows: a console control handler. Waiters use
 * waitForExit() instead of polling sleep, so a shutdown request is acted on
 * immediately rather than on the next schedule tick. A second signal forces an
 * immediate process exit.
 */
class QuitHandler
{
public:
    static QuitHandler *instance();

    /// Check if an exit has been requested (lock-free).
    bool shouldExit() const;
    /// Request an exit from thread context: sets the flag, wakes waiters, logs.
    void requestExit();
    /// Async-signal-safe: sets the flag and wakes waiters, nothing else.
    void markExit();
    /// Blocks until an exit is requested or the timeout elapses; true if exiting.
    bool waitForExit(std::chrono::milliseconds timeout);

private:
    QuitHandler() = default;
    ~QuitHandler() = default;

    QuitHandler(const QuitHandler &) = delete;
    QuitHandler &operator=(const QuitHandler &) = delete;

    std::atomic<bool> m_exit_flag{false};
};

/**
 * @brief Registers the platform exit handlers (POSIX signals / Windows console).
 * @return true on successful registration, false otherwise.
 */
bool setupQuitHandler();

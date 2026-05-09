#pragma once
// ---------------------------------------------------------------------------
// SIGCHLD signal-safety guard for non-reactor threads
// ---------------------------------------------------------------------------
// ACE_Process_Manager::handle_signal() calls reactor()->notify() from signal
// context, which acquires ACE_Notification_Queue::notify_queue_lock_ (a plain
// pthread_mutex — NOT async-signal-safe).  If SIGCHLD interrupts a thread
// that already holds that mutex (via register_handler / cancel_timer /
// remove_handler / mask_ops / notify → Token::sleep_hook →
// push_new_notification), the signal handler re-enters push_new_notification
// on the same non-recursive mutex, causing permanent self-deadlock.
//
// BLOCK_SIGCHLD_FOR_THREAD() — call once at thread entry to permanently
//     block SIGCHLD for the calling thread's lifetime.  Preferred for
//     worker and timer threads: zero per-call overhead, no risk of
//     forgetting a guard at individual call sites.
//
// SCOPED_SIGCHLD_BLOCK — RAII guard that blocks SIGCHLD for the current
//     scope only.  Use when the thread entry point is not under our
//     control (e.g. ACE internal threads) or for one-off protection.
//
// IMPORTANT: Never block SIGCHLD on reactor IO threads — they must
//     remain eligible to receive SIGCHLD for child-process reaping.
//
// Ref: C++NPv2 (Douglas C. Schmidt) §3 Sidebar 17:
// "Avoiding Reactor Notification Mechanism Deadlock"
// ---------------------------------------------------------------------------

#if !defined(_WIN32)
#include <signal.h>

inline void blockSigchldForThread()
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &mask, nullptr);
}

struct ScopedSigchldBlock
{
	ScopedSigchldBlock()
	{
		sigemptyset(&m_mask);
		sigaddset(&m_mask, SIGCHLD);
		pthread_sigmask(SIG_BLOCK, &m_mask, &m_prev);
	}
	~ScopedSigchldBlock() { pthread_sigmask(SIG_SETMASK, &m_prev, nullptr); }

	ScopedSigchldBlock(const ScopedSigchldBlock &) = delete;
	ScopedSigchldBlock &operator=(const ScopedSigchldBlock &) = delete;

private:
	sigset_t m_mask;
	sigset_t m_prev;
};

#define BLOCK_SIGCHLD_FOR_THREAD() blockSigchldForThread()
#define SCOPED_SIGCHLD_BLOCK ScopedSigchldBlock _sigchld_guard
#else
#define BLOCK_SIGCHLD_FOR_THREAD() ((void)0)
#define SCOPED_SIGCHLD_BLOCK ((void)0)
#endif

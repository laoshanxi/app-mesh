// src/daemon/process/ProcessManager.cpp
#include "ProcessManager.h"

#include <ace/Guard_T.h>

#if defined(_WIN32)
int Process_Manager::handle_signal(int signum, siginfo_t *info, ucontext_t *context)
{
	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_mutex);
	return ACE_Process_Manager::handle_signal(signum, info, context);
}
#else
int Process_Manager::handle_input(ACE_HANDLE handle)
{
	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_mutex);
	return ACE_Process_Manager::handle_input(handle);
}
#endif

ACE_Recursive_Thread_Mutex &Process_Manager::mutex()
{
	return m_mutex;
}

Process_Manager *Process_Manager::instance()
{
	static Process_Manager pm;
	return &pm;
}

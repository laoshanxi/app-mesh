// src/daemon/process/ProcessManager.cpp
#include "ProcessManager.h"

#include <ace/Guard_T.h>

int Process_Manager::handle_input(ACE_HANDLE handle)
{
	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_mutex);
	return ACE_Process_Manager::handle_input(handle);
}

ACE_Recursive_Thread_Mutex &Process_Manager::mutex()
{
	return m_mutex;
}

Process_Manager *Process_Manager::instance()
{
	static Process_Manager pm;
	return &pm;
}

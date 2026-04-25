// src/daemon/process/ProcessManager.cpp
#include "ProcessManager.h"

ACE_Recursive_Thread_Mutex &Process_Manager::mutex()
{
	return m_mutex;
}

Process_Manager *Process_Manager::instance()
{
	static Process_Manager pm;
	return &pm;
}

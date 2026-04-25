// src/daemon/process/ProcessManager.h
#pragma once

#include <ace/Process_Manager.h>

// ACE_Process_Manager with exposed mutex for thread-safe process management.
class Process_Manager : public ACE_Process_Manager
{
public:
	~Process_Manager() = default;
	static Process_Manager *instance();
	ACE_Recursive_Thread_Mutex &mutex();

private:
	ACE_Recursive_Thread_Mutex m_mutex;
};

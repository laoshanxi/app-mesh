// src/daemon/process/AttachProcess.cpp
#include "AttachProcess.h"

AttachProcess::AttachProcess(pid_t pid)
{
#if defined(_WIN32)
	process_info_.hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, pid);
	if (process_info_.hProcess)
		process_info_.dwProcessId = pid;
#else
	child_id_ = pid;
#endif
}

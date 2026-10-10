// src/daemon/process/AttachProcess.cpp
#include "AttachProcess.h"

AttachProcess::AttachProcess(pid_t pid)
{
	child_id_ = pid;
}

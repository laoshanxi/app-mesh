// src/daemon/process/AttachProcess.h
#pragma once

#include <ace/Process.h>

// Construct an ACE_Process with a given pid for synchronous waitpid.
class AttachProcess : public ACE_Process
{
public:
	explicit AttachProcess(pid_t pid);
	~AttachProcess() = default;
};

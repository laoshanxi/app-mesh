#ifndef MONITORED_PROCESS_H
#define MONITORED_PROCESS_H
#include <ace/Process.h>
#include <ace/Pipe.h>
#include <thread>
#include <memory>
#include <queue>
#include <mutex>
#include "AppProcess.h"

//////////////////////////////////////////////////////////////////////////
// Monitored Process Object
//////////////////////////////////////////////////////////////////////////
class MonitoredProcess :public AppProcess
{
public:
	explicit MonitoredProcess(int cacheOutputLines, bool enableBuildinThread = true);
	virtual ~MonitoredProcess();

	// overwrite ACE_Process spawn method
	virtual pid_t spawn(ACE_Process_Options &options);

	virtual pid_t wait(ACE_exitcode* status = 0, int wait_options = 0);
	virtual void safeWait(int timerId = 0);
	void setAsyncHttpRequest(void* httpRequest) { m_httpRequest = httpRequest; }

	// pipe message
	virtual std::string getOutputMsg() override;
	virtual std::string fetchOutputMsg() override;
	void runPipeReaderThread();
	virtual bool complete() override { return m_buildinThreadFinished; }
private:
	ACE_HANDLE m_pipeHandler[2]; // 0 for read, 1 for write
	std::shared_ptr<ACE_Pipe> m_pipe;
	FILE* m_readPipeFile;
	
	std::queue<std::string> m_msgQueue;
	std::recursive_mutex m_queueMutex;
	void* m_httpRequest;

	std::shared_ptr<std::thread> m_thread;
	bool m_buildinThreadFinished;
	bool m_enableBuildinThread;
};

#endif 


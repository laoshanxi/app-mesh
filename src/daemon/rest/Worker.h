#pragma once
#include "Data.h"

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>
#include <ace/Task.h>
#include <concurrentqueue/blockingconcurrentqueue.h>

#include <memory>

namespace WSS
{
	class ReplyContext;
}
class HttpRequest;
struct HttpRequestMsg;
using RequestQueue = moodycamel::BlockingConcurrentQueue<std::shared_ptr<HttpRequestMsg>>;

class Worker : public ACE_Task_Base
{
public:
	Worker() = default;
	virtual ~Worker(void) = default;

public:
	bool processRequest(std::shared_ptr<HttpRequest> &request);
	void queueInputRequest(ByteBuffer &data, int tcpHandlerID, void *lwsSessionID = NULL, std::shared_ptr<WSS::ReplyContext> uwsContext = nullptr);

protected:
	virtual int svc();
	bool processForward(const std::string forwardTo, std::shared_ptr<HttpRequest> &request);

	RequestQueue m_messages;
};

using WORKER = ACE_Singleton<Worker, ACE_Null_Mutex>;

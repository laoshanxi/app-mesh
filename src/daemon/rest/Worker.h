// src/daemon/rest/Worker.h
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
	~Worker() override = default;

	bool processRequest(std::shared_ptr<HttpRequest> &request);
	void queueInputRequest(ByteBuffer &data, int tcpClientId, void *lwsSessionID = nullptr, std::shared_ptr<WSS::ReplyContext> uwsContext = nullptr);
	void shutdown();

protected:
	int svc() override;
	bool processForward(const std::string forwardTo, std::shared_ptr<HttpRequest> &request);

	RequestQueue m_messages;
};

using WORKER = ACE_Singleton<Worker, ACE_Null_Mutex>;

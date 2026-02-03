// src/daemon/rest/Worker.h
#pragma once

#include "Data.h"

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>
#include <ace/Task.h>
#include <concurrentqueue/blockingconcurrentqueue.h>

#include <memory>
#include <string>

namespace WSS
{
	class ReplyContext;
}

class HttpRequest;
struct HttpRequestContext;

using RequestQueue = moodycamel::BlockingConcurrentQueue<std::shared_ptr<HttpRequestContext>>;

class Worker : public ACE_Task_Base
{
public:
	Worker() = default;
	~Worker() override = default;

	// Non-copyable and non-movable
	Worker(const Worker &) = delete;
	Worker &operator=(const Worker &) = delete;
	Worker(Worker &&) = delete;
	Worker &operator=(Worker &&) = delete;

	bool process(const std::shared_ptr<HttpRequest> &request);

	void queueTcpRequest(ByteBuffer &&data, int tcpClientId);
	void queueLwsRequest(ByteBuffer &&data, void *lwsSession);
	void queueUwsRequest(ByteBuffer &&data, std::shared_ptr<WSS::ReplyContext> uwsContext);

	void shutdown();

protected:
	int svc() override;
	bool forward(std::string forwardTo, const std::shared_ptr<HttpRequest> &request);

private:
	RequestQueue m_messages;
};

using WORKER = ACE_Singleton<Worker, ACE_Null_Mutex>;

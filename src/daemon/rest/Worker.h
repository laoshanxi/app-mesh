// src/daemon/rest/Worker.h
#pragma once

#include "Data.h"
#include "../../common/Utility.h"

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>
#include <ace/Task.h>
#include <concurrentqueue/blockingconcurrentqueue.h>

#include <atomic>
#include <memory>
#include <string>

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

	// Answer an lws request with a correlated error frame; false when no uuid
	// could be recovered from the payload.
	static bool replyErrorLws(const LwsSessionRef &lwsRef, const ByteBuffer &data,
							  web::http::status_code status, const std::string &message);

	void queueTcpRequest(ByteBuffer &&data, int tcpClientId);
	void queueLwsRequest(ByteBuffer &&data, LwsSessionRef lwsRef);

	void shutdown();

protected:
	int svc() override;
	bool forward(std::string forwardTo, const std::shared_ptr<HttpRequest> &request);

private:
	// Returns false when the shared queue is saturated or allocation fails; the
	// caller must then answer the request itself. Not for the sentinel.
	bool enqueueRequest(const std::shared_ptr<HttpRequestContext> &ctx);

	RequestQueue m_messages;
	std::atomic<size_t> m_pendingCount{0}; // in-flight requests queued but not yet processed
};

using WORKER = ACE_Singleton<Worker, ACE_Null_Mutex>;

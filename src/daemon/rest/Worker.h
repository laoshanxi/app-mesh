// src/daemon/rest/Worker.h
#pragma once

#include "../../common/Utility.h"
#include "Data.h"

#include <concurrentqueue/blockingconcurrentqueue.h>

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace WSS
{
	class ReplyContext;
}

class HttpRequest;
struct HttpRequestContext;

using RequestQueue = moodycamel::BlockingConcurrentQueue<std::shared_ptr<HttpRequestContext>>;

class Worker
{
public:
	static Worker *instance();

	Worker() = default;
	~Worker() = default;

	// Non-copyable and non-movable
	Worker(const Worker &) = delete;
	Worker &operator=(const Worker &) = delete;
	Worker(Worker &&) = delete;
	Worker &operator=(Worker &&) = delete;

	/// Spawn `threadCount` worker threads draining the shared queue.
	void start(size_t threadCount);

	bool process(const std::shared_ptr<HttpRequest> &request);

	void queueWsRequest(std::string &&data, std::shared_ptr<WSS::ReplyContext> wsContext);

	void shutdown();

	/// Join every worker thread.
	void wait();

protected:
	void svc();
	bool forward(std::string forwardTo, const std::shared_ptr<HttpRequest> &request);

private:
	// Drops and returns false when the shared queue is saturated. Not for the sentinel.
	bool enqueueRequest(std::shared_ptr<HttpRequestContext> ctx);

	RequestQueue m_messages;
	std::atomic<size_t> m_pendingCount{0}; // in-flight requests queued but not yet processed
	size_t m_threadCount{0};               // matched by shutdown() sentinels and joined by wait()
	std::vector<std::thread> m_threads;
};

using WORKER = Worker;

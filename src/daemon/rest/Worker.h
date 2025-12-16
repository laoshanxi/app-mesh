#pragma once
#include "Data.h"

#include <concurrentqueue/blockingconcurrentqueue.h>
#include <memory>

namespace WSS
{
	class ReplyContext;
}
class HttpRequest;
struct HttpRequestMsg;
using RequestQueue = moodycamel::BlockingConcurrentQueue<std::shared_ptr<HttpRequestMsg>>;

class Worker
{
public:
	Worker() = default;
	virtual ~Worker(void) = default;

	static void runRequestLoop();
	static bool processRequest(std::shared_ptr<HttpRequest> &request);
	static bool processForward(const std::string forwardTo, std::shared_ptr<HttpRequest> &request);
	static void queueInputRequest(ByteBuffer &data, int tcpHandlerID, void *lwsSessionID = NULL, std::shared_ptr<WSS::ReplyContext> uwsContext = nullptr);

private:
	static RequestQueue m_messages;
};

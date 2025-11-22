#pragma once
#include <atomic>
#include <memory>
#include <mutex>

#include <ace/Map_Manager.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/Svc_Handler.h>
#include <boost/lockfree/spsc_queue.hpp>
#include <concurrentqueue/blockingconcurrentqueue.h>
#ifdef __has_include
#if __has_include(<ace/SSL/SSL_SOCK_Stream.h>)
#include <ace/SSL/SSL_SOCK_Stream.h>
#else
#include <ace/SSL_SOCK_Stream.h>
#endif
#else
#include <ace/SSL/SSL_SOCK_Stream.h>
#endif

#include "protoc/ProtobufHelper.h"

class HttpRequest;
struct HttpRequestMsg;
using RequestQueue = moodycamel::BlockingConcurrentQueue<std::shared_ptr<HttpRequestMsg>>;
using ResponseQueue = moodycamel::ConcurrentQueue<std::unique_ptr<Response>>;

// = TITLE
//     Receive client message from the remote clients.
//
// = DESCRIPTION
//     This class demonstrates how to receive messages from remote
//     clients using the notification mechanisms in the
//     <ACE_Reactor>.  In addition, it also illustrates how to
//     utilize the <ACE_Reactor> timer mechanisms, as well.
//
//     Note: the construction function of ACE_SSL_SOCK_Stream can used to specify a ACE_SSL_Context
//       Define a new ACE_SSL_SOCK_Stream if you want to change the global ACE_SSL_Context
//       ACE_SSL_SOCK_Stream (ACE_SSL_Context *context = ACE_SSL_Context::instance ());
class TcpHandler : public ACE_Svc_Handler<ACE_SSL_SOCK_Stream, ACE_NULL_SYNCH>
{
	struct FileUploadInfo
	{
		std::string m_filePath;
		std::map<std::string, std::string> m_requestHeaders;

		// Constructor for easy creation
		FileUploadInfo(const std::string &uploadFilePath, const std::map<std::string, std::string> &requestHeaders);
	};

public:
	TcpHandler(void);
	virtual ~TcpHandler(void);

	// = Hooks for opening and closing handlers.
	virtual int open(void *) override;

	/// <summary>
	/// Process TCP request
	/// </summary>
	static void handleTcpRestLoop();
	static bool processRequest(std::shared_ptr<HttpRequest> &request);
	static void closeTcpHandler(int tcpHandlerId);
	const int &id();
	static void queueInputRequest(std::shared_ptr<std::vector<std::uint8_t>> &data, int tcpHandlerId, void *wsSessionId = NULL);

protected:
	// = Demultiplexing hooks.
	virtual int handle_input(ACE_HANDLE) override;
	virtual int handle_output(ACE_HANDLE fd) override;

	/// <summary>
	/// Reply response to Golang
	/// </summary>
	/// <param name="Response"></param>
	bool reply(std::unique_ptr<Response> &&resp);
	bool sendData(const char *data, size_t length);
	bool sendBytes(const iovec *iov, size_t count);

	int testStream();
	bool recvUploadFile();

public:
	static bool replyTcp(int tcpHandlerId, std::unique_ptr<Response> &&resp);
	static ACE_SSL_Context *initTcpSSL(ACE_SSL_Context *context, const std::string &certFile, const std::string &keyFile, const std::string &caPath);

private:
	std::string m_clientHostName;
	std::mutex m_socketLock;
	const int m_id;
	ResponseQueue m_respQueue;
	boost::lockfree::spsc_queue<std::shared_ptr<FileUploadInfo>> m_pendingUploadFile;

	static ACE_Map_Manager<int, TcpHandler *, ACE_Recursive_Thread_Mutex> m_handlers;
	static RequestQueue m_messageQueue;
	static std::atomic_int m_idGenerator;
};

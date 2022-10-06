#pragma once
#include <mutex>

#include <ace/Map_Manager.h>
#include <ace/Message_Queue.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/SOCK_Stream.h>
#include <ace/Svc_Handler.h>

#include "HttpRequest.h"
#include "protoc/Response.pb.h"

// = TITLE
//     Receive client message from the remote clients.
//
// = DESCRIPTION
//     This class demonstrates how to receive messages from remote
//     clients using the notification mechanisms in the
//     <ACE_Reactor>.  In addition, it also illustrates how to
//     utilize the <ACE_Reactor> timer mechanisms, as well.
class TcpHandler : public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
public:
	TcpHandler(void);
	virtual ~TcpHandler(void);

	// = Hooks for opening and closing handlers.
	virtual int open(void *);

	/// <summary>
	/// Process TCP request
	/// </summary>
	/// <param name="message"></param>
	static void handleTcpRest();
	static void closeMsgQueue();

protected:
	// = Demultiplexing hooks.
	virtual int handle_input(ACE_HANDLE);

	/// <summary>
	/// Reply response to Golang
	/// </summary>
	/// <param name="appmesh::Response"></param>
	bool replyResponse(const appmesh::Response &resp);

public:
	static bool replyResponse(TcpHandler *tcpHandler, const appmesh::Response &resp);

private:
	std::string m_clientHostName;
	std::recursive_mutex m_socketSendLock;

	static ACE_Map_Manager<void *, bool, ACE_Recursive_Thread_Mutex> m_handlers;
	static ACE_Message_Queue<ACE_MT_SYNCH> messageQueue;
};

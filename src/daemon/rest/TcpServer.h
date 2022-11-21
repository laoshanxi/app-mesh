#pragma once
#include <atomic>
#include <mutex>

#include <ace/Map_Manager.h>
#include <ace/Message_Queue.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/SSL/SSL_SOCK_Stream.h>
#include <ace/Svc_Handler.h>

#include "protoc/Response.pb.h"

// = TITLE
//     Receive client message from the remote clients.
//
// = DESCRIPTION
//     This class demonstrates how to receive messages from remote
//     clients using the notification mechanisms in the
//     <ACE_Reactor>.  In addition, it also illustrates how to
//     utilize the <ACE_Reactor> timer mechanisms, as well.
class TcpHandler : public ACE_Svc_Handler<ACE_SSL_SOCK_Stream, ACE_NULL_SYNCH>
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
	const int &id();

protected:
	// = Demultiplexing hooks.
	virtual int handle_input(ACE_HANDLE);

	/// <summary>
	/// Reply response to Golang
	/// </summary>
	/// <param name="appmesh::Response"></param>
	bool reply(const appmesh::Response &resp);
	bool sendBytes(const char *data, size_t length);

public:
	static bool replyTcp(int tcpHandlerId, const appmesh::Response &resp);
	static void initTcpSSL();

private:
	std::string m_clientHostName;
	std::mutex m_socketLock;
	const int m_id;


	static ACE_Map_Manager<int, TcpHandler *, ACE_Recursive_Thread_Mutex> m_handlers;
	static ACE_Message_Queue<ACE_MT_SYNCH> m_messageQueue;
	static std::atomic_int m_idGenerator;
};

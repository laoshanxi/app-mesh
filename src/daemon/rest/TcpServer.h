#pragma once
#include <mutex>

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

protected:
	// = Demultiplexing hooks.
	virtual int handle_input(ACE_HANDLE);

	/// <summary>
	/// Process TCP request
	/// </summary>
	/// <param name="message"></param>
	void handleTcpRest(const HttpRequest &message);

	/// <summary>
	/// Reply response to Golang
	/// </summary>
	/// <param name="appmesh::Response"></param>
	bool replyResponse(const appmesh::Response &resp);

private:
	std::string m_clientHostName;
	std::recursive_mutex m_socketSendLock;
};

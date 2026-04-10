// src/daemon/rest/SocketServer.h
#pragma once

#include "Data.h"
#include "FileTransferHandler.h"
#include "SocketStream.h"

#include <ace/Map_Manager.h>
#include <ace/Recursive_Thread_Mutex.h>

#include <memory>

class SocketServer;
using ServerStreamMap = ACE_Map_Manager<int, SocketServer *, ACE_Recursive_Thread_Mutex>;

// Server-side socket handler. Managed by ACE_Acceptor.
class SocketServer : public SocketStream
{

public:
    SocketServer(ACE_SSL_Context *ctx = ACE_SSL_Context::instance(), ACE_Reactor *reactor = ACE_Reactor::instance());
    virtual ~SocketServer();

    // = Hooks for opening.
    virtual int open(void *acceptor_or_connector = nullptr) override;

    static bool replyTcp(int clientId, std::unique_ptr<Response> &&resp);
    static void closeClient(int clientID);

    int getId() const;
    static SocketStreamPtr findClient(int clientId);

private:
    const int m_id; // Unique, constant ID for this client session.
    FileTransferHandler m_fileTransfer;
};

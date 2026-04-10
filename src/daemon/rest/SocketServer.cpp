// src/daemon/rest/SocketServer.cpp
#include "SocketServer.h"
#include "Worker.h"

#include <ace/Guard_T.h>

static std::atomic_int idGenerator{0};
static ServerStreamMap streams{};

SocketServer::SocketServer(ACE_SSL_Context *ctx, ACE_Reactor *reactor)
    : SocketStream(ctx, reactor), m_id(++idGenerator)
{
    const static char fname[] = "SocketServer::SocketServer() ";
    LOG_DBG << fname << "New client session | ClientID=" << m_id;
}

SocketServer::~SocketServer()
{
    const static char fname[] = "SocketServer::~SocketServer() ";
    streams.unbind(m_id);
    LOG_DBG << fname << "Client session terminated | ClientID=" << m_id;
}

int SocketServer::open(void *acceptor_or_connector)
{
    const static char fname[] = "SocketServer::open() ";
    LOG_INF << fname << "Initializing connection for client | ClientID=" << m_id;

    // NOTE: callback functions are invoked on the reactor I/O thread.
    this->onData(
        [this](std::vector<std::uint8_t> &&data)
        {
            const static char fname_cb[] = "SocketServer::onData() ";
            LOG_DBG << fname_cb << "Data received from client | ClientID=" << getId() << " | Bytes=" << data.size();

            {
                std::lock_guard<std::mutex> flock(m_fileTransfer.transfer_mutex());
                if (m_fileTransfer.onDataReceived(data, getId()))
                    return;
            }
            WORKER::instance()->queueTcpRequest(std::move(data), getId());
        });

    this->onSent(
        [this](const std::unique_ptr<msgpack::sbuffer> &data)
        {
            std::lock_guard<std::mutex> flock(m_fileTransfer.transfer_mutex());
            m_fileTransfer.onDataSent(*this, getId());
        });

    this->onError(
        [id = m_id](const std::string &msg)
        {
            LOG_WAR << "SocketServer::onError() | ClientID=" << id << " | Error occurred: " << msg;
        });

    this->onClose(
        [id = m_id]()
        {
            streams.unbind(id);
            LOG_DBG << "SocketServer::onClose() | ClientID=" << id;
        });

    // Bind before open to prevent use-after-free (open releases construction ref)
    streams.bind(m_id, this);
    int result = SocketStream::open(acceptor_or_connector);
    if (result == -1)
    {
        streams.unbind(m_id);
        return result;
    }
    LOG_DBG << fname << "Client session registered | ClientID=" << m_id << " | ActiveSessions=" << streams.current_size();
    return result;
}

SocketStreamPtr SocketServer::findClient(int clientId)
{
    const static char fname[] = "SocketServer::findClient() ";

    SocketServer *client = nullptr;
    ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, locker, streams.mutex(), SocketStreamPtr());
    if (streams.find(clientId, client) == 0 && client != nullptr)
    {
        return SocketStreamPtr(client);
    }
    LOG_WAR << fname << "Target client not found | ClientID=" << clientId;
    return SocketStreamPtr();
}

bool SocketServer::replyTcp(int clientId, std::unique_ptr<Response> &&resp)
{
    const static char fname[] = "SocketServer::replyTcp() ";

    auto clientGuard = findClient(clientId);
    if (clientGuard.stream() == nullptr)
    {
        return false;
    }

    auto *client = static_cast<SocketServer *>(clientGuard.stream());

    LOG_DBG << fname << "Sending response | ClientID=" << clientId;
    // Hold m_file_mutex only for check, release before send() to avoid lock inversion
    {
        std::lock_guard<std::mutex> flock(client->m_fileTransfer.transfer_mutex());
        client->m_fileTransfer.prepareTransfer(resp, clientId);
    }
    auto rt = client->send(resp->serialize()); // response (onSent will trigger first chunk)
    return rt;
}

void SocketServer::closeClient(int clientId)
{
    const static char fname[] = "SocketServer::closeClient() ";

    auto client = findClient(clientId);
    if (client.stream() != nullptr)
    {
        LOG_INF << fname << "Closing ClientID=" << clientId;
        client.stream()->shutdown();
    }
}

int SocketServer::getId() const { return m_id; }

// src/daemon/rest/SocketServer.cpp
#include "EventDispatcher.h"
#include "SocketServer.h"
#include "Worker.h"

#include <mutex>
#include <unordered_map>

// Cap on concurrent inbound TCP sessions — bounds memory/fd from a connection flood.
static constexpr size_t MAX_TCP_CONNECTIONS = 10000;

static std::atomic_int idGenerator{0};
// Live client sessions by ClientID. Raw pointers — safe only because onClose unbinds BEFORE
// the reactor drops the final reference, and findClient() pins entries under the map mutex.
static std::mutex streamsMutex;
static std::unordered_map<int, SocketServer *> streams;

SocketServer::SocketServer(ACE_SSL_Context *ctx, ACE_Reactor *reactor)
    : SocketStream(ctx, reactor), m_id(++idGenerator)
{
    const static char fname[] = "SocketServer::SocketServer() ";
    LOG_DBG << fname << "New client session | ClientID=" << m_id;
}

SocketServer::~SocketServer()
{
    const static char fname[] = "SocketServer::~SocketServer() ";
    {
        std::lock_guard<std::mutex> lock(streamsMutex);
        streams.erase(m_id);
    }
    LOG_DBG << fname << "Client session terminated | ClientID=" << m_id;
}

int SocketServer::open(void *acceptor_or_connector)
{
    const static char fname[] = "SocketServer::open() ";
    const int id = m_id;
    LOG_INF << fname << "Initializing connection for client | ClientID=" << m_id;

    // Over the cap: return -1 so ACE_Acceptor calls close() (releases the construction ref).
    {
        std::lock_guard<std::mutex> lock(streamsMutex);
        if (streams.size() >= MAX_TCP_CONNECTIONS)
        {
            LOG_WAR << fname << "Connection limit reached (" << MAX_TCP_CONNECTIONS << "), rejecting | ClientID=" << m_id;
            return -1;
        }
    }

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
        [id](const std::string &msg)
        {
            const static char fname_cb[] = "SocketServer::onError() ";
            LOG_WAR << fname_cb << "| ClientID=" << id << " | Error occurred: " << msg;
        });

    this->onClose(
        [id]()
        {
            const static char fname_cb[] = "SocketServer::onClose() ";
            {
                std::lock_guard<std::mutex> lock(streamsMutex);
                streams.erase(id);
            }
            EventDispatcher::instance()->removeByConnection(ConnectionKey::tcp(id));
            LOG_DBG << fname_cb << "| ClientID=" << id;
        });

    // Bind before open (open releases the construction ref) and AFTER the callback
    // setters: the map mutex is what publishes the callbacks to worker threads (rule 3).
    size_t activeSessions = 0;
    {
        std::lock_guard<std::mutex> lock(streamsMutex);
        streams[m_id] = this;
        activeSessions = streams.size();
    }
    // open() drops the construction ref, after which another reactor thread may delete
    // this; cache id before the call so we never read a freed member afterwards.
    int result = SocketStream::open(acceptor_or_connector);
    if (result == -1)
    {
        std::lock_guard<std::mutex> lock(streamsMutex);
        streams.erase(id);
        return result;
    }
    LOG_DBG << fname << "Client session registered | ClientID=" << id << " | ActiveSessions=" << activeSessions;
    return result;
}

SocketStreamPtr SocketServer::findClient(int clientId)
{
    const static char fname[] = "SocketServer::findClient() ";

    {
        std::lock_guard<std::mutex> lock(streamsMutex);
        auto it = streams.find(clientId);
        if (it != streams.end() && it->second != nullptr)
        {
            // Pin under the map mutex: add_reference happens before onClose can unbind.
            return SocketStreamPtr(it->second);
        }
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
    // Hold transfer_mutex only for prepare, release before send() to avoid lock inversion
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

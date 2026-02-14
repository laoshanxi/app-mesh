// src/daemon/rest/SocketServer.cpp
#include "SocketServer.h"

#include <ace/Guard_T.h>
#include <ace/Map_Manager.h>
#include <ace/Recursive_Thread_Mutex.h>

#include <atomic>
#include <fstream>
#include <memory>
#include <vector>

struct FileUploadInfo
{
    FileUploadInfo(const std::string &uploadFilePath, const HttpHeaderMap &requestHeaders)
        : m_filePath(uploadFilePath), m_requestHeaders(requestHeaders),
          m_file(uploadFilePath, std::ios::binary | std::ios::out | std::ios::trunc)
    {
    }

    std::string m_filePath;
    HttpHeaderMap m_requestHeaders;
    std::ofstream m_file;
};

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
    LOG_DBG << fname << "Client session terminated | ClientID=" << m_id << " | RemainingSessions=" << streams.current_size();
}

int SocketServer::open(void *acceptor_or_connector)
{
    const static char fname[] = "SocketServer::open() ";
    LOG_INF << fname << "Initializing connection for client | ClientID=" << m_id;

    // TODO: those callback functions are IO thread, avoid handle none-IO operation here!
    this->onData(
        [this](std::vector<std::uint8_t> &&data)
        {
            const static char fname_cb[] = "SocketServer::onData() ";
            LOG_DBG << fname_cb << "Data received from client | ClientID=" << getId() << " | Bytes=" << data.size();

            if (m_pendingUploadFile)
            {
                recvNextUploadChunk(m_pendingUploadFile, std::move(data));
            }
            else
            {
                WORKER::instance()->queueTcpRequest(std::move(data), getId());
            }
        });

    this->onSent(
        [this](const std::unique_ptr<msgpack::sbuffer> &data)
        {
            if (m_pendingDownloadFile)
            {
                sendNextDownloadChunk(m_pendingDownloadFile);
            }
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

    // Register in stream map before opening (so replyTcp can find us once reactor is active).
    streams.bind(m_id, this);

    // Proceed with base class opening (registers with reactor).
    int result = SocketStream::open(acceptor_or_connector);
    if (result == -1)
    {
        streams.unbind(m_id);
    }
    else
    {
        LOG_DBG << fname << "Client session registered | ClientID=" << m_id << " | ActiveSessions=" << streams.current_size();
    }
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
    client->checkForUploadFileRequest(resp);   // pre set upload before response
    client->checkForDownloadFileRequest(resp); // pre set download before response
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

void SocketServer::checkForUploadFileRequest(std::unique_ptr<Response> &resp)
{
    const static char fname[] = "SocketServer::checkForUploadFileRequest() ";

    if (resp->http_status == web::http::status_codes::OK &&
        resp->request_uri == REST_PATH_UPLOAD && !resp->body.empty() &&
        resp->headers.count(HTTP_HEADER_KEY_X_Send_File_Socket))
    {
        const auto fileName = Utility::decode64(resp->headers.find(HTTP_HEADER_KEY_X_Send_File_Socket)->second);
        auto uploadInfo = std::make_unique<FileUploadInfo>(fileName, resp->file_upload_request_headers);
        if (!uploadInfo->m_file.is_open())
        {
            auto msg = Utility::text2json("Failed open file").dump();
            resp->http_status = web::http::status_codes::InternalError;
            resp->body = std::vector<std::uint8_t>(msg.begin(), msg.end());
            LOG_ERR << fname << "Upload file creation failed | ClientID=" << getId() << " | FilePath=" << fileName;
            return;
        }
        m_pendingUploadFile = std::move(uploadInfo);
        LOG_INF << fname << "Upload file transfer initiated | ClientID=" << getId() << " | FilePath=" << fileName;
    }
}

void SocketServer::checkForDownloadFileRequest(std::unique_ptr<Response> &resp)
{
    const static char fname[] = "SocketServer::checkForDownloadFileRequest() ";

    if (resp->http_status == web::http::status_codes::OK &&
        resp->request_uri == REST_PATH_DOWNLOAD && !resp->body.empty() &&
        resp->headers.count(HTTP_HEADER_KEY_X_Recv_File_Socket))
    {
        const auto fileName = Utility::decode64(resp->headers.find(HTTP_HEADER_KEY_X_Recv_File_Socket)->second);
        auto fileStream = std::make_unique<std::ifstream>(fileName, std::ios::binary);
        if (!fileStream->is_open())
        {
            auto msg = Utility::text2json("Failed to open file for reading").dump();
            resp->http_status = web::http::status_codes::InternalError;
            resp->body = std::vector<std::uint8_t>(msg.begin(), msg.end());
            LOG_ERR << fname << "Download file access failed | ClientID=" << getId() << " | FilePath=" << fileName;
            return;
        }
        m_pendingDownloadFile = std::move(fileStream);
        LOG_INF << fname << "Download file transfer initiated | ClientID=" << getId() << " | FilePath=" << fileName;
    }
}

void SocketServer::sendNextDownloadChunk(std::unique_ptr<std::ifstream> &download)
{
    const static char fname[] = "SocketServer::sendNextDownloadChunk() ";

    if (!download)
        return;

    std::unique_ptr<msgpack::sbuffer> buffer = std::make_unique<msgpack::sbuffer>(TCP_CHUNK_BLOCK_SIZE);
    const auto readSize = buffer->read_from(*download, TCP_CHUNK_BLOCK_SIZE);

    if (readSize > 0)
    {
        // Send exactly what we read
        this->send(std::move(buffer));
    }
    else
    {
        LOG_INF << fname << "File download transfer completed | ClientID=" << getId();
        download.reset();
        this->send("", 0); // Signal end of transfer
    }
}

void SocketServer::recvNextUploadChunk(std::unique_ptr<FileUploadInfo> &upload, std::vector<std::uint8_t> &&data)
{
    const static char fname[] = "SocketServer::recvNextUploadChunk() ";

    if (!upload)
        return;

    if (data.size() > 0)
    {
        upload->m_file.write(reinterpret_cast<const char *>(data.data()), data.size());
        if (!upload->m_file.good())
        {
            LOG_ERR << fname << "File write operation failed during upload | ClientID=" << getId() << " | FilePath=" << upload->m_filePath;
            upload.reset();
        }
    }
    else
    {
        LOG_INF << fname << "File upload completed successfully | ClientID=" << getId() << " | Destination=" << upload->m_filePath;
        Utility::applyFilePermission(upload->m_filePath, upload->m_requestHeaders);
        upload.reset();
    }
    return;
}

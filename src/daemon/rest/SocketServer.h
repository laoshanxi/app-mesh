#pragma once

#include "SocketStream.h"
#include "Worker.h"

#include <ace/Guard_T.h>
#include <ace/Map_Manager.h>
#include <ace/Recursive_Thread_Mutex.h>

#include <atomic>
#include <fstream>
#include <memory>
#include <vector>

class SocketServer;
using ServerStreamMap = ACE_Map_Manager<int, SocketServer *, ACE_Recursive_Thread_Mutex>;

// Server-side socket handler. Managed by ACE_Acceptor.
class SocketServer : public SocketStream
{
    struct FileUploadInfo
    {
        FileUploadInfo(const std::string &uploadFilePath, const HttpHeaderMap &requestHeaders)
            : m_filePath(uploadFilePath),
              m_requestHeaders(requestHeaders),
              m_file(uploadFilePath, std::ios::binary | std::ios::out | std::ios::trunc)
        {
        }

        std::string m_filePath;
        HttpHeaderMap m_requestHeaders;
        std::ofstream m_file;
    };

public:
    SocketServer(ACE_SSL_Context *ctx = ACE_SSL_Context::instance(), ACE_Reactor *reactor = ACE_Reactor::instance())
        : SocketStream(ctx, reactor), m_id(++idGenerator())
    {
        const static char fname[] = "SocketServer::SocketServer() ";
        streams().bind(m_id, this);
        LOG_DBG << fname << "New client session established | ClientID=" << m_id << " | ActiveSessions=" << streams().current_size();
    }

    virtual ~SocketServer()
    {
        const static char fname[] = "SocketServer::~SocketServer() ";
        streams().unbind(m_id);
        LOG_DBG << fname << "Client session terminated | ClientID=" << m_id << " | RemainingSessions=" << streams().current_size();
    }

    // = Hooks for opening.
    virtual int open(void *acceptor_or_connector = nullptr) override
    {
        const static char fname[] = "SocketServer::open() ";
        LOG_INF << fname << "Initializing connection for client | ClientID=" << m_id;

        this->onData([this](std::vector<std::uint8_t> &&data)
        {
            const static char fname_cb[] = "SocketServer::onData() ";
            LOG_DBG << fname_cb << "Data received from client | ClientID=" << getId() << " | Bytes=" << data.size();

            if (m_pendingUploadFile)
            {
                recvNextUploadChunk(m_pendingUploadFile, std::move(data));
            }
            else
            {
                auto buf = std::make_shared<std::vector<std::uint8_t>>(std::move(data));
                Worker::queueInputRequest(buf, getId());
            }
        });

        this->onSent([this](const std::unique_ptr<msgpack::sbuffer> &data)
        {
            if (m_pendingDownloadFile)
            {
                sendNextDownloadChunk(m_pendingDownloadFile);
            }
        });

        this->onError([id = m_id](const std::string &msg)
        {
            LOG_WAR << "SocketServer::onError() | ClientID=" << id << " | Error occurred: " << msg;
        });

        // Proceed with base class opening (registers with reactor).
        return SocketStream::open(acceptor_or_connector);
    }

    static bool replyTcp(int clientId, std::unique_ptr<Response> &&resp)
    {
        const static char fname[] = "SocketServer::replyTcp() ";

        ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, locker, streams().mutex(), false);

        SocketServer *client = nullptr;
        if (streams().find(clientId, client) == 0 && client)
        {
            LOG_DBG << fname << "Sending response to client | ClientID=" << clientId;
            client->checkForUploadFileRequest(resp);   // pre set upload before response
            auto rt = client->send(resp->serialize()); // response
            client->checkForDownloadFileRequest(resp); // post set download after response
            return rt;
        }

        LOG_WAR << fname << "Target client not found - cannot deliver response | ClientID=" << clientId << " | AvailableSessions=" << streams().current_size();
        return false;
    }

    static void closeClient(int clientID)
    {
        const static char fname[] = "SocketServer::closeClient() ";

        ACE_GUARD(ACE_Recursive_Thread_Mutex, locker, streams().mutex());
        SocketServer *client = NULL;
        if (streams().find(clientID, client) == 0 && client)
        {
            LOG_INF << fname << "Closing ClientID=" << clientID;
            client->shutdown();
        }
        else
        {
            LOG_WAR << fname << "No such ClientID=" << clientID;
        }
    }

    int getId() const { return m_id; }

private:
    void checkForUploadFileRequest(std::unique_ptr<Response> &resp)
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

    void checkForDownloadFileRequest(std::unique_ptr<Response> &resp)
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
                auto msg = Utility::text2json("Failed write file").dump();
                resp->http_status = web::http::status_codes::InternalError;
                resp->body = std::vector<std::uint8_t>(msg.begin(), msg.end());
                LOG_ERR << fname << "Download file access failed | ClientID=" << getId() << " | FilePath=" << fileName;
                return;
            }
            m_pendingDownloadFile = std::move(fileStream);
            sendNextDownloadChunk(m_pendingDownloadFile);
            LOG_INF << fname << "Download file transfer initiated | ClientID=" << getId() << " | FilePath=" << fileName;
        }
    }

    void sendNextDownloadChunk(std::unique_ptr<std::ifstream> &download)
    {
        const static char fname[] = "SocketServer::sendNextDownloadChunk() ";

        if (!download)
            return;

        std::vector<char> buffer(TCP_CHUNK_BLOCK_SIZE);
        download->read(buffer.data(), buffer.size());

        const auto readSize = static_cast<std::size_t>(download->gcount());

        if (readSize > 0)
        {
            // Send exactly what we read
            this->send(buffer.data(), readSize);
        }
        else
        {
            LOG_INF << fname << "File download transfer completed | ClientID=" << getId();
            download.reset();
            this->send("", 0); // Signal end of transfer
        }
    }

    void recvNextUploadChunk(std::unique_ptr<FileUploadInfo> &upload, std::vector<std::uint8_t> &&data)
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

    static std::atomic_int &idGenerator()
    {
        static std::atomic_int instance{0};
        return instance;
    }
    static ServerStreamMap &streams()
    {
        static ServerStreamMap instance{};
        return instance;
    }

private:
    const int m_id; // Unique, constant ID for this client session.

    std::unique_ptr<FileUploadInfo> m_pendingUploadFile;
    std::unique_ptr<std::ifstream> m_pendingDownloadFile;
};

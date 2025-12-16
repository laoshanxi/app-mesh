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
    SocketServer(ACE_SSL_Context *ctx = ACE_SSL_Context::instance(), ACE_Reactor *reactor = ACE_Reactor::instance());
    virtual ~SocketServer();

    // = Hooks for opening.
    virtual int open(void *acceptor_or_connector = nullptr) override;

    static bool replyTcp(int clientId, std::unique_ptr<Response> &&resp);
    static void closeClient(int clientID);

    int getId() const;

private:
    void checkForUploadFileRequest(std::unique_ptr<Response> &resp);
    void checkForDownloadFileRequest(std::unique_ptr<Response> &resp);
    void sendNextDownloadChunk(std::unique_ptr<std::ifstream> &download);
    void recvNextUploadChunk(std::unique_ptr<FileUploadInfo> &upload, std::vector<std::uint8_t> &&data);

    static std::atomic_int &idGenerator();
    static ServerStreamMap &streams();

private:
    const int m_id; // Unique, constant ID for this client session.

    std::unique_ptr<FileUploadInfo> m_pendingUploadFile;
    std::unique_ptr<std::ifstream> m_pendingDownloadFile;
};

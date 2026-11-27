// src/daemon/rest/tcp/FileTransferHandler.h
#pragma once

#include <memory>
#include <mutex>
#include <string>

#include <trantor/net/TcpConnection.h>

#include "../FileUpload.h"

class Response;

// Manages socket file upload/download state for a single TCP connection.
//
// Wire protocol: after the REST handshake response echoes X-Send/Recv-File-Socket,
// file bytes flow as raw framed messages (8-byte header + payload, no msgpack
// envelope) on the same connection. An empty frame marks end of transfer.
//
// All public methods require the caller to hold transfer_mutex().
class FileTransferHandler
{
public:
	FileTransferHandler() = default;
	~FileTransferHandler() = default;

	FileTransferHandler(const FileTransferHandler &) = delete;
	FileTransferHandler &operator=(const FileTransferHandler &) = delete;

	// IO loop. Returns true when the frame payload was consumed as upload data.
	bool onFrameReceived(const std::string &data, int clientId);

	// Reply path (worker thread). Inspects response headers to arm
	// upload/download state before the response frame is sent.
	void prepareTransfer(Response &resp, int clientId);

	// Reply path (worker thread), after the response frame was queued.
	void startDownload(const trantor::TcpConnectionPtr &conn, int clientId);

	std::mutex &transfer_mutex() { return m_transfer_mutex; }

private:
	void recvNextUploadChunk(const std::string &data, int clientId);

	std::mutex m_transfer_mutex;
	std::unique_ptr<FileUploadInfo> m_pendingUpload;
	std::unique_ptr<FdFileStream> m_pendingDownload;
};

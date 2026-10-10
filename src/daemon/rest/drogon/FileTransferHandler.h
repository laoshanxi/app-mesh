// src/daemon/rest/drogon/FileTransferHandler.h
#pragma once

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <trantor/net/TcpConnection.h>

#include "../../../common/HttpHeaderMap.h"

class Response;

struct FileUploadInfo
{
	// Stream bytes into a temp file in the SAME directory as the destination, then
	// atomically rename it into place on success (same directory => same filesystem,
	// so rename is atomic). The destination only ever appears as a complete file.
	FileUploadInfo(const std::string &uploadFilePath, const std::string &tempFilePath, const HttpHeaderMap &requestHeaders)
		: m_filePath(uploadFilePath), m_tempPath(tempFilePath), m_requestHeaders(requestHeaders),
		  m_file(tempFilePath, std::ios::binary | std::ios::out | std::ios::trunc)
	{
	}

	// Unless the upload committed (was renamed into place), drop the partial temp file.
	// Covers write errors, client disconnects, and aborted transfers, so the destination
	// never holds a partial/corrupt file and a retry is never blocked by a leftover.
	~FileUploadInfo()
	{
		if (m_file.is_open())
			m_file.close();
		if (!m_committed && !m_tempPath.empty())
			std::remove(m_tempPath.c_str());
	}

	std::string m_filePath;
	std::string m_tempPath;
	HttpHeaderMap m_requestHeaders;
	std::ofstream m_file;
	std::size_t m_bytesWritten = 0;
	bool m_committed = false;
};

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
	std::unique_ptr<std::ifstream> m_pendingDownload;
};

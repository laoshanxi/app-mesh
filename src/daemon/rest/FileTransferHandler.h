// src/daemon/rest/FileTransferHandler.h
#pragma once

#include "../../common/HttpHeaderMap.h"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class SocketStream;
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
	bool m_committed = false;
};

/// Manages file upload/download state for a single connection.
///
/// All public methods require caller to hold transfer_mutex().
/// NEVER call SocketStream::send() while holding transfer_mutex() from a worker thread.
class FileTransferHandler
{
public:
	FileTransferHandler() = default;
	~FileTransferHandler() = default;

	FileTransferHandler(const FileTransferHandler &) = delete;
	FileTransferHandler &operator=(const FileTransferHandler &) = delete;

	/// Reactor thread only. Caller must hold transfer_mutex().
	bool onDataReceived(std::vector<std::uint8_t> &data, int clientId);

	/// Reactor thread only. Caller must hold transfer_mutex().
	void onDataSent(SocketStream &stream, int clientId);

	/// Called from replyTcp (worker thread, under m_transfer_mutex).
	/// Inspects response headers to set up upload/download state.
	void prepareTransfer(std::unique_ptr<Response> &resp, int clientId);

	std::mutex &transfer_mutex() { return m_transfer_mutex; }

private:
	void sendNextDownloadChunk(SocketStream &stream, int clientId);
	void recvNextUploadChunk(std::vector<std::uint8_t> &data, int clientId);

	std::mutex m_transfer_mutex;
	std::unique_ptr<FileUploadInfo> m_pendingUpload;
	std::unique_ptr<std::ifstream> m_pendingDownload;
};

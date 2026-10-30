// src/daemon/rest/drogon/FileTransferHandler.h
#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#include <trantor/net/TcpConnection.h>

#include "../../../common/HttpHeaderMap.h"

class Response;

struct FileUploadInfo
{
	enum class CommitResult
	{
		Committed,
		AlreadyExists, // a concurrent upload won the destination
		Failed
	};

	// Stream bytes into a temp file in the SAME directory as the destination, then
	// publish it in one step. The destination only ever appears as a complete file.
	// overwrite=true publishes by rename, atomically replacing an existing file.
	FileUploadInfo(const std::string &uploadFilePath, const std::string &tempFilePath,
				   const HttpHeaderMap &requestHeaders, bool overwrite = false)
		: m_filePath(uploadFilePath), m_tempPath(tempFilePath), m_requestHeaders(requestHeaders), m_overwrite(overwrite)
	{
		// Missing parent directories are created for every transport surface.
		std::error_code ec;
		std::filesystem::create_directories(std::filesystem::path(uploadFilePath).parent_path(), ec);
		m_file.open(tempFilePath, std::ios::binary | std::ios::out | std::ios::trunc);
	}

	// Unless the upload committed (was published), drop the partial temp file:
	// the destination never holds a partial file and a retry is never blocked.
	~FileUploadInfo()
	{
		if (m_file.is_open())
			m_file.close();
		if (!m_committed && !m_tempPath.empty())
			std::remove(m_tempPath.c_str());
	}

	// Publish the temp file without replacing an existing destination: rename() would
	// silently overwrite a concurrent winner of the precheck, link() cannot.
	CommitResult commit()
	{
		m_file.flush();
		m_file.close();
		std::error_code ec;
		if (m_overwrite)
		{
			// rename() replaces atomically on POSIX; Windows refuses an existing
			// destination, so clear it there and retry (no concurrent winner to lose).
			std::filesystem::rename(m_tempPath, m_filePath, ec);
			if (ec == std::errc::file_exists || ec == std::errc::permission_denied)
			{
				std::error_code removeEc;
				std::filesystem::remove(m_filePath, removeEc);
				std::filesystem::rename(m_tempPath, m_filePath, ec);
			}
			if (ec)
				return CommitResult::Failed;
			m_committed = true;
			return CommitResult::Committed;
		}
		std::filesystem::create_hard_link(m_tempPath, m_filePath, ec);
		if (ec == std::errc::file_exists)
			return CommitResult::AlreadyExists;
		if (ec)
		{
			// Filesystems without hard links (FAT, some CIFS/FUSE mounts): a checked rename keeps
			// uploads working there, at the cost of a tiny window where a concurrent winner is replaced.
			if (std::filesystem::exists(m_filePath, ec))
				return CommitResult::AlreadyExists;
			std::filesystem::rename(m_tempPath, m_filePath, ec);
			if (ec)
				return CommitResult::Failed;
		}
		else
		{
			std::filesystem::remove(m_tempPath, ec);
		}
		m_committed = true;
		return CommitResult::Committed;
	}

	std::string m_filePath;
	std::string m_tempPath;
	HttpHeaderMap m_requestHeaders;
	std::ofstream m_file;
	std::size_t m_bytesWritten = 0;
	bool m_committed = false;
	bool m_overwrite = false;
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

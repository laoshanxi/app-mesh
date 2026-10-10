// src/daemon/rest/FileTransferHandler.cpp
#include "FileTransferHandler.h"
#include "Data.h"
#include "SocketStream.h"
#include "../Configuration.h"

bool FileTransferHandler::onDataReceived(std::vector<std::uint8_t> &data, int clientId)
{
	if (m_pendingUpload)
	{
		recvNextUploadChunk(data, clientId);
		return true;
	}
	return false;
}

void FileTransferHandler::onDataSent(SocketStream &stream, int clientId)
{
	if (m_pendingDownload)
	{
		sendNextDownloadChunk(stream, clientId);
	}
}

void FileTransferHandler::prepareTransfer(std::unique_ptr<Response> &resp, int clientId)
{
	const static char fname[] = "FileTransferHandler::prepareTransfer() ";

	// One transfer per connection: the wire protocol consumes raw frames after
	// an arm, so a second arm while one is pending would cross-wire the state.
	// Refuse it; the existing transfer continues undisturbed.
	if (m_pendingUpload || m_pendingDownload)
	{
		auto msg = Utility::text2json("A file transfer is already active on this connection").dump();
		resp->http_status = web::http::status_codes::Conflict;
		resp->body = std::vector<std::uint8_t>(msg.begin(), msg.end());
		resp->headers.erase(HTTP_HEADER_KEY_X_Send_File_Socket);
		resp->headers.erase(HTTP_HEADER_KEY_X_Recv_File_Socket);
		LOG_ERR << fname << "Refused a second concurrent transfer | ClientID=" << clientId;
		return;
	}

	// Check for upload request
	if (resp->http_status == web::http::status_codes::OK &&
		resp->request_uri == REST_PATH_UPLOAD && !resp->body.empty() &&
		resp->headers.count(HTTP_HEADER_KEY_X_Send_File_Socket))
	{
		// Defense-in-depth: re-validate using shared validation (RestHandler already validated)
		const auto fileName = Utility::decode64(resp->headers.find(HTTP_HEADER_KEY_X_Send_File_Socket)->second);
		if (!Utility::validateFilePath(fileName, Configuration::instance()->getFileAllowedBaseDir()))
		{
			auto msg = Utility::text2json("Invalid file path").dump();
			resp->http_status = web::http::status_codes::Forbidden;
			resp->body = std::vector<std::uint8_t>(msg.begin(), msg.end());
			LOG_ERR << fname << "Path traversal detected in upload | ClientID=" << clientId << " | FilePath=" << fileName;
			return;
		}

		// Temp file lives in the destination's own directory (append a unique suffix to the
		// full path) so the final rename stays on the same filesystem and is atomic.
		const auto tempName = fileName + "." + Utility::shortID() + ".part";
		auto uploadInfo = std::make_unique<FileUploadInfo>(fileName, tempName, resp->file_upload_request_headers);
		if (!uploadInfo->m_file.is_open())
		{
			auto msg = Utility::text2json("Failed open file").dump();
			resp->http_status = web::http::status_codes::InternalError;
			resp->body = std::vector<std::uint8_t>(msg.begin(), msg.end());
			LOG_ERR << fname << "Upload file creation failed | ClientID=" << clientId << " | FilePath=" << fileName;
			return;
		}
		m_pendingUpload = std::move(uploadInfo);
		LOG_INF << fname << "Upload file transfer initiated | ClientID=" << clientId << " | FilePath=" << fileName;
	}

	// Check for download request
	else if (resp->http_status == web::http::status_codes::OK &&
		resp->request_uri == REST_PATH_DOWNLOAD && !resp->body.empty() &&
		resp->headers.count(HTTP_HEADER_KEY_X_Recv_File_Socket))
	{
		const auto fileName = Utility::decode64(resp->headers.find(HTTP_HEADER_KEY_X_Recv_File_Socket)->second);
		if (!Utility::validateFilePath(fileName, Configuration::instance()->getFileAllowedBaseDir()))
		{
			auto msg = Utility::text2json("Invalid file path").dump();
			resp->http_status = web::http::status_codes::Forbidden;
			resp->body = std::vector<std::uint8_t>(msg.begin(), msg.end());
			LOG_ERR << fname << "Path traversal detected in download | ClientID=" << clientId << " | FilePath=" << fileName;
			return;
		}

		auto fileStream = std::make_unique<std::ifstream>(fileName, std::ios::binary);
		if (!fileStream->is_open())
		{
			auto msg = Utility::text2json("Failed to open file for reading").dump();
			resp->http_status = web::http::status_codes::InternalError;
			resp->body = std::vector<std::uint8_t>(msg.begin(), msg.end());
			LOG_ERR << fname << "Download file access failed | ClientID=" << clientId << " | FilePath=" << fileName;
			return;
		}
		m_pendingDownload = std::move(fileStream);
		LOG_INF << fname << "Download file transfer initiated | ClientID=" << clientId << " | FilePath=" << fileName;
	}
}

void FileTransferHandler::sendNextDownloadChunk(SocketStream &stream, int clientId)
{
	const static char fname[] = "FileTransferHandler::sendNextDownloadChunk() ";

	if (!m_pendingDownload)
		return;

	std::string buffer(TCP_CHUNK_BLOCK_SIZE, '\0');
	m_pendingDownload->read(&buffer[0], static_cast<std::streamsize>(TCP_CHUNK_BLOCK_SIZE));
	const auto readSize = static_cast<size_t>(m_pendingDownload->gcount());

	if (readSize > 0)
	{
		buffer.resize(readSize);
		stream.send(std::move(buffer));
	}
	else
	{
		LOG_INF << fname << "File download transfer completed | ClientID=" << clientId;
		m_pendingDownload.reset();
		stream.send("", 0); // Signal end of transfer
	}
}

void FileTransferHandler::recvNextUploadChunk(std::vector<std::uint8_t> &data, int clientId)
{
	const static char fname[] = "FileTransferHandler::recvNextUploadChunk() ";

	if (!m_pendingUpload)
		return;

	if (!data.empty())
	{
		m_pendingUpload->m_file.write(reinterpret_cast<const char *>(data.data()), data.size());
		if (!m_pendingUpload->m_file.good())
		{
			LOG_ERR << fname << "File write operation failed during upload | ClientID=" << clientId << " | FilePath=" << m_pendingUpload->m_filePath;
			m_pendingUpload.reset(); // FileUploadInfo dtor closes and removes the partial temp file
		}
	}
	else
	{
		// EOF: commit atomically. Temp and destination share a directory (same filesystem),
		// so a successful rename publishes the complete file in one step; on failure the
		// dtor removes the temp and the destination is left untouched.
		const auto dst = m_pendingUpload->m_filePath;
		const auto tmp = m_pendingUpload->m_tempPath;
		m_pendingUpload->m_file.flush();
		m_pendingUpload->m_file.close();
		if (std::rename(tmp.c_str(), dst.c_str()) == 0)
		{
			m_pendingUpload->m_committed = true; // already in place; dtor must not remove it
			Utility::applyFilePermission(dst, m_pendingUpload->m_requestHeaders);
			LOG_INF << fname << "File upload completed successfully | ClientID=" << clientId << " | Destination=" << dst;
		}
		else
		{
			LOG_ERR << fname << "Failed to commit uploaded file via rename | ClientID=" << clientId << " | Destination=" << dst;
		}
		m_pendingUpload.reset();
	}
}

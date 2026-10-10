// src/daemon/rest/drogon/FileTransferHandler.cpp
#include "FileTransferHandler.h"

#include "../../../common/StreamLogger.h"
#include "../../../common/Utility.h"
#include "../../Configuration.h"
#include "../Data.h"
#include "FrameCodec.h"

bool FileTransferHandler::onFrameReceived(const std::string &data, int clientId)
{
	if (m_pendingUpload)
	{
		recvNextUploadChunk(data, clientId);
		return true;
	}
	return false;
}

void FileTransferHandler::startDownload(const trantor::TcpConnectionPtr &conn, int clientId)
{
	const static char fname[] = "FileTransferHandler::startDownload() ";

	if (!m_pendingDownload)
		return;

	// Generator node: refilled as the socket drains (backpressure), framed per
	// chunk itself; an empty body frame ends the transfer.
	std::shared_ptr<std::ifstream> stream = std::move(m_pendingDownload);
	auto terminatorSent = std::make_shared<bool>(false);
	conn->sendStream(
		[stream, terminatorSent](char *buf, std::size_t size) -> std::size_t
		{
			if (buf == nullptr || !stream)
				return 0; // nullptr = the node releasing us
			if (*terminatorSent)
				return 0;
			if (size <= TCP_MESSAGE_HEADER_LENGTH)
			{
				LOG_ERR << "FileTransferHandler::startDownload() stream buffer too small: " << size;
				return 0;
			}

			const auto payloadCapacity = size - TCP_MESSAGE_HEADER_LENGTH;
			stream->read(buf + TCP_MESSAGE_HEADER_LENGTH, static_cast<std::streamsize>(payloadCapacity));
			const auto readSize = static_cast<std::size_t>(stream->gcount());

			// Header plus payload; a zero-length body ends the transfer.
			tcpframe::writeHeader(buf, readSize);
			if (readSize == 0)
				*terminatorSent = true;
			return TCP_MESSAGE_HEADER_LENGTH + readSize;
		});

	LOG_INF << fname << "Download stream armed | ClientID=" << clientId;
}

void FileTransferHandler::prepareTransfer(Response &resp, int clientId)
{
	const static char fname[] = "FileTransferHandler::prepareTransfer() ";

	// One transfer per connection: the wire protocol consumes raw frames after
	// an arm, so a second arm while one is pending would cross-wire the state.
	// Refuse it; the existing transfer continues undisturbed.
	if (m_pendingUpload || m_pendingDownload)
	{
		auto msg = Utility::text2json("A file transfer is already active on this connection").dump();
		resp.http_status = web::http::status_codes::Conflict;
		resp.body = std::vector<std::uint8_t>(msg.begin(), msg.end());
		resp.headers.erase(HTTP_HEADER_KEY_X_Send_File_Socket);
		resp.headers.erase(HTTP_HEADER_KEY_X_Recv_File_Socket);
		LOG_ERR << fname << "Refused a second concurrent transfer | ClientID=" << clientId;
		return;
	}

	// Check for upload request
	if (resp.http_status == web::http::status_codes::OK &&
		resp.request_uri == REST_PATH_UPLOAD && !resp.body.empty() &&
		resp.headers.count(HTTP_HEADER_KEY_X_Send_File_Socket))
	{
		// Defense-in-depth: re-validate using shared validation (RestHandler already validated)
		const auto fileName = Utility::decode64(resp.headers.find(HTTP_HEADER_KEY_X_Send_File_Socket)->second);
		if (!Utility::validateFilePath(fileName, Configuration::instance()->getFileAllowedBaseDir()))
		{
			auto msg = Utility::text2json("Invalid file path").dump();
			resp.http_status = web::http::status_codes::Forbidden;
			resp.body = std::vector<std::uint8_t>(msg.begin(), msg.end());
			LOG_ERR << fname << "Path traversal detected in upload | ClientID=" << clientId << " | FilePath=" << fileName;
			return;
		}

		// Temp file lives in the destination's own directory (append a unique suffix to the
		// full path) so the final rename stays on the same filesystem and is atomic.
		const auto tempName = fileName + "." + Utility::shortID() + ".part";
		auto uploadInfo = std::make_unique<FileUploadInfo>(fileName, tempName, resp.file_upload_request_headers);
		if (!uploadInfo->m_file.is_open())
		{
			auto msg = Utility::text2json("Failed open file").dump();
			resp.http_status = web::http::status_codes::InternalError;
			resp.body = std::vector<std::uint8_t>(msg.begin(), msg.end());
			LOG_ERR << fname << "Upload file creation failed | ClientID=" << clientId << " | FilePath=" << fileName;
			return;
		}
		m_pendingUpload = std::move(uploadInfo);
		LOG_INF << fname << "Upload file transfer initiated | ClientID=" << clientId << " | FilePath=" << fileName;
	}

	// Check for download request
	else if (resp.http_status == web::http::status_codes::OK &&
		resp.request_uri == REST_PATH_DOWNLOAD && !resp.body.empty() &&
		resp.headers.count(HTTP_HEADER_KEY_X_Recv_File_Socket))
	{
		const auto fileName = Utility::decode64(resp.headers.find(HTTP_HEADER_KEY_X_Recv_File_Socket)->second);
		if (!Utility::validateFilePath(fileName, Configuration::instance()->getFileAllowedBaseDir()))
		{
			auto msg = Utility::text2json("Invalid file path").dump();
			resp.http_status = web::http::status_codes::Forbidden;
			resp.body = std::vector<std::uint8_t>(msg.begin(), msg.end());
			LOG_ERR << fname << "Path traversal detected in download | ClientID=" << clientId << " | FilePath=" << fileName;
			return;
		}

		auto fileStream = std::make_unique<std::ifstream>(fileName, std::ios::binary);
		if (!fileStream->is_open())
		{
			auto msg = Utility::text2json("Failed to open file for reading").dump();
			resp.http_status = web::http::status_codes::InternalError;
			resp.body = std::vector<std::uint8_t>(msg.begin(), msg.end());
			LOG_ERR << fname << "Download file access failed | ClientID=" << clientId << " | FilePath=" << fileName;
			return;
		}
		m_pendingDownload = std::move(fileStream);
		LOG_INF << fname << "Download file transfer initiated | ClientID=" << clientId << " | FilePath=" << fileName;
	}
}

void FileTransferHandler::recvNextUploadChunk(const std::string &data, int clientId)
{
	const static char fname[] = "FileTransferHandler::recvNextUploadChunk() ";

	if (!m_pendingUpload)
		return;

	if (!data.empty())
	{
		if (m_pendingUpload->m_bytesWritten + data.size() > MAX_UPLOAD_SIZE)
		{
			LOG_ERR << fname << "Upload exceeds size limit | ClientID=" << clientId << " | FilePath=" << m_pendingUpload->m_filePath;
			m_pendingUpload.reset(); // same as a write error: temp file is dropped, nothing is committed
			return;
		}
		m_pendingUpload->m_bytesWritten += data.size();
		m_pendingUpload->m_file.write(data.data(), static_cast<std::streamsize>(data.size()));
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

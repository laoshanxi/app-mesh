// src/daemon/rest/FileTransferHandler.h
#pragma once

#include "../../common/HttpHeaderMap.h"
#include "../../common/Utility.h"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class SocketStream;
class Response;

// Minimal fd-backed stream with the ifstream/ofstream subset the transfer paths
// use. The descriptor was jailed by Utility::openFileWithinJail at open time and
// pins the inode: reads and writes can never drift onto a path component that an
// attacker swapped to a symlink after validation.
class FdFileStream
{
public:
	FdFileStream() = default;
	explicit FdFileStream(int fd) : m_fd(fd) {}
	~FdFileStream() { close(); }
	FdFileStream(const FdFileStream &) = delete;
	FdFileStream &operator=(const FdFileStream &) = delete;

	void attach(int fd)
	{
		close();
		m_fd = fd;
		m_good = fd >= 0;
	}
	bool is_open() const { return m_fd >= 0; }
	bool good() const { return m_good; }
	int fd() const { return m_fd; }

	// ifstream-style chunk read: loops over partial reads, only a zero gcount
	// (or a negative one on error) ends the transfer.
	std::streamsize read(char *buf, std::size_t size)
	{
		std::streamsize total = 0;
		while (buf != nullptr && m_fd >= 0 && total < static_cast<std::streamsize>(size))
		{
			const auto n = ::read(m_fd, buf + total, size - static_cast<std::size_t>(total));
			if (n > 0)
			{
				total += n;
				continue;
			}
			if (n < 0 && errno == EINTR)
				continue;
			if (n < 0)
				m_good = false;
			break;
		}
		m_gcount = total;
		return total;
	}
	std::streamsize gcount() const { return m_gcount; }

	// ofstream-style write of the full buffer; good() turns false on a short write.
	void write(const char *buf, std::size_t size)
	{
		if (m_fd < 0 || buf == nullptr)
		{
			m_good = false;
			return;
		}
		while (size > 0)
		{
			const auto n = ::write(m_fd, buf, size);
			if (n > 0)
			{
				buf += n;
				size -= static_cast<std::size_t>(n);
				continue;
			}
			if (n < 0 && errno == EINTR)
				continue;
			m_good = false;
			break;
		}
	}
	void flush() {} // unbuffered: every write already reached the kernel
	void close()
	{
		if (m_fd >= 0)
		{
			::close(m_fd);
			m_fd = -1;
		}
	}

private:
	int m_fd = -1;
	bool m_good = false;
	std::streamsize m_gcount = 0;
};

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
	// allowedBaseDir is passed in (instead of reading Configuration) so this
	// transport header stays decoupled from daemon configuration internals.
	FileUploadInfo(const std::string &uploadFilePath, const std::string &tempFilePath,
				   const HttpHeaderMap &requestHeaders, bool overwrite = false,
				   const std::string &allowedBaseDir = "")
		: m_filePath(uploadFilePath), m_tempPath(tempFilePath), m_requestHeaders(requestHeaders), m_overwrite(overwrite)
	{
		// Missing parent directories are created for every transport surface.
		boost::system::error_code ec;
		fs::create_directories(fs::path(uploadFilePath).parent_path(), ec);
		// Open through the jailed helper: the fd is pinned to a verified in-jail
		// inode, so a directory component swapped to a symlink cannot move the temp
		// file (or its later rename) out of the jail. m_dirFd keeps the pinned
		// parent directory so commit() publishes relative to it.
		std::string resolvedTemp;
		const int fd = Utility::openFileWithinJail(tempFilePath, true, allowedBaseDir, resolvedTemp, &m_rejected, &m_dirFd);
		if (fd >= 0)
		{
			if (!resolvedTemp.empty())
				m_tempPath = resolvedTemp; // cleanup and rename target the verified location
			m_file.attach(fd);
		}
	}

	// Unless the upload committed (was published), drop the partial temp file:
	// the destination never holds a partial file and a retry is never blocked.
	~FileUploadInfo()
	{
		if (m_file.is_open())
			m_file.close();
		if (!m_committed && !m_tempPath.empty())
		{
			if (m_dirFd >= 0)
			{
				const std::string tempLeaf = fs::path(m_tempPath).filename().string();
				::unlinkat(m_dirFd, tempLeaf.c_str(), 0);
			}
			else
				std::remove(m_tempPath.c_str());
		}
		if (m_dirFd >= 0)
			::close(m_dirFd);
	}

	// The committed file's descriptor; stays open across commit on POSIX so the
	// post-commit chmod can ride the inode instead of the swappable name.
	int fd() const { return m_file.fd(); }

	// Publish the temp file without replacing an existing destination: rename() would
	// silently overwrite a concurrent winner of the precheck, link() cannot.
	CommitResult commit()
	{
		m_file.flush();
		if (m_dirFd < 0)
			return CommitResult::Failed;
		const std::string tempLeaf = fs::path(m_tempPath).filename().string();
		const std::string destLeaf = fs::path(m_filePath).filename().string();
		if (m_overwrite)
		{
			// renameat against the pinned parent keeps the final landing spot inside
			// the verified directory even if a parent component was swapped meanwhile.
			if (::renameat(m_dirFd, tempLeaf.c_str(), m_dirFd, destLeaf.c_str()) != 0)
				return CommitResult::Failed;
			m_committed = true;
			return CommitResult::Committed;
		}
		if (::linkat(m_dirFd, tempLeaf.c_str(), m_dirFd, destLeaf.c_str(), 0) == 0)
		{
			::unlinkat(m_dirFd, tempLeaf.c_str(), 0);
		}
		else if (errno == EEXIST)
		{
			return CommitResult::AlreadyExists;
		}
		else
		{
			// Filesystems without hard links (FAT, some CIFS/FUSE mounts): a checked rename keeps
			// uploads working there, at the cost of a tiny window where a concurrent winner is replaced.
			struct stat st
			{
			};
			if (::fstatat(m_dirFd, destLeaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0)
				return CommitResult::AlreadyExists;
			if (::renameat(m_dirFd, tempLeaf.c_str(), m_dirFd, destLeaf.c_str()) != 0)
				return CommitResult::Failed;
		}
		m_committed = true;
		return CommitResult::Committed;
	}

	std::string m_filePath;
	std::string m_tempPath;
	HttpHeaderMap m_requestHeaders;
	FdFileStream m_file;
	int m_dirFd = -1; // pinned verified parent directory
	std::size_t m_bytesWritten = 0;
	bool m_committed = false;
	bool m_overwrite = false;
	bool m_rejected = false; // the resolved temp location failed the jail check
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
	std::unique_ptr<FdFileStream> m_pendingDownload;
};

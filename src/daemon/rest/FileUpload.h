// src/daemon/rest/FileUpload.h
#pragma once

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif


#include "../../common/HttpHeaderMap.h"
#include "../../common/Utility.h"
#include "../../common/StreamLogger.h"

class Response;

// Minimal fd-backed stream with the ifstream/ofstream subset the transfer paths
// use. The descriptor was jailed by Utility::openFileWithinJail at open time and
// pins the inode: reads and writes can never drift onto a path component that an
// attacker swapped to a symlink after validation.
class FdFileStream
{
public:
	FdFileStream() = default;
	explicit FdFileStream(int fd) : m_fd(fd) { m_good = fd >= 0; }
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
	// True once a read hit end-of-file; a zero gcount with eof() set is a clean
	// stream end, not a failure.
	bool eof() const { return m_eof; }
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
			if (n == 0)
				m_eof = true;
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
	bool m_eof = false;
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
		// Missing parent directories are created for every transport surface; the
		// jailed component walk keeps creation inside the jail even on a symlink swap.
		const auto parentDir = std::filesystem::path(uploadFilePath).parent_path().string();
		if (!parentDir.empty() && !Utility::createDirectoriesWithinJail(parentDir, allowedBaseDir))
		{
			m_rejected = true;
			return;
		}
#if !defined(_WIN32)
		// An overwrite publishes a fresh inode: record the replaced file's attributes now,
		// before the temp exists (a later stat could see a concurrent writer's file).
		if (m_overwrite)
		{
			const int statDirFd = ::open(parentDir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
			if (statDirFd >= 0)
			{
				struct stat st
				{
				};
				if (::fstatat(statDirFd, std::filesystem::path(uploadFilePath).filename().c_str(), &st,
							  AT_SYMLINK_NOFOLLOW) == 0 &&
					S_ISREG(st.st_mode))
				{
					m_preservedSt = st;
					m_hasPreserved = true;
				}
				::close(statDirFd);
			}
		}
#endif
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
#if defined(_WIN32)
			std::remove(m_tempPath.c_str());
#else
			if (m_dirFd >= 0)
			{
				const std::string tempLeaf = std::filesystem::path(m_tempPath).filename().string();
				::unlinkat(m_dirFd, tempLeaf.c_str(), 0);
			}
			else
				std::remove(m_tempPath.c_str());
#endif
		}
#if !defined(_WIN32)
		if (m_dirFd >= 0)
			::close(m_dirFd);
#endif
	}

	// The committed file's descriptor; stays open across commit on POSIX so the
	// post-commit chmod can ride the inode instead of the swappable name.
	int fd() const { return m_file.fd(); }

	// Publish the temp file without replacing an existing destination: rename() would
	// silently overwrite a concurrent winner of the precheck, link() cannot.
	CommitResult commit()
	{
		m_file.flush();
#if defined(_WIN32)
		m_file.close(); // Windows rename refuses an open file
#endif
#if defined(_WIN32)
		// Windows has no renameat/linkat/fstatat: the temp and destination names stay
		// lexical (same platform limitation as the fd reflection in the jail helper).
		std::error_code ec;
		if (m_overwrite)
		{
			// Windows rename refuses an existing destination, so clear it and retry
			// (no concurrent winner to lose).
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
#else
		if (m_dirFd < 0)
			return CommitResult::Failed;
		const std::string tempLeaf = std::filesystem::path(m_tempPath).filename().string();
		const std::string destLeaf = std::filesystem::path(m_filePath).filename().string();
		// Flush the data before the rename publishes it; a failed fsync only warns (fsync-less filesystems).
		if (m_file.is_open() && ::fsync(m_file.fd()) != 0)
			LOG_WAR << "FileUploadInfo::commit() fsync failed: " << last_error_msg();
		if (m_overwrite)
		{
			// renameat against the pinned parent keeps the final landing spot inside
			// the verified directory even if a parent component was swapped meanwhile.
			if (::renameat(m_dirFd, tempLeaf.c_str(), m_dirFd, destLeaf.c_str()) != 0)
				return CommitResult::Failed;
			m_committed = true;
			restorePreservedAttributes();
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
#endif
	}

	std::string m_filePath;
	std::string m_tempPath;
	HttpHeaderMap m_requestHeaders;
	FdFileStream m_file;
	int m_dirFd = -1; // pinned verified parent directory (POSIX; -1 on Windows)
	std::size_t m_bytesWritten = 0;
	bool m_committed = false;
	bool m_overwrite = false;
	bool m_rejected = false; // the resolved temp location failed the jail check
#if !defined(_WIN32)
	// Attributes of the replaced file, replayed onto the committed inode when the client sent none.
	struct stat m_preservedSt
	{
	};
	bool m_hasPreserved = false;

	// The rename swapped in a fresh inode (0644/daemon owner): replay the replaced
	// file's attributes where the client sent no explicit header (applyFilePermission
	// keeps applying those); a non-root fchown failure warns and continues.
	void restorePreservedAttributes()
	{
		if (!m_hasPreserved || !m_file.is_open())
			return;
		const auto userIt = m_requestHeaders.find(HTTP_HEADER_KEY_file_user);
		const auto groupIt = m_requestHeaders.find(HTTP_HEADER_KEY_file_group);
		if ((userIt == m_requestHeaders.end() || userIt->second.empty()) &&
			(groupIt == m_requestHeaders.end() || groupIt->second.empty()))
		{
			if (::fchown(m_file.fd(), m_preservedSt.st_uid, m_preservedSt.st_gid) != 0)
				LOG_WAR << "FileUploadInfo::restorePreservedAttributes() fchown failed: " << last_error_msg();
		}
		const auto modeIt = m_requestHeaders.find(HTTP_HEADER_KEY_file_mode);
		if (modeIt == m_requestHeaders.end() || modeIt->second.empty())
			::fchmod(m_file.fd(), m_preservedSt.st_mode & 07777);
	}
#endif
};

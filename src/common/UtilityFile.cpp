// src/common/UtilityFile.cpp
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdarg>
#include <cstdlib>
#include <errno.h>
#include <fstream>
#include <future>
#include <iterator>
#include <list>
#include <locale>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#if !defined(_WIN32)
#include <iconv.h>
#include <pthread.h>
#include <sys/file.h>
#endif
#include <thread>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h> // For _NSGetExecutablePath
#elif defined(_WIN32)
#include <windows.h>
#endif

#include <boost/algorithm/string.hpp>
#include <json/json.h>
#include "os/chown.h"
#include "os/linux.h"

#include "Utility.h"

const std::string Utility::getExecutablePath()
{
	const static char fname[] = "Utility::getExecutablePath() ";
#if defined(_WIN32)
	char buf[MAX_PATH] = {0};
	DWORD len = ::GetModuleFileNameA(NULL, buf, MAX_PATH);
	if (len == 0 || len >= MAX_PATH)
	{
		LOG_ERR << fname << "Failed to retrieve executable path: " << ::GetLastError();
		return "";
	}

	return fs::path(buf).string();

#elif defined(__linux__)
	char buf[PATH_MAX] = {0};
	auto count = ::readlink("/proc/self/exe", buf, PATH_MAX);
	if (count < 0 || count >= PATH_MAX)
	{
		LOG_ERR << fname << "Failed to read /proc/self/exe: " << last_error_msg();
		return "";
	}
	buf[count] = '\0';
	return buf;

#elif defined(__APPLE__)
	std::vector<char> buf(PATH_MAX);
	uint32_t size = buf.size();
	if (_NSGetExecutablePath(buf.data(), &size) != 0)
	{
		LOG_ERR << fname << "Failed to retrieve executable path";
		return "";
	}

	// Resolve symlinks to get the real path
	char realPath[PATH_MAX] = {0};
	if (realpath(buf.data(), realPath) == nullptr)
	{
		LOG_ERR << fname << "Failed to resolve real path: " << last_error_msg();
		return "";
	}
	return realPath;

#else
	LOG_ERR << fname << "Platform not supported";
	return "";
#endif
}

const std::string &Utility::getBinDir()
{
	static const std::string selfBinDir = fs::path(getExecutablePath()).parent_path().string();
	return selfBinDir;
}

const std::string &Utility::getHomeDir()
{
	static const std::string homeDir = fs::path(getBinDir()).parent_path().string();
	return homeDir;
}

const std::string Utility::getWorkConfigFilePath(const std::string &configFile)
{
	return (fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_WORK_CONFIG_DIR / configFile).string();
}

const std::string Utility::getConfigFilePath(const std::string &configFile, bool write)
{
	const std::string workingConfigFile = getWorkConfigFilePath(configFile);
	if (write || Utility::isFileExist(workingConfigFile))
	{
		createDirectory((fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_WORK_CONFIG_DIR).string(),
						fs::perms::owner_all);
		return workingConfigFile;
	}
	return (fs::path(Utility::getHomeDir()) / APPMESH_WORK_CONFIG_DIR / configFile).string();
}

bool Utility::isDirExist(const std::string &path)
{
	std::error_code ec;
	return fs::exists(path, ec) && fs::is_directory(path, ec);
}

bool Utility::isFileExist(const std::string &path)
{
	std::error_code ec;
	return fs::exists(path, ec) && !fs::is_directory(path, ec);
}

bool Utility::createDirectory(const std::string &path, fs::perms perms)
{
	const static char fname[] = "Utility::createDirectory() ";

	if (!isDirExist(path))
	{
		const fs::path directoryPath = fs::path(path);
		if (!fs::create_directories(directoryPath))
		{
			LOG_ERR << fname << "Failed to create directory <" << path << "> with error: " << last_error_msg();
			return false;
		}
		// os::chown(getuid(), getgid(), path, false);
		LOG_DBG << fname << "Created directory <" << path << ">";
		fs::permissions(directoryPath, perms);
	}
	return true;
}

bool Utility::createRecursiveDirectory(const std::string &path, fs::perms perms)
{
	const static char fname[] = "Utility::createRecursiveDirectory() ";
	try
	{
		if (fs::exists(path))
			return true;

		// This is where the crash happens
		if (fs::create_directories(path))
		{
			// Set permissions (ignoring errors if we don't own the file)
			std::error_code ec;
			fs::permissions(path, perms, ec);
			return true;
		}
	}
	catch (const std::exception &e)
	{
		// VITAL: Catch the permission error so the app survives
		LOG_WAR << fname << "Cannot create directory <" << path << ">. Container might be read-only. Error: " << e.what();
	}
	return false;
}

bool Utility::removeDir(const std::string &path)
{
	const static char fname[] = "Utility::removeDir() ";

	std::error_code ec;
	if (fs::exists(path, ec))
	{
		auto removed = fs::remove_all(path, ec);
		if (ec)
		{
			LOG_ERR << fname << "Failed to remove <" << path << "> with error: " << ec.message();
			return false;
		}
		else
		{
			LOG_INF << fname << "removed <" << removed << "> files/directories from <" << path << ">";
			return true;
		}
	}
	return true;
}

void Utility::removeFile(const std::string &path)
{
	const static char fname[] = "Utility::removeFile() ";

	if (path.length() && isFileExist(path))
	{
		std::error_code ec;
		fs::remove(path, ec);
		if (ec)
			LOG_WAR << fname << "Failed to remove file <" << path << "> with error: " << ec.message();
		else
			LOG_DBG << fname << "file <" << path << "> removed";
	}
}

std::string Utility::readFile(const std::string &path)
{
	const static char fname[] = "Utility::readFile() ";

	FILE *file = ::fopen(path.c_str(), "r");
	if (nullptr == file)
	{
		if (!startWith(path, "/proc/"))
			LOG_WAR << fname << "Failed to open file <" << path << "> with error: " << last_error_msg();
		return "";
	}

	// Use a buffer to read the file in BUFSIZ
	// chunks and append it to the string we return.
	//
	// NOTE: We aren't able to use fseek() / ftell() here
	// to find the file size because these functions don't
	// work properly for in-memory files like /proc/*/stat.
	char *buffer = new char[BUFSIZ];
	std::string result;

	while (true)
	{
		std::size_t read = ::fread(buffer, 1, BUFSIZ, file);

		if (::ferror(file))
		{
			// NOTE: ferror() will not modify errno if the stream
			// is valid, which is the case here since it is open.
			LOG_ERR << fname << "Failed to read file <" << path << "> with error: " << last_error_msg();
			delete[] buffer;
			::fclose(file);
			return "";
		}

		result.append(buffer, read);

		if (read != BUFSIZ)
		{
			assert(feof(file));
			break;
		}
	};

	::fclose(file);
	delete[] buffer;
	return result;
}

std::string Utility::readFileCpp(const std::string &path)
{
	const static char fname[] = "Utility::readFileCpp() ";

	std::ifstream file(path.c_str(), std::ios::in | std::ios::binary);
	if (!file)
	{
		LOG_WAR << fname << "Cannot open file <" << path << ">";
		return std::string();
	}

	std::string content;

	// Try to reserve size if this is a regular file
	file.seekg(0, std::ios::end);
	const std::streamoff size = file.tellg();
	if (size > 0)
		content.reserve(static_cast<size_t>(size));
	file.seekg(0, std::ios::beg);

	content.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

	return content;
}

// Helper function to validate UTF-8
// Helper function to convert from specific codepage to UTF-8
std::string Utility::readFileCpp(const std::string &path, long *position, long maxSize, bool readLine)
{
	const static char fname[] = "Utility::readFileCpp() ";

	if (!Utility::isFileExist(path))
	{
		LOG_WAR << fname << "File <" << path << "> does not exist";
		return std::string();
	}

	std::ifstream fileStream(path, std::ios::in | std::ios::binary);
	if (!fileStream.is_open())
	{
		LOG_ERR << fname << "Failed to open file <" << path << ">";
		return std::string();
	}

	// Get file size
	fileStream.seekg(0, std::ios::end);
	const std::streampos fileSize = fileStream.tellg();
	if (fileSize == std::streampos(-1))
	{
		LOG_ERR << fname << "Failed to get size of file <" << path << ">";
		return std::string();
	}

	// Validate position
	if (position && *position > fileSize)
	{
		throw std::invalid_argument(
			Utility::stringFormat("Invalid position <%ld>, file size: <%ld>", *position, static_cast<long>(fileSize)));
	}

	fileStream.clear();

	// Set read position
	if (position && *position >= 0)
		fileStream.seekg(*position);
	else
		fileStream.seekg(0, std::ios::beg);
	if (!fileStream.good())
	{
		LOG_ERR << fname << "Failed to seek to read position in file <" << path << ">";
		return std::string();
	}

	std::string result;

	if (maxSize >= 0)
	{
		// Forward reading
		size_t readSize = (maxSize == 0) ? static_cast<size_t>(fileSize)
										 : std::min(static_cast<size_t>(maxSize), static_cast<size_t>(fileSize));

		if (readLine)
		{
			std::string line;
			if (std::getline(fileStream, line))
			{
				result = line.substr(0, readSize);
			}
		}
		else
		{
			result.resize(readSize);
			fileStream.read(&result[0], readSize);
			result.resize(fileStream.gcount()); // Adjust to actual bytes read
		}
	}
	else
	{
		// Reverse reading
		size_t readSize = std::min(static_cast<size_t>(-maxSize), static_cast<size_t>(fileSize));

		// Adjust position for reverse reading
		if (position && *position == 0)
		{
			if (!fileStream.seekg(0, std::ios::end))
			{
				LOG_ERR << fname << "Failed to seek to end of file <" << path << "> for reverse reading";
				return std::string();
			}
		}

		const std::streampos endPos = fileStream.tellg();
		if (endPos == std::streampos(-1))
		{
			LOG_ERR << fname << "Failed to get current position in file <" << path << ">";
			return std::string();
		}

		if (readLine)
		{
			// Reverse line reading
			result.reserve(readSize);
			size_t bytesRead = 0;
			while (fileStream.tellg() > 0 && bytesRead < readSize)
			{
				if (!fileStream.seekg(-1, std::ios::cur))
				{
					break;
				}

				int c = fileStream.get();
				if (c == EOF || c == '\n')
				{
					break;
				}

				result.push_back(static_cast<char>(c));
				if (!fileStream.seekg(-1, std::ios::cur))
				{
					break;
				}

				++bytesRead;
			}
			std::reverse(result.begin(), result.end());
		}
		else
		{
			// Reverse block reading
			if (endPos > static_cast<std::streamoff>(readSize))
			{
				if (!fileStream.seekg(-static_cast<std::streamoff>(readSize), std::ios::end))
				{
					LOG_ERR << fname << "Failed to seek in file <" << path << "> for reverse reading";
					return std::string();
				}
			}
			else
			{
				if (!fileStream.seekg(0, std::ios::beg))
				{
					LOG_ERR << fname << "Failed to seek to beginning of file <" << path << ">";
					return std::string();
				}
				readSize = static_cast<size_t>(endPos);
			}

			result.resize(readSize);
			if (!fileStream.read(&result[0], readSize))
			{
				LOG_ERR << fname << "Failed to read content of file <" << path << ">";
				return std::string();
			}
			result.resize(fileStream.gcount());
		}
	}

	// Update position
	if (position)
	{
		const std::streampos currentPos = fileStream.tellg();
		if (currentPos == std::streampos(-1))
		{
			// If we can't get the position, estimate it
			*position = *position + static_cast<long>(result.size());
		}
		else
		{
			*position = static_cast<long>(currentPos);
		}
	}

	return fileBytesToUtf8(result);
}

std::map<std::string, std::string> Utility::fileAttributeHeaders(const std::string &file)
{
	std::map<std::string, std::string> headers;
	if (const auto stat = os::fileStat(file))
	{
		const auto &[fileMode, fileUser, fileGroup] = *stat;
		headers[HTTP_HEADER_KEY_file_mode] = std::to_string(fileMode);
		headers[HTTP_HEADER_KEY_file_user] = fileUser;
		headers[HTTP_HEADER_KEY_file_group] = fileGroup;
	}
	return headers;
}

void Utility::applyFilePermission(const std::string &file, HttpHeaderMap headers, int fd)
{
	const static char fname[] = "Utility::applyFilePermission() ";

	if (fd < 0 && !Utility::isFileExist(file))
	{
		return;
	}

#if !defined(_WIN32)
	auto userIt = headers.find(HTTP_HEADER_KEY_file_user);
	auto groupIt = headers.find(HTTP_HEADER_KEY_file_group);
	if (userIt != headers.end() && groupIt != headers.end() && !userIt->second.empty() && !groupIt->second.empty())
	{
		if (Utility::runningInContainer())
		{
			// A container upload is created by the fixed daemon identity. Do not
			// transfer it to a host/client identity that may be absent or unreadable.
			LOG_DBG << fname << "Ignoring remote owner <" << userIt->second << ":" << groupIt->second
					<< "> for container file <" << file << ">";
		}
		else
		{
			try
			{
				// Use the verified fd when there is one: a path swapped after the jail check cannot redirect the change.
				if (fd >= 0)
					os::fchown(fd, userIt->second, groupIt->second);
				else
					os::chown(file, userIt->second, groupIt->second);
			}
			catch (...)
			{
				LOG_WAR << fname << "Invalid user/group ID value: " << userIt->second << "/" << groupIt->second;
			}
		}
	}
#endif

	if (auto modeIt = headers.find(HTTP_HEADER_KEY_file_mode); modeIt != headers.end() && !modeIt->second.empty())
	{
		try
		{
			int mode = std::stoi(modeIt->second);
			if (mode < 0 || mode > 0777)
				throw std::out_of_range("file mode must be between 0 and 0777");
			if (Utility::runningInContainer())
				mode |= 0400; // Keep uploads readable by the fixed daemon owner.
#if !defined(_WIN32)
			if (fd >= 0)
				os::fileChmodFd(fd, static_cast<uint16_t>(mode));
			else
#endif
				os::fileChmod(file, static_cast<uint16_t>(mode));
		}
		catch (...)
		{
			LOG_WAR << fname << "Invalid file mode value: " << modeIt->second;
		}
	}
}

namespace
{
	// Case folds on macOS/Windows so a differently-cased alias of the install tree or /proc cannot slip past; byte-exact elsewhere.
	bool pathPrefixMatch(const std::string &path, const std::string &prefixWithSlash, const std::string &prefixExact)
	{
		const auto equalWithin = [&path](size_t length, const std::string &prefix)
		{
#if defined(__APPLE__) || defined(_WIN32)
			for (size_t i = 0; i < length; i++)
			{
				if (std::tolower(static_cast<unsigned char>(path[i])) != std::tolower(static_cast<unsigned char>(prefix[i])))
					return false;
			}
			return true;
#else
			return path.compare(0, length, prefix) == 0;
#endif
		};
		if (path.size() == prefixExact.size())
			return equalWithin(path.size(), prefixExact);
		// The trailing separator keeps "/opt" from matching "/opt2/...".
		return path.size() > prefixWithSlash.size() && equalWithin(prefixWithSlash.size(), prefixWithSlash);
	}

	// Reflect an open directory fd to its real path (F_GETPATH / /proc/self/fd); empty when the platform cannot.
	std::string reflectDirFdPath(int dirFd)
	{
#if defined(__APPLE__)
		char realPath[4096] // F_GETPATH wants a MAXPATHLEN-sized buffer; larger is fine
		{
		};
		if (::fcntl(dirFd, F_GETPATH, realPath) == 0)
			return realPath;
#elif !defined(_WIN32)
		char fdLink[32];
		char target[PATH_MAX];
		::snprintf(fdLink, sizeof(fdLink), "/proc/self/fd/%d", dirFd);
		const auto len = ::readlink(fdLink, target, sizeof(target) - 1);
		if (len > 0)
		{
			target[len] = '\0';
			return target;
		}
#endif
		return {};
	}
} // namespace

bool Utility::validateFilePath(const std::string &filePath, const std::string &allowedBaseDir)
{
	// Reject null bytes
	if (filePath.find('\0') != std::string::npos)
		return false;
	// Reject ".." path components (component-level check avoids false positives on names like "..hidden")
	for (const auto &component : fs::path(filePath))
	{
		if (component == "..")
			return false;
	}
	// Reject pseudo filesystems (procfs/sysfs/devfs): their files stat as regular size-0 files, so a
	// download would answer 200 empty; pathPrefixMatch folds case, covering differently-cased aliases.
	const auto isPseudoFsPath = [](const std::string &path) {
		for (const char *pseudo : {"/proc", "/sys", "/dev"})
		{
			if (pathPrefixMatch(path, std::string(pseudo) + "/", pseudo))
				return true;
		}
		return false;
	};
	if (isPseudoFsPath(filePath))
		return false;
	// Enforce base-directory jail when configured
	if (!allowedBaseDir.empty() && !isPathTraversalSafe(allowedBaseDir, filePath))
		return false;
	// The daemon's own tree (binaries, TLS keys, bootstrap credentials, registry) is never
	// transferable, whatever the jail allows; the exchange roots follow the effective jail
	// (created at startup, so validation stays side-effect free).
	const auto jailDir = allowedBaseDir.empty() ? (fs::path(getHomeDir()) / APPMESH_WORK_DIR).string() : allowedBaseDir;
	const auto inExchange = isPathTraversalSafe((fs::path(jailDir) / APPMESH_WORK_SHARE_DIR).string(), filePath) ||
							isPathTraversalSafe((fs::path(jailDir) / APPMESH_WORKSPACES_DIR).string(), filePath);
	if (isPathTraversalSafe(getHomeDir(), filePath) && !inExchange)
		return false;
	// The pseudo-fs check above is lexical; follow symlinks so a link planted
	// in an allowed tree cannot reach /proc behind a permissive jail.
	std::error_code resolveEc;
	const auto resolvedPath = fs::canonical(filePath, resolveEc);
	if (!resolveEc && isPseudoFsPath(resolvedPath.string()))
		return false;
	return true;
}

int Utility::openFileWithinJail(const std::string &filePath, bool forWrite, const std::string &allowedBaseDir,
								std::string &resolvedOut, bool *rejectedOut, int *dirFdOut)
{
	const static char fname[] = "Utility::openFileWithinJail() ";
	resolvedOut.clear();
	if (rejectedOut)
		*rejectedOut = false;
	if (dirFdOut)
		*dirFdOut = -1;
	// Cheap lexical precheck keeps the caller's validate-then-403 log semantics.
	if (!validateFilePath(filePath, allowedBaseDir))
	{
		if (rejectedOut)
			*rejectedOut = true;
		return -1;
	}

#if defined(_WIN32)
	// Windows offers no fd-to-path reflection, so the lexical check above is the
	// whole gate there (platform limitation; behavior matches the pre-fix code).
	const int fd = ::_open(filePath.c_str(),
						   forWrite ? (_O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY) : (_O_RDONLY | _O_BINARY),
						   _S_IREAD | _S_IWRITE);
	if (fd < 0)
	{
		LOG_ERR << fname << "Failed to open <" << filePath << ">: " << last_error_msg();
		return -1;
	}
	resolvedOut = filePath;
	struct _stat st
	{
	};
	if (forWrite || (_fstat(fd, &st) == 0 && (st.st_mode & _S_IFMT) == _S_IFREG))
		return fd;
	::_close(fd);
	return -1;
#else
	int fd = -1;
	int dirFd = -1;
	std::string exclusiveName; // the O_EXCL name inside the pinned dirFd (cleanup on reject)
	if (forWrite)
	{
		// Create the unique temp name inside its parent directory through a pinned
		// dirfd: the exclusive name then lives in the directory actually walked, so a
		// rejected jail check can drop exactly the file this call just created.
		const fs::path temp(filePath);
		exclusiveName = temp.filename().string();
		dirFd = ::open(temp.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (dirFd < 0 || exclusiveName.empty() || exclusiveName == "." || exclusiveName == "..")
		{
			if (dirFd >= 0)
				::close(dirFd);
			return -1;
		}
		fd = ::openat(dirFd, exclusiveName.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
		if (fd < 0)
		{
			::close(dirFd);
			return -1;
		}
	}
	else
	{
		fd = ::open(filePath.c_str(), O_RDONLY | O_CLOEXEC);
		if (fd < 0)
		{
			LOG_ERR << fname << "Failed to open <" << filePath << "> for reading: " << last_error_msg();
			return -1;
		}
		struct stat st
		{
		};
		if (::fstat(fd, &st) != 0)
		{
			LOG_ERR << fname << "Failed to stat <" << filePath << ">: " << last_error_msg();
			::close(fd);
			return -1;
		}
		if (!S_ISREG(st.st_mode))
		{
			// Directories (and anything non-regular) are not transferable payloads.
			LOG_ERR << fname << "Not a regular file, refusing the transfer of <" << filePath << ">";
			::close(fd);
			return -1;
		}
		// A hardlink passes every path gate but still reads the excluded inode; serve single-link files only.
		if (st.st_nlink != 1)
		{
			if (rejectedOut)
				*rejectedOut = true;
			::close(fd);
			return -1;
		}
	}

	// Resolve what the descriptor ACTUALLY landed on and re-run the full jail
	// rules there: the fd pins the inode, so a component swapped to a symlink
	// between the check above and the open cannot hide behind the original name.
	std::string resolved;
#if defined(__APPLE__)
	char realPath[4096] // F_GETPATH wants a MAXPATHLEN-sized buffer; larger is fine
	{
	};
	if (::fcntl(fd, F_GETPATH, realPath) == 0)
		resolved = realPath;
#else
	char fdLink[32];
	char target[PATH_MAX];
	::snprintf(fdLink, sizeof(fdLink), "/proc/self/fd/%d", fd);
	const auto len = ::readlink(fdLink, target, sizeof(target) - 1);
	if (len > 0)
	{
		target[len] = '\0';
		resolved = target;
	}
#endif
	if (resolved.empty() || !validateFilePath(resolved, allowedBaseDir))
	{
		LOG_ERR << fname << "Resolved location <" << resolved << "> of <" << filePath
				<< "> is outside the allowed jail; rejecting the transfer";
		if (rejectedOut)
			*rejectedOut = true;
		// ENOENT: a racing writer already dropped the rejected temp.
		if (forWrite && !exclusiveName.empty() && ::unlinkat(dirFd, exclusiveName.c_str(), 0) != 0 && errno != ENOENT)
			LOG_ERR << fname << "Failed to unlink rejected temp file <" << exclusiveName << ">: " << last_error_msg();
		::close(fd);
		if (dirFd >= 0)
			::close(dirFd);
		return -1;
	}
	resolvedOut = resolved;
	if (dirFd >= 0)
	{
		// Hand the pinned parent to an upload commit; otherwise it has no further use.
		if (dirFdOut != nullptr)
			*dirFdOut = dirFd;
		else
			::close(dirFd);
	}
	return fd;
#endif
}

Utility::JailUnlinkStatus Utility::unlinkFileWithinJail(const std::string &filePath, const std::string &allowedBaseDir,
														std::string &resolvedOut)
{
	const static char fname[] = "Utility::unlinkFileWithinJail() ";
	resolvedOut.clear();
	if (!validateFilePath(filePath, allowedBaseDir))
		return JailUnlinkStatus::Rejected;

#if defined(_WIN32)
	// Windows offers no fd-to-path reflection, so the lexical check above is the
	// whole gate there (same platform limitation openFileWithinJail documents).
	struct _stat st
	{
	};
	if (::_stat(filePath.c_str(), &st) != 0)
		return JailUnlinkStatus::NotFound;
	if ((st.st_mode & _S_IFMT) != _S_IFREG)
		return JailUnlinkStatus::NotFound;
	if (::_unlink(filePath.c_str()) != 0)
	{
		LOG_ERR << fname << "Failed to unlink <" << filePath << ">: " << last_error_msg();
		return JailUnlinkStatus::Failed;
	}
	resolvedOut = filePath;
	return JailUnlinkStatus::Removed;
#else
	const fs::path target(filePath);
	const auto leaf = target.filename().string();
	if (!target.is_absolute() || leaf.empty() || leaf == "." || leaf == "..")
		return JailUnlinkStatus::Failed;

	// Walk every parent component relative to the pinned dirfd (the walk may traverse legitimate symlinks), but the
	// final pinned directory is reflected and re-validated below, so a middle swap outside the jail is rejected first.
	int dirFd = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	for (const auto &component : target.parent_path())
	{
		if (component == "/" || component.empty())
			continue;
		const auto next = ::openat(dirFd, component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		::close(dirFd);
		if (next < 0)
		{
			LOG_ERR << fname << "Failed to pin parent directory of <" << filePath << ">: " << last_error_msg();
			return JailUnlinkStatus::Failed;
		}
		dirFd = next;
	}
	const auto closeGuard = [&dirFd]()
	{ ::close(dirFd); };

	// The pinned directory decides: re-run the jail rules on its reflected path, then require a regular non-symlink leaf.
	const auto resolvedDir = reflectDirFdPath(dirFd);
	if (resolvedDir.empty())
	{
		closeGuard();
		return JailUnlinkStatus::Failed;
	}
	const auto resolvedLeafPath = (fs::path(resolvedDir) / leaf).string();
	if (!validateFilePath(resolvedLeafPath, allowedBaseDir))
	{
		LOG_ERR << fname << "Resolved location <" << resolvedLeafPath << "> of <" << filePath
				<< "> is outside the allowed jail; rejecting the delete";
		closeGuard();
		return JailUnlinkStatus::Rejected;
	}
	struct stat st
	{
	};
	if (::fstatat(dirFd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0)
	{
		closeGuard();
		return JailUnlinkStatus::NotFound;
	}
	if (!S_ISREG(st.st_mode))
	{
		// Directories and symlinks are not deletable payloads (the routes always refuse them; the pin only removes the race).
		closeGuard();
		return JailUnlinkStatus::NotFound;
	}
	if (::unlinkat(dirFd, leaf.c_str(), 0) != 0)
	{
		LOG_ERR << fname << "Failed to unlink <" << resolvedLeafPath << ">: " << last_error_msg();
		closeGuard();
		return JailUnlinkStatus::Failed;
	}
	closeGuard();
	resolvedOut = resolvedLeafPath;
	return JailUnlinkStatus::Removed;
#endif
}

bool Utility::createDirectoriesWithinJail(const std::string &dirPath, const std::string &allowedBaseDir)
{
	const static char fname[] = "Utility::createDirectoriesWithinJail() ";
	// The not-yet-existing tail is covered by the ancestor-walk inside the check.
	if (!validateFilePath(dirPath, allowedBaseDir))
		return false;

#if defined(_WIN32)
	// No fd machinery to pin with on Windows; the lexical check above is the gate.
	std::error_code ec;
	return fs::create_directories(dirPath, ec) || (!ec && isDirExist(dirPath));
#else
	const fs::path target(dirPath);
	if (!target.is_absolute())
		return false;
	int dirFd = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	for (const auto &component : target)
	{
		if (component == "/" || component.empty())
			continue;
		auto next = ::openat(dirFd, component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (next < 0 && errno == ENOENT)
		{
			// Create the missing component only inside a directory that just passed the jail check on its pinned fd,
			// so a middle directory swapped outside the jail is rejected before any mkdir.
			const auto pinned = reflectDirFdPath(dirFd);
			if (pinned.empty() || !validateFilePath(pinned, allowedBaseDir))
			{
				LOG_ERR << fname << "Resolved parent <" << pinned << "> of <" << dirPath
						<< "> is outside the allowed jail; refusing to create directories";
				::close(dirFd);
				return false;
			}
			if (::mkdirat(dirFd, component.c_str(), 0755) != 0)
			{
				LOG_ERR << fname << "Failed to create <" << component << "> inside the jail: " << last_error_msg();
				::close(dirFd);
				return false;
			}
			next = ::openat(dirFd, component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		}
		::close(dirFd);
		if (next < 0)
		{
			LOG_ERR << fname << "Failed to pin <" << component << "> of <" << dirPath << ">: " << last_error_msg();
			return false;
		}
		dirFd = next;
	}
	const auto resolvedDir = reflectDirFdPath(dirFd);
	::close(dirFd);
	if (resolvedDir.empty())
		return false;
	// The created tree must sit where the jail said it would.
	return validateFilePath(resolvedDir, allowedBaseDir);
#endif
}

bool Utility::isPathTraversalSafe(const std::string &baseDir, const std::string &filePath)
{
	std::error_code ec;

	// Resolve the allowed base directory — must exist and be canonical.
	fs::path canonicalBase = fs::canonical(fs::path(baseDir), ec);
	if (ec)
	{
		return false;
	}

	fs::path file(filePath);

	// Try to canonicalize the full path directly (works when file already exists).
	fs::path resolvedPath = fs::canonical(file, ec);
	if (ec)
	{
		// File does not exist yet (e.g. upload target). Walk up to find the nearest
		// existing ancestor, canonicalize it, then re-append the remaining components.
		// This allows uploads to new subdirectories within the allowed base.
		fs::path remaining;
		fs::path ancestor = std::move(file);
		while (!ancestor.empty())
		{
			fs::path parent = ancestor.parent_path();
			if (parent == ancestor)
				break; // reached root
			remaining = ancestor.filename() / remaining;
			ancestor = std::move(parent);
			fs::path canonicalAncestor = fs::canonical(ancestor, ec);
			if (!ec)
			{
				resolvedPath = canonicalAncestor / remaining;
				break;
			}
		}
		if (ec)
		{
			// No existing ancestor found — reject.
			return false;
		}
	}

	// Ensure resolvedPath starts with canonicalBase (prefix check).
	// Append trailing separator to base so "/opt" does not match "/opt2/…".
	std::string baseStr = canonicalBase.string();
	if (baseStr.back() != fs::path::preferred_separator)
	{
		baseStr += fs::path::preferred_separator;
	}
	std::string resolvedStr = resolvedPath.string();

	// Allow exact match to base dir itself or any path inside it; the compare folds case on macOS/Windows
	// (pathPrefixMatch) so a differently-cased alias cannot dodge the exclusion checks built on this.
	if (!pathPrefixMatch(resolvedStr, baseStr, canonicalBase.string()))
	{
		return false;
	}

	return true;
}

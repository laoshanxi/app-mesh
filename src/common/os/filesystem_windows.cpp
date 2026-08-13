// src/common/os/filesystem_windows.cpp
// Windows-specific filesystem utilities.

#include "filesystem.h"

#include <algorithm>
#include <cstring>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <direct.h>
#include <io.h>
#include <shlwapi.h>
#include <windows.h>

#pragma comment(lib, "shlwapi.lib")

#include "../Utility.h"
#include "handler.hpp"

namespace os
{

	std::vector<std::string> ls(const std::string &directory)
	{
		const static char fname[] = "os::ls() ";
		std::vector<std::string> result;

		std::string searchPath = directory + "\\*";
		WIN32_FIND_DATAA findData;
		// FindFirstFile returns a search handle that must be closed with FindClose, not CloseHandle
		HANDLE raw = FindFirstFileA(searchPath.c_str(), &findData);
		if (raw == INVALID_HANDLE_VALUE)
		{
			LOG_WAR << fname << "Failed to open directory: " << directory << " with error: " << last_error_msg();
			return result;
		}
		std::unique_ptr<void, decltype(&FindClose)> hFind(raw, FindClose);

		do
		{
			std::string name = findData.cFileName;
			if (name != "." && name != "..")
			{
				result.push_back(std::move(name));
			}
		} while (FindNextFileA(static_cast<HANDLE>(hFind.get()), &findData));

		DWORD error = GetLastError();
		if (error != ERROR_NO_MORE_FILES)
		{
			LOG_WAR << fname << "Failed to read directory: " << directory << " with error: " << last_error_msg();
		}

		return result;
	}

	std::shared_ptr<FilesystemUsage> df(const std::string &path)
	{
		const static char fname[] = "os::df() ";
		auto df = std::make_shared<FilesystemUsage>();

		ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;

		if (GetDiskFreeSpaceExA(path.c_str(), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes))
		{
			const auto totalBytes = totalNumberOfBytes.QuadPart;
			const auto freeBytes = std::min(totalNumberOfFreeBytes.QuadPart, totalBytes);
			const auto availableBytes = std::min(freeBytesAvailable.QuadPart, freeBytes);
			df->totalSize = totalBytes;
			df->usedSize = totalBytes - freeBytes;
			df->availableSize = availableBytes;
			if (totalBytes > 0)
			{
				df->usagePercentage = static_cast<double>(df->usedSize) / df->totalSize;
			}
		}
		else
		{
			LOG_ERR << fname << "Failed to get disk space for path: " << path
					<< " Error: " << GetLastError();
			return nullptr;
		}

		return df;
	}

	std::map<std::string, std::string> getMountPoints()
	{
		const static char fname[] = "os::getMountPoints() ";
		std::map<std::string, std::string> mountPointsMap;
		char volume[MAX_PATH + 1] = {0};
		HANDLE search = FindFirstVolumeA(volume, MAX_PATH + 1);
		if (search == INVALID_HANDLE_VALUE)
		{
			LOG_WAR << fname << "FindFirstVolume failed: " << GetLastError();
			return mountPointsMap;
		}
		do
		{
			if (GetDriveTypeA(volume) != DRIVE_FIXED)
				continue;

			DWORD needed = 0;
			GetVolumePathNamesForVolumeNameA(volume, nullptr, 0, &needed);
			std::vector<char> paths(needed > 1 ? needed : 1, '\0');
			if (needed > 1 && GetVolumePathNamesForVolumeNameA(volume, paths.data(), needed, &needed))
			{
				std::string preferredMountPath;
				for (const char *path = paths.data(); *path; path += std::strlen(path) + 1)
				{
					if (preferredMountPath.empty() || std::strlen(path) < preferredMountPath.size())
						preferredMountPath = path;
				}
				if (!preferredMountPath.empty())
					mountPointsMap[preferredMountPath] = volume;
			}
		} while (FindNextVolumeA(search, volume, MAX_PATH + 1));
		FindVolumeClose(search);

		return mountPointsMap;
	}

	std::tuple<int, std::string, std::string> fileStat(const std::string &path)
	{
		const static char fname[] = "fileStat() ";

		struct _stat fileStat {};
		if (::_stat(path.c_str(), &fileStat) == 0)
		{
			int permissionBits = fileStat.st_mode & 0777;
			return std::make_tuple(permissionBits, "", "");
		}
		else
		{
			LOG_WAR << fname << "Failed stat <" << path << "> with error: " << last_error_msg();
			return std::make_tuple(-1, "", "");
		}
	}

	bool fileChmod(const std::string &path, uint16_t mode)
	{
		const static char fname[] = "fileChmod() ";

		constexpr uint16_t MAX_FILE_MODE = 0777;
		if (mode > MAX_FILE_MODE)
		{
			LOG_WAR << fname << "Invalid mode value <" << mode << "> for chmod <" << path << ">";
			return false;
		}

		// Windows does not support POSIX file permissions
		return false;
	}

	std::string createTmpFile(const std::string &fileName, const std::string &content, uint16_t mode)
	{
		const char *fname = "os::createTmpFile() ";
		(void)mode;

		try
		{
			fs::path finalPath;

			if (fileName.empty())
			{
				// Use GetTempFileNameA for reliable temp file creation
				char tmpDir[MAX_PATH];
				GetTempPathA(MAX_PATH, tmpDir);
				char tmpFile[MAX_PATH];
				if (GetTempFileNameA(tmpDir, "amsh", 0, tmpFile) == 0)
				{
					LOG_WAR << fname << "GetTempFileNameA failed in directory <" << tmpDir << "> with error " << ::GetLastError();
					return {};
				}
				finalPath = tmpFile;
			}
			else
			{
				// Use GetTempFileNameA with the parent directory to generate a unique file,
				// matching POSIX mkstemp behavior that appends a random suffix.
				auto parentDir = fs::absolute(fileName).parent_path();
				std::string prefix = fs::path(fileName).filename().string();
				if (prefix.size() > 3) prefix = prefix.substr(0, 3);
				char tmpFile[MAX_PATH];
				if (GetTempFileNameA(parentDir.string().c_str(), prefix.c_str(), 0, tmpFile) == 0)
				{
					LOG_WAR << fname << "GetTempFileNameA failed in directory <" << parentDir.string() << "> with error " << ::GetLastError();
					return {};
				}
				finalPath = tmpFile;
			}

			SECURITY_ATTRIBUTES sa{};
			sa.nLength = sizeof(sa);
			sa.bInheritHandle = FALSE;
			sa.lpSecurityDescriptor = NULL;

			HANDLE hFile = ::CreateFileA(
				finalPath.string().c_str(),
				GENERIC_WRITE,
				0,
				&sa,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_TEMPORARY,
				NULL);

			if (hFile == INVALID_HANDLE_VALUE)
			{
				LOG_WAR << fname << "Failed to create file <" << finalPath.string() << "> with error " << ::GetLastError();
				return {};
			}

			DWORD bytesWritten = 0;
			if (!content.empty())
			{
				if (!::WriteFile(hFile, content.data(), static_cast<DWORD>(content.size()), &bytesWritten, NULL) ||
					bytesWritten != content.size())
				{
					LOG_WAR << fname << "Failed to write to file <" << finalPath.string() << ">, wrote " << bytesWritten << " of " << content.size() << " bytes";
					::CloseHandle(hFile);
					return {};
				}
			}

			::FlushFileBuffers(hFile);
			::CloseHandle(hFile);

			return finalPath.string();
		}
		catch (const std::exception &e)
		{
			LOG_WAR << fname << "Exception while creating temp file: " << e.what();
			return {};
		}
	}

} // namespace os

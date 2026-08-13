// src/common/os/filesystem.h
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace os
{
	/// List files in a directory.
	std::vector<std::string> ls(const std::string &directory);

	struct FilesystemUsage
	{
		uint64_t totalSize = 0;
		uint64_t usedSize = 0;
		uint64_t availableSize = 0;
		double usagePercentage = 0.0;
	};

	/// Get filesystem usage statistics.
	std::shared_ptr<FilesystemUsage> df(const std::string &path =
#if defined(_WIN32)
											"C:\\"
#else
											"/"
#endif
	);

	/// Get mounted local logical disks and their device identifiers.
	std::map<std::string, std::string> getMountPoints();

	/// Get file status including mode, username, and groupname.
	std::tuple<int, std::string, std::string> fileStat(const std::string &path);

	/// Change file permissions using a numeric mode value.
	bool fileChmod(const std::string &path, uint16_t mode);

	/// Change file permissions using a numeric shorthand value (e.g., 755).
	bool chmod(const std::string &path, uint16_t mode);

	/// Creates a temporary file with the requested mode and writes the content.
	std::string createTmpFile(const std::string &fileName, const std::string &content, uint16_t mode = 0644);

} // namespace os

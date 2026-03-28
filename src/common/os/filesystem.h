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

	/// Get mount points and their devices.
	std::map<std::string, std::string> getMountPoints();

	/// Get file status including mode, username, and groupname.
	std::tuple<int, std::string, std::string> fileStat(const std::string &path);

	/// Change file permissions using a numeric mode value.
	bool fileChmod(const std::string &path, uint16_t mode);

	/// Change file permissions using a numeric shorthand value (e.g., 755).
	bool chmod(const std::string &path, uint16_t mode);

	/// Creates a secure temporary file, writes given content, and returns its path.
	std::string createTmpFile(const std::string &fileName, const std::string &content);

} // namespace os

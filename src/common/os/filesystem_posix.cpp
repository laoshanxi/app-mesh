// src/common/os/filesystem_posix.cpp
// POSIX filesystem utilities shared by Linux and macOS.

#include "filesystem.h"

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <grp.h>
#include <memory>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "../Utility.h"

namespace os
{

	std::vector<std::string> ls(const std::string &directory)
	{
		const static char fname[] = "os::ls() ";
		std::vector<std::string> result;

		std::unique_ptr<DIR, void (*)(DIR *)> dir(opendir(directory.c_str()), [](DIR *d)
												  { if(d) closedir(d); });
		if (!dir)
		{
			LOG_WAR << fname << "Failed to open directory: " << directory << " with error: " << last_error_msg();
			return result;
		}

		struct dirent *entry;
		errno = 0;

		while ((entry = readdir(dir.get())) != nullptr)
		{
			const std::string name = entry->d_name;
			if (name == "." || name == "..")
			{
				continue;
			}
			result.push_back(name);
		}

		if (errno != 0)
		{
			LOG_WAR << fname << "Failed to read directory: " << directory << " with error: " << last_error_msg();
			return {};
		}

		return result;
	}

	std::tuple<int, std::string, std::string> fileStat(const std::string &path)
	{
		const static char fname[] = "fileStat() ";

		struct stat st;
		if (stat(path.c_str(), &st) != 0)
		{
			LOG_WAR << fname << "Failed stat <" << path << "> with error: " << last_error_msg();
			return std::make_tuple(-1, "", "");
		}

		int mode = st.st_mode & 0777;

		std::string username;
		std::string groupname;

		if (struct passwd *pw = getpwuid(st.st_uid))
		{
			username = pw->pw_name;
		}
		else
		{
			username = std::to_string(st.st_uid);
		}

		if (struct group *gr = getgrgid(st.st_gid))
		{
			groupname = gr->gr_name;
		}
		else
		{
			groupname = std::to_string(st.st_gid);
		}

		return std::make_tuple(mode, username, groupname);
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

		if (::chmod(path.c_str(), mode) == 0)
		{
			return true;
		}
		else
		{
			LOG_WAR << fname << "Failed chmod <" << path << "> with error: " << last_error_msg();
			return false;
		}
	}

	std::string createTmpFile(const std::string &fileName, const std::string &content)
	{
		const char *fname = "os::createTmpFile() ";

		try
		{
			fs::path finalPath;

			std::string tmpl;
			if (fileName.empty())
			{
				tmpl = (fs::temp_directory_path() / "appmesh-XXXXXX").string();
			}
			else
			{
				tmpl = fs::absolute(fileName).string() + "-XXXXXX";
			}

			std::vector<char> buf(tmpl.begin(), tmpl.end());
			buf.push_back('\0');

			int fd = ::mkstemp(buf.data());
			if (fd == -1)
			{
				LOG_DBG << fname << "Failed to create temp file from template <" << tmpl << ">";
				return {};
			}

			if (::fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1)
			{
				LOG_DBG << fname << "Failed to set permissions on file <" << buf.data() << ">";
				::close(fd);
				::unlink(buf.data());
				LOG_DBG << fname << "file <" << buf.data() << "> removed";
				return {};
			}

			if (!content.empty())
			{
				ssize_t written = ::write(fd, content.data(), content.size());
				if (written == -1 || static_cast<size_t>(written) != content.size())
				{
					LOG_DBG << fname << "Failed to write content to file <" << buf.data() << ">";
					::close(fd);
					::unlink(buf.data());
					LOG_DBG << fname << "file <" << buf.data() << "> removed";
					return {};
				}
				::fsync(fd);
			}

			::close(fd);
			finalPath = buf.data();

			return finalPath.string();
		}
		catch (const std::exception &e)
		{
			LOG_DBG << fname << "Exception: " << e.what();
			return {};
		}
	}

} // namespace os

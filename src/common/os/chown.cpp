#if !defined(_WIN32)
#include <cstring>
#include <fts.h>
#include <grp.h>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#endif

#include "../Utility.h"
#include "chown.h"
#include "linux.h"

namespace os
{

	bool chown(const std::string &path, uid_t uid, gid_t gid, bool recursive)
	{
		constexpr char fname[] = "os::chown() ";
#if !defined(_WIN32)
		// Input validation
		if (path.empty() || !fs::exists(path))
		{
			LOG_ERR << fname << "Path does not exist: " << path;
			return false;
		}
		constexpr uid_t INVALID_UID = static_cast<uid_t>(-1);
		constexpr gid_t INVALID_GID = static_cast<gid_t>(-1);
		if (uid == INVALID_UID || gid == INVALID_GID)
		{
			LOG_ERR << fname << "Invalid UID or GID provided";
			return false;
		}

		// Prepare FTS path array
		char *const path_arr[] = {const_cast<char *>(path.c_str()), nullptr};

		// Open file hierarchy
		const int fts_options = FTS_NOCHDIR | FTS_PHYSICAL;
		std::unique_ptr<FTS, decltype(&::fts_close)> tree(::fts_open(path_arr, fts_options, nullptr), ::fts_close);

		if (tree == nullptr)
		{
			LOG_ERR << fname << "Failed to open path: " << path << ", error: " << last_error_msg();
			return false;
		}

		FTSENT *node;
		while ((node = ::fts_read(tree.get())) != nullptr)
		{
			// Early exit for non-recursive mode
			if (node->fts_level > FTS_ROOTLEVEL && !recursive)
			{
				break;
			}

			switch (node->fts_info)
			{
			case FTS_D:		 // Preorder directory
			case FTS_F:		 // Regular file
			case FTS_SL:	 // Symbolic link
			case FTS_SLNONE: // Symbolic link without target
			{
				if (::lchown(node->fts_path, uid, gid) < 0)
				{
					LOG_ERR << fname << "Failed to change ownership of " << node->fts_path << ", error: " << last_error_msg();
					return false;
				}
				LOG_DBG << fname << "Changed ownership of " << node->fts_path << " to uid=" << uid << " gid=" << gid;
				break;
			}

			case FTS_DNR: // Unreadable directory
			case FTS_ERR: // Error; errno is set
			case FTS_DC:  // Directory that causes cycles
			case FTS_NS:  // stat(2) failed
			{
				LOG_ERR << fname << "Failed to process " << node->fts_path << ", error type: " << node->fts_info << ", error: " << std::strerror(node->fts_errno);
				return false;
			}

			default:
				break;
			}
		}

		LOG_DBG << fname << "Successfully changed ownership" << (recursive ? " recursively" : "") << " for " << path;
#endif
		return true;
	}

	bool chown(const std::string &path, std::string user, std::string group, bool recursive)
	{
		constexpr char fname[] = "os::chown() ";
#if !defined(_WIN32)
		// Input validation
		if (path.empty())
		{
			LOG_ERR << fname << "Empty path provided";
			return false;
		}

		// Verify path exists
		if (!fs::exists(path))
		{
			LOG_ERR << fname << "Path does not exist: " << path;
			return false;
		}

		// Get current ownership
		struct stat st;
		if (::lstat(path.c_str(), &st) != 0)
		{
			LOG_ERR << fname << "Failed to get file stats for " << path << ": " << last_error_msg();
			return false;
		}

		// Initialize with current values
		uid_t uid = st.st_uid;
		gid_t gid = st.st_gid;

		// Update uid if user is specified
		if (!user.empty())
		{
			if (!os::getUidByName(user, uid, gid))
			{
				LOG_ERR << fname << "Failed to get user information for '" << user << "'";
				return false;
			}
		}

		// Update gid if group is specified
		if (!group.empty())
		{
			// Determine required buffer size (cached static value)
			static const auto bufsize = []()
			{
				long size = sysconf(_SC_GETGR_R_SIZE_MAX);
				return (size == -1) ? 16384 : size;
			}();

			// Allocate buffer
			std::vector<char> buffer(bufsize);
			struct group grp;
			struct group *result = nullptr;

			// Try getting group information
			int err = ::getgrnam_r(group.c_str(), &grp, buffer.data(), buffer.size(), &result);
			if (err != 0)
			{
				LOG_WAR << fname << "Failed to get group information for '" << group << "': " << std::strerror(err);
			}
			else if (result == nullptr)
			{
				LOG_WAR << fname << "Group '" << group << "' not found";
			}
			else
			{
				gid = grp.gr_gid;
			}
		}

		LOG_DBG << fname << "Attempting to change ownership of " << path
				<< " to " << (user.empty() ? "current user" : user)
				<< " (uid=" << uid << ")"
				<< ", group=" << (group.empty() ? "current group" : group)
				<< " (gid=" << gid << ")"
				<< (recursive ? " recursively" : "");

		// Attempt to change ownership
		return chown(path, uid, gid, recursive);
#else
		LOG_DBG << fname << "Skipping ownership change on Windows for path: " << path;
		return true; // No-op on Windows
#endif
	}

} // namespace os

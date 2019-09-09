
#ifndef __STOUT_OS_POSIX_CHOWN_HPP__
#define __STOUT_OS_POSIX_CHOWN_HPP__
#include <string>
#include <fts.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include "../../common//Utility.h"
namespace os {

	// Set the ownership for a path. This function never follows any symlinks.
	inline bool chown(uid_t uid, gid_t gid, const std::string& path, bool recursive)
	{
		char* path_[] = { const_cast<char*>(path.c_str()), nullptr };

		FTS* tree = ::fts_open(path_, FTS_NOCHDIR | FTS_PHYSICAL, nullptr);

		if (tree == nullptr)
		{
			return false;
		}

		FTSENT *node;
		while ((node = ::fts_read(tree)) != nullptr)
		{
			switch (node->fts_info)
			{
				// Preorder directory.
			case FTS_D:
				// Regular file.
			case FTS_F:
				// Symbolic link.
			case FTS_SL:
				// Symbolic link without target.
			case FTS_SLNONE: {
				if (::lchown(node->fts_path, uid, gid) < 0)
				{
					::fts_close(tree);
					return false;
				}

				break;
			}

							 // Unreadable directory.
			case FTS_DNR:
				// Error; errno is set.
			case FTS_ERR:
				// Directory that causes cycles.
			case FTS_DC:
				// `stat(2)` failed.
			case FTS_NS: {
				::fts_close(tree);
				return false;
			}

			default:
				break;
			}

			if (node->fts_level == FTS_ROOTLEVEL && !recursive)
			{
				break;
			}
		}

		::fts_close(tree);
		return true;
	}


	// Changes the specified path's user and group ownership to that of
	// the specified user.
	inline bool chown(const std::string& path, const std::string& user, bool recursive = false)
	{
		const static char fname[] = "os::chown() ";

		if (user.empty()) return false;

		passwd* passwd;
		errno = 0;
		if ((passwd = ::getpwnam(user.c_str())) == nullptr)
		{

			if (errno)
			{
				LOG_WAR << fname << "Failed to get user information for '" << user << "'";
			}
			else
			{
				LOG_WAR << fname << "No such user '" << user << "'";
			}
			return false;
		}

		return chown(passwd->pw_uid, passwd->pw_gid, path, recursive);
	}

} // namespace os {

#endif // __STOUT_OS_POSIX_CHOWN_HPP__

#pragma once

#include <string>
#include <sys/types.h>

namespace os
{

    /**
     * @brief Changes owner and group of a file or directory
     * @param path Path to the file or directory
     * @param uid User id of the new owner
     * @param gid Group id of the new group
     * @param recursive If true, applies changes recursively for directories
     * @return true if successful, false otherwise
     */
    bool chown(const std::string &path, uid_t uid, gid_t gid, bool recursive = false);

    /**
     * @brief Changes owner and group of a file or directory
     * @param path Path to the file or directory
     * @param user Username of the new owner (can be empty to keep current)
     * @param group Group name of the new group (can be empty to keep current)
     * @param recursive If true, applies changes recursively for directories
     * @return true if successful, false otherwise
     */
    bool chown(const std::string &path, std::string user, std::string group = "", bool recursive = false);

} // namespace os

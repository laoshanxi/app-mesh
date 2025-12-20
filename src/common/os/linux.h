// src/common/os/linux.h
#pragma once

// This file contains cross-platform OS utilities for Linux/macOS/Windows.
// Common headers required for declarations
#include <atomic>
#include <chrono>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ace/OS.h>           // for ACE_OS::abc()
#include <ace/OS_NS_unistd.h> // for uid_t, pid_t

#include "models.h"     // for Process
#include "procstat.hpp" // for ProcessStatus

namespace os
{

    /**
     * @brief List files in a directory.
     *
     * Retrieves the names of all files and directories in the specified directory.
     * If the directory cannot be accessed, returns an empty vector.
     *
     * @param directory Path to the directory.
     * @return A vector of file and directory names within the specified directory.
     */
    std::vector<std::string> ls(const std::string &directory);

    /**
     * @brief Get total system CPU time.
     *
     * Cross-platform implementation to get total CPU time.
     *
     * @return Total system CPU time in appropriate units, or 0 on error.
     */
    int64_t cpuTotalTime();

    /**
     * @brief Get the status of a process.
     *
     * Cross-platform process status retrieval.
     *
     * @param pid Process ID.
     * @return A shared pointer to a `ProcessStatus` object, or `nullptr` if the process does not exist or an error occurs.
     */
    std::shared_ptr<ProcessStatus> status(pid_t pid);

    /**
     * @brief Get the command line of a process.
     *
     * Cross-platform command line retrieval.
     *
     * @param pid Process ID (default is 0, which represents the current process).
     * @return A string containing the command line of the specified process.
     */
    std::string cmdline(pid_t pid = 0);

#if defined(_WIN32)
    // Forward declarations for Windows-specific types used internally
    // These structs are defined in the .cpp or via Windows headers included there
    struct _SYSTEM_PROCESS_INFORMATION; // Forward declaration
#endif

    /**
     * @brief Get the set of process IDs for the descendants of a given process.
     *
     * @param rootPid The root process ID.
     * @return A set containing the PIDs of all descendant processes.
     */
    std::unordered_set<pid_t> child_pids(pid_t rootPid);

    /**
     * @brief Get the set of process IDs for the given process and its descendants.
     *
     * @param rootPid The root process ID (defaults to current process).
     * @return A set containing the PIDs of the process and its descendants.
     */
    std::unordered_set<pid_t> pids(pid_t rootPid = ACE_OS::getpid());

    // Structure containing memory information
    struct Memory
    {
        Memory();
        uint64_t total_bytes;
        uint64_t free_bytes;
        uint64_t totalSwap_bytes;
        uint64_t freeSwap_bytes;
    };

    std::ostream &operator<<(std::ostream &stream, const Memory &mem);

    // Cross-platform page size
    size_t pagesize();

    /**
     * @brief Get process information for a given PID.
     *
     * Cross-platform process information retrieval.
     *
     * @param pid Process ID of the target process.
     * @return Shared pointer to a Process struct containing the process details.
     */
    std::shared_ptr<Process> process(pid_t pid);

    /**
     * @brief Get process information for a given PID from a pre-fetched list.
     *
     * @param pid Process ID of the target process.
     * @param processes A list of pre-fetched Process objects.
     * @return Shared pointer to a Process struct if found, otherwise nullptr.
     */
    std::shared_ptr<Process> process(pid_t pid, const std::list<Process> &processes);

    // Returns the total size of main and free memory.
    std::shared_ptr<Memory> memory();

    std::list<Process> processes();

    //************************CPU****************************************
    // Representation of a processor (cross-platform)
    struct CPU
    {
        CPU(unsigned int _id, unsigned int _core, unsigned int _socket);
        // These are non-const because we need the default assignment operator.
        unsigned int id;     // "processor"
        unsigned int core;   // "core id"
        unsigned int socket; // "physical id"
    };

    std::ostream &operator<<(std::ostream &stream, const CPU &cpu);

    /**
     * @brief Get information about all CPUs in the system.
     *
     * Cross-platform CPU information retrieval.
     * Thread-safe implementation using double-checked locking pattern.
     *
     * @return List of CPU objects containing processor ID, core ID and socket ID.
     */
    std::list<CPU> cpus();

    //************************CPU****************************************
    // Structure returned by loadavg(). Encodes system load average
    // for the last 1, 5 and 15 minutes.
    struct Load
    {
        double one;
        double five;
        double fifteen;
    };

    /**
     * @brief Get system load averages for the last 1, 5, and 15 minutes.
     *
     * Cross-platform load average implementation.
     * Note: Windows doesn't have a direct equivalent to Unix load average,
     * so we approximate using CPU usage.
     *
     * @return Shared pointer to Load struct with the average loads for the last 1, 5, and 15 minutes.
     */
    std::shared_ptr<Load> loadavg();

    struct FilesystemUsage
    {
        uint64_t totalSize = 0;       // Total size in bytes
        uint64_t usedSize = 0;        // Used size in bytes
        double usagePercentage = 0.0; // Usage as a percentage (0.0 to 1.0)
    };

    /**
     * @brief Get filesystem usage statistics.
     *
     * Cross-platform disk usage information.
     *
     * @param path Directory path (default is "/" on Unix, "C:\\" on Windows).
     * @return Shared pointer to FilesystemUsage containing size, used space, and usage.
     */
    std::shared_ptr<FilesystemUsage> df(const std::string &path =
#if defined(_WIN32)
                                            "C:\\"
#else
                                            "/"
#endif
    );

    /**
     * @brief Get mount points and their devices.
     *
     * Cross-platform mount point enumeration.
     *
     * @return Map of mount points and devices.
     */
    std::map<std::string, std::string> getMountPoints();

    /**
     * @brief Get file mode, user ID, and group ID.
     * Cross-platform file stat information.
     *
     * @param path File path.
     * @return Tuple containing file mode (permissions), user ID, and group ID. Returns (-1, -1, -1) on failure.
     */
    std::tuple<int, int, int> fileStat(const std::string &path);

    /**
     * @brief Change file permissions using a numeric mode value.
     * Cross-platform file permission modification.
     *
     * @param path File path.
     * @param mode Permissions mode in octal (e.g., 0755).
     * @return True if successful, false otherwise.
     */
    bool fileChmod(const std::string &path, uint16_t mode);

    /**
     * @brief Change file permissions using a numeric shorthand value (e.g., 755).
     * Cross-platform permission modification with shorthand notation.
     *
     * @param path File path.
     * @param mode Shorthand permissions mode (e.g., 755).
     * @return True if successful, false otherwise.
     */
    bool chmod(const std::string &path, uint16_t mode);

    // SID to UID conversion for Windows simulation
    unsigned int hashSidToUid(const std::string &sidString);

    bool getUidByName(const std::string &userName, unsigned int &uid, unsigned int &groupid);

    // Get uid for Windows and Linux
    uid_t get_uid();

    std::string getUsernameByUid(uid_t uid = get_uid());

    /**
     * @brief Creates a secure temporary file, writes given content, and returns its path.
     *
     * @param fileName   Base filename. If empty, a randomized name "appmesh-%%%%-%%%%.tmp" is used.
     * @param content    String content to write into the file.
     * @return Output the full path of the created file, or empty string on failure.
     */
    std::string createTmpFile(const std::string &fileName, const std::string &content);

} // namespace os
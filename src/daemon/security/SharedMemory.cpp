// src/daemon/security/SharedMemory.cpp
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <chrono>
#include <fstream>
#include <thread>

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

#include "../../common/Utility.h"
#include "../../common/os/chown.h"
#include "../../common/os/proc.h"
#include "SharedMemory.h"

namespace bip = boost::interprocess;

SharedMemory::SharedMemory()
    : m_shmName(GenerateSharedMemoryName())
{
}

SharedMemory::~SharedMemory()
{
    cleanup();
}

bool SharedMemory::create()
{
    const static char fname[] = "SharedMemory::create() ";

    auto shmName = m_shmName;
#if defined(__APPLE__)
    // macOS: Use POSIX shared memory with /tmp prefix for memory-mapped files
    // Note: This creates a file-backed shared memory, not true POSIX shm
    shmName = (fs::path("/tmp/") / shmName).string();
#elif defined(__linux__)
    // Linux: Use tmpfs-based shared memory for fast in-memory access
    shmName = (fs::path("/dev/shm/") / shmName).string();
#elif defined(_WIN32)
    shmName = (fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_WORK_TMP_DIR / shmName).string();
#endif
    m_shmPath = shmName;

    // The child opens the exported path and maps the file itself, so the
    // segment must stay a plain file with the byte contract below.
#if !defined(_WIN32)
    // O_EXCL|O_NOFOLLOW: the segment name is weakly unpredictable and lives in
    // a world-writable directory, so refuse to follow a planted link or clobber
    // an existing file.
    const int fd = ::open(shmName.c_str(), O_CREAT | O_EXCL | O_NOFOLLOW | O_RDWR, 0600);
    if (fd < 0)
    {
        LOG_WAR << fname << "Failed to create shared memory <" << shmName << ">: " << last_error_msg();
        return false;
    }
    if (::ftruncate(fd, PSK_SHM_TOTAL_SIZE) != 0)
    {
        LOG_WAR << fname << "Failed to size shared memory <" << shmName << ">: " << last_error_msg();
        ::close(fd);
        return false;
    }
    ::close(fd);
#else
    // The mapping needs a file of full size, and the mapping takes the size the
    // file has when it is created: keep the stream scoped so it is closed first.
    {
        std::ofstream file(shmName, std::ios::binary | std::ios::trunc);
        const char zeros[PSK_SHM_TOTAL_SIZE] = {0};
        if (!file.write(zeros, sizeof(zeros)))
        {
            LOG_WAR << fname << "Failed to create shared memory <" << shmName << ">: write error";
            return false;
        }
    }
#endif

    try
    {
        m_mapping = std::make_unique<bip::file_mapping>(shmName.c_str(), bip::read_write);
        m_region = std::make_unique<bip::mapped_region>(*m_mapping, bip::read_write, 0, PSK_SHM_TOTAL_SIZE);
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "Failed to map shared memory <" << shmName << ">: " << e.what();
        cleanup();
        return false;
    }
    LOG_DBG << fname << "Shared memory created successfully: " << shmName;

    m_shmPtr = static_cast<psk_shared_memory_t *>(m_region->get_address());
    if (!m_shmPtr)
    {
        LOG_WAR << fname << "Failed to get pointer for shared memory <" << shmName << ">";
        cleanup();
        return false;
    }

    // Initialize the struct properly
    memset(m_shmPtr->message, 0, PSK_FLAG_OFFSET);
    // Initialize atomic flag using placement new to ensure proper construction
    new (&m_shmPtr->flag) std::atomic<int32_t>(0);

    // Ensure memory operations are visible across processes
    std::atomic_thread_fence(std::memory_order_seq_cst);
    return true;
}

// Non-blocking check for the flag set by the child process
bool SharedMemory::isFlagSet() const
{
    return m_shmPtr && m_shmPtr->flag.load(std::memory_order_acquire) == 1;
}

// Wait for the flag to be set to 1 by child process
// Returns true if flag is set, false if timeout
bool SharedMemory::waitForFlag(int timeoutSeconds)
{
    const static char fname[] = "SharedMemory::waitForFlag() ";

    if (!m_shmPtr)
    {
        LOG_WAR << fname << "SharedMemory pointer is null";
        return false;
    }

    auto start = std::chrono::steady_clock::now();
    while (true)
    {
        if (m_shmPtr->flag.load(std::memory_order_acquire) == 1)
        {
            LOG_DBG << fname << "Flag received successfully";
            return true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(timeoutSeconds))
        {
            LOG_WAR << fname << "Timed out waiting for flag after <" << timeoutSeconds << "> seconds";
            return false;
        }
    }
}

// Write to shared memory (parent process writes data for child)
bool SharedMemory::writeData(const char *data)
{
    const static char fname[] = "SharedMemory::writeData() ";

    if (!m_shmPtr)
    {
        LOG_WAR << fname << "SharedMemory pointer is null";
        return false;
    }

    if (!data)
    {
        LOG_WAR << fname << "Data pointer is null";
        return false;
    }

    size_t len = strlen(data);
    if (len > PSK_MSG_LENGTH)
    {
        LOG_WAR << fname << "Data too long: " << len << " > " << PSK_MSG_LENGTH;
        return false;
    }

    // Clear the message buffer first
    memset(m_shmPtr->message, 0, PSK_FLAG_OFFSET);
    // Copy data ensuring null termination
    strncpy(m_shmPtr->message, data, PSK_MSG_LENGTH);
    m_shmPtr->message[PSK_MSG_LENGTH] = '\0';

    // Ensure write is visible to other processes
    std::atomic_thread_fence(std::memory_order_release);
    LOG_DBG << fname << "Data written successfully, length: " << len;
    return true;
}

// Read from shared memory (child process reads data written by parent)
const char *SharedMemory::readData() const
{
    if (!m_shmPtr)
    {
        return nullptr;
    }
    return m_shmPtr->message;
}

// Set the flag to 1 (child process sets flag after reading)
void SharedMemory::writeFlag()
{
    const static char fname[] = "SharedMemory::writeFlag() ";

    if (!m_shmPtr)
    {
        LOG_WAR << fname << "SharedMemory pointer is null";
        return;
    }

    m_shmPtr->flag.store(1, std::memory_order_release);
    // Ensure flag write is visible across processes
    std::atomic_thread_fence(std::memory_order_seq_cst);
    LOG_DBG << fname << "Flag set successfully";
}

const std::string &SharedMemory::shmPath() const
{
    return m_shmPath;
}

bool SharedMemory::changeOwner(const std::string &user)
{
    const static char fname[] = "SharedMemory::changeOwner() ";

    if (user.empty())
        return true;
#if defined(_WIN32)
    LOG_WAR << fname << "Changing shared memory owner is not supported on Windows";
    return false;
#else
    if (m_shmPath.empty())
    {
        LOG_WAR << fname << "Shared memory is not created yet";
        return false;
    }
    if (!os::chown(m_shmPath, user))
    {
        LOG_WAR << fname << "Failed to change owner of <" << m_shmPath << "> to <" << user << ">";
        return false;
    }
    return true;
#endif
}

void SharedMemory::cleanup()
{
    if (m_mapping && m_shmPtr)
    {
        // Explicitly destroy the atomic before cleanup
        m_shmPtr->flag.~atomic();
        m_shmPtr = nullptr;
    }

    // Unmap and close before removing the file: on Windows the deletion
    // fails while our own handle is still open.
    m_region.reset();
    m_mapping.reset();
    if (!m_shmPath.empty())
    {
        std::error_code ec;
        fs::remove(fs::path(m_shmPath), ec);
    }
}

std::string SharedMemory::GenerateSharedMemoryName()
{
    return "appmesh_shm_" + Utility::shortID() + "_" + std::to_string(os::getpid());
}

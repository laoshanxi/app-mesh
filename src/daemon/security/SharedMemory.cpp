#pragma once
#include <ace/OS_NS_stdlib.h>
#include <ace/OS_NS_string.h>
#include <ace/OS_NS_unistd.h>
#include <ace/Shared_Memory_MM.h>
#include <atomic>
#include <boost/filesystem.hpp>
#include <chrono>
#include <thread>

#include "../../common/Utility.h"
#include "SharedMemory.h"

SharedMemory::SharedMemory()
    : m_shmName(GetSharedMemoryName()), m_aceShm(nullptr), m_shmPtr(nullptr)
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
    shmName = (boost::filesystem::path("/tmp/") / shmName).string();
#elif defined(__linux__)
    // Linux: Use tmpfs-based shared memory for fast in-memory access
    shmName = (boost::filesystem::path("/dev/shm/") / shmName).string();
#elif defined(_WIN32)
    shmName = (boost::filesystem::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_WORK_TMP_DIR / shmName).string();
#endif

    m_aceShm = std::make_shared<ACE_Shared_Memory_MM>();

#if defined(_WIN32)
    // Windows: ACE_Shared_Memory_MM uses CreateFileMapping internally
    if (m_aceShm->open(shmName.c_str(), PSK_SHM_TOTAL_SIZE, O_CREAT | O_RDWR) == -1)
#else
    // Unix-like: Use appropriate file permissions for shared memory
    if (m_aceShm->open(shmName.c_str(), PSK_SHM_TOTAL_SIZE, O_CREAT | O_RDWR, 0600) == -1)
#endif
    {
        LOG_WAR << fname << "Failed to create shared memory: " << last_error_msg();
        m_aceShm = nullptr;
        return false;
    }
    LOG_INF << fname << "Shared memory created successfully: " << shmName;

    m_shmPtr = static_cast<psk_shared_memory_t *>(m_aceShm->malloc());
    if (!m_shmPtr)
    {
        LOG_WAR << fname << "Failed to get shared memory pointer";
        cleanup();
        return false;
    }

    // Initialize the struct properly
    ACE_OS::memset(m_shmPtr->message, 0, PSK_FLAG_OFFSET);
    // Initialize atomic flag using placement new to ensure proper construction
    new (&m_shmPtr->flag) std::atomic<int32_t>(0);

    // Ensure memory operations are visible across processes
    std::atomic_thread_fence(std::memory_order_seq_cst);
    return true;
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
            LOG_INF << fname << "Flag received successfully";
            return true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(timeoutSeconds))
        {
            LOG_WAR << fname << "Wait flag timeout after " << timeoutSeconds << " seconds";
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

    size_t len = ACE_OS::strlen(data);
    if (len > PSK_MSG_LENGTH)
    {
        LOG_WAR << fname << "Data too long: " << len << " > " << PSK_MSG_LENGTH;
        return false;
    }

    // Clear the message buffer first
    ACE_OS::memset(m_shmPtr->message, 0, PSK_FLAG_OFFSET);
    // Copy data ensuring null termination
    ACE_OS::strncpy(m_shmPtr->message, data, PSK_MSG_LENGTH);
    m_shmPtr->message[PSK_MSG_LENGTH] = '\0';

    // Ensure write is visible to other processes
    std::atomic_thread_fence(std::memory_order_release);
    LOG_INF << fname << "Data written successfully, length: " << len;
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
    LOG_INF << fname << "Flag set successfully";
}

// Get the shared memory name for environment export
std::string SharedMemory::shmName() const
{
    return m_shmName;
}

void SharedMemory::cleanup()
{
    if (m_aceShm && m_shmPtr)
    {
        // Explicitly destroy the atomic before cleanup
        m_shmPtr->flag.~atomic();
    }

    if (m_aceShm)
    {
        m_aceShm->close();
        m_aceShm->remove();
        m_aceShm = nullptr;
        m_shmPtr = nullptr;
    }
}

// Export the shared memory name to environment variable by parent process
void SharedMemory::exportEnv(const std::string &envName)
{
    const static char fname[] = "SharedMemory::exportEnv() ";

    if (envName.empty())
    {
        LOG_WAR << fname << "Environment variable name is empty";
        return;
    }

    // Use thread_local storage to avoid static memory issues in multi-threaded environments
    thread_local std::string env_copy;
    thread_local std::string last_value;

    std::string current_value = envName + "=" + m_shmName;

    // Avoid redundant putenv calls
    if (current_value == last_value)
    {
        return;
    }

    env_copy = current_value;
    last_value = current_value;

    if (ACE_OS::putenv(env_copy.data()) != 0)
    {
        LOG_WAR << fname << "Failed to export environment variable: " << envName << ", error: " << last_error_msg();
    }
    else
    {
        LOG_INF << fname << "Environment variable exported: " << envName;
    }
}

std::string SharedMemory::GetSharedMemoryName()
{
    return "appmesh_shm_" + Utility::createUUID() + "_" + std::to_string(ACE_OS::getpid());
}

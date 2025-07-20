#pragma once
#include <ace/OS_NS_stdlib.h>
#include <ace/OS_NS_string.h>
#include <ace/OS_NS_unistd.h>
#include <ace/Shared_Memory_MM.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
#if defined(WIN32)
#include <windows.h>
#endif

#include "../../common/Utility.h"

class SharedMemoryFlag
{
public:
    SharedMemoryFlag(size_t size, size_t flagOffset)
        : m_shmName(GetSharedMemoryName()),
          m_aceShm(nullptr),
          m_shmPtr(nullptr),
          m_size(size),
          m_flagOffset(flagOffset)
    {
    }

    ~SharedMemoryFlag()
    {
        cleanup();
    }

    // Create shared memory segment and init flag to 0
    bool create()
    {
        auto shmName = m_shmName;
#if defined(__APPLE__)
        // macOS POSIX shared memory uses /tmp for disk backed shared memory
        shmName = (boost::filesystem::path("/tmp/") / shmName).string();
#elif defined(__linux__)
        // Linux shared memory in tmpfs for fast in-memory shared memory
        shmName = (boost::filesystem::path("/dev/shm/") / shmName).string();
#endif

        m_aceShm = std::make_shared<ACE_Shared_Memory_MM>();
        if (m_aceShm->open(shmName.c_str(), m_size, O_CREAT | O_RDWR, ACE_DEFAULT_FILE_PERMS) == -1)
        {
            LOG_WAR << "Failed to create shared memory: " << ACE_OS::strerror(errno);
            m_aceShm = nullptr;
            return false;
        }

        m_shmPtr = static_cast<uint8_t *>(m_aceShm->malloc());
        if (!m_shmPtr)
        {
            LOG_WAR << "Failed to get shared memory pointer";
            cleanup();
            return false;
        }

        // Reset memory to 0
        ACE_OS::memset(m_shmPtr, 0, m_size);
        return true;
    }

    // Wait for the flag to be set to 1 by child process
    // Returns true if flag is set, false if timeout
    bool waitForFlag(int timeoutSeconds = 10)
    {
        if (!m_shmPtr)
            return false;

        auto start = std::chrono::steady_clock::now();
        while (true)
        {
            // Use atomic load for thread safety
            if (static_cast<std::atomic<uint8_t> *>(reinterpret_cast<void *>(&m_shmPtr[m_flagOffset]))->load(std::memory_order_acquire) == 1)
            {
                return true;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() > timeoutSeconds)
            {
                LOG_WAR << "Wait flag timeout after " << timeoutSeconds << " seconds";
                return false;
            }
        }
    }

    // Write to shared memory (parent process writes data for child)
    void writeData(const char *data, size_t len)
    {
        if (!m_shmPtr || len > m_flagOffset)
        {
            LOG_WAR << "Invalid write parameters: len=" << len << ", flagOffset=" << m_flagOffset;
            return;
        }
        ACE_OS::memcpy(m_shmPtr, data, len);
    }

    // Read from shared memory (child process reads data written by parent)
    const char *readData() const
    {
        return reinterpret_cast<const char *>(m_shmPtr);
    }

    // Set the flag to 1 (child process writes flag)
    void writeFlag()
    {
        if (m_shmPtr)
        {
            // Use atomic store for thread safety
            static_cast<std::atomic<uint8_t> *>(reinterpret_cast<void *>(&m_shmPtr[m_flagOffset]))->store(1, std::memory_order_release);
        }
    }

    // Get the shared memory name for environment export
    std::string shmName() const
    {
        return m_shmName;
    }

    void cleanup()
    {
        if (m_aceShm)
        {
            m_aceShm->close();
            m_aceShm->remove();
            m_aceShm = nullptr;
            m_shmPtr = nullptr;
        }
    }

    // Export the shared memory name to environment variable by parent process
    void exportEnv(const std::string &envName)
    {
        std::string envVar = envName + "=" + m_shmName;
        if (ACE_OS::putenv(envVar.c_str()) != 0)
        {
            LOG_WAR << "Failed to export environment variable: " << envName;
        }
    }

private:
    std::string m_shmName;
    std::shared_ptr<ACE_Shared_Memory_MM> m_aceShm;
    uint8_t *m_shmPtr;
    size_t m_size;       // shared memory size
    size_t m_flagOffset; // offset for flag byte

    // Generate a unique shared memory name based on process ID
    static std::string GetSharedMemoryName()
    {
        return "appmesh_shm_" + Utility::createUUID() + "_" + std::to_string(ACE_OS::getpid());
    }
};
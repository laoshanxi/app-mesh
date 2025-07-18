#include <chrono>
#include <openssl/hmac.h>
#include <sstream>
#include <string>
#include <thread>

#ifndef _WIN32
#include <fcntl.h>    //  shm_open  fcntl
#include <sys/mman.h> //  mmap munmap shm_unlink
#include <unistd.h>
#endif

#include <ace/OS_NS_string.h>
#include <ace/OS_NS_unistd.h>
#include <ace/Shared_Memory_MM.h>

#include "../../common/Password.h"
#include "../../common/Utility.h"
#include "HMACVerifier.h"

HMACVerifier::HMACVerifier()
    : m_shmName("/appmesh_" + Utility::createUUID()),
      m_psk(generatePassword(PSK_LENGTH, true, true, true, true)),
      m_shmPtr(nullptr)
#ifdef _WIN32
      ,m_aceShm(nullptr)
#endif
{
}

HMACVerifier::~HMACVerifier()
{
    cleanupSharedMemory();
}

std::string HMACVerifier::generateHMAC(const std::string &message) const
{
    unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(), m_psk.data(), m_psk.length(),
         reinterpret_cast<const unsigned char *>(message.data()),
         message.length(), hmac, &hmac_len);

    return bytesToHex(hmac, hmac_len);
}

bool HMACVerifier::verifyHMAC(const std::string &message, const std::string &receivedHmac) const
{
    return generateHMAC(message) == receivedHmac;
}

bool HMACVerifier::writePSKToSHM()
{
    const static char fname[] = "HMACVerifier::writePSKToSHM() ";

#ifdef _WIN32
    // Use ACE for Windows
    m_aceShm = new ACE_Shared_Memory_MM();

    // Create a temporary file name for Windows
    std::string tempPath = std::string(ACE_OS::getenv("TEMP") ? ACE_OS::getenv("TEMP") : "C:\\temp") + m_shmName + ".shm";

    if (m_aceShm->open(tempPath.c_str(), PSK_SHM_TOTAL_SIZE, O_CREAT | O_RDWR, ACE_DEFAULT_FILE_PERMS) == -1)
    {
        LOG_ERR << fname << "Failed to create shared memory: " << ACE_OS::strerror(errno);
        delete m_aceShm;
        m_aceShm = nullptr;
        return false;
    }

    m_shmPtr = m_aceShm->malloc();
    if (!m_shmPtr)
    {
        LOG_ERR << fname << "Failed to get shared memory pointer";
        delete m_aceShm;
        m_aceShm = nullptr;
        return false;
    }

#else
    // Original POSIX implementation for Linux/macOS
#if defined(__APPLE__)
    int fd = open((std::string("/private/tmp") + m_shmName).c_str(), O_CREAT | O_RDWR, 0600);
#else
    int fd = shm_open(m_shmName.c_str(), O_CREAT | O_RDWR, 0600);
#endif
    if (fd == -1)
    {
        LOG_ERR << fname << "Failed to create shared memory: " << strerror(errno);
        return false;
    }

    auto cleanup = [this, fd]()
    {
        close(fd);
#if defined(__APPLE__)
        unlink((std::string("/private/tmp") + m_shmName).c_str());
#else
        shm_unlink(m_shmName.c_str());
#endif
    };

    if (ftruncate(fd, PSK_SHM_TOTAL_SIZE) == -1)
    {
        LOG_ERR << fname << "Failed to set shared memory size: " << strerror(errno);
        cleanup();
        return false;
    }

    // TODO: agent start with same user as C++, no need change permission
    // modify permission, allow other user access
    // if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) == -1)
    //{
    //    LOG_ERR << fname << "Failed to change shared memory permissions: " << strerror(errno);
    //    cleanup();
    //    return false;
    //}

    void *shmPtr = mmap(NULL, PSK_SHM_TOTAL_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shmPtr == MAP_FAILED)
    {
        LOG_ERR << fname << "Failed to map shared memory: " << strerror(errno);
        cleanup();
        return false;
    }

    close(fd); // close fd, still valid in memory
    m_shmPtr = shmPtr;
#endif

    // Common code for all platforms
    ACE_OS::memcpy(m_shmPtr, m_psk.data(), PSK_LENGTH + 1);
    *((char *)m_shmPtr + PSK_FLAG_OFFSET) = 0; // init flag to zero

    LOG_INF << fname << "PSK prepared in shared memory successfully";

    return true;
}

bool HMACVerifier::waitPSKRead()
{
    const static char fname[] = "HMACVerifier::waitPSKRead() ";

    if (!m_shmPtr)
        return false;

    auto start = std::chrono::steady_clock::now();
    char *flagPtr = static_cast<char *>(m_shmPtr) + PSK_FLAG_OFFSET;

    while (*flagPtr == 0) // wait flag to be set to 1
    {
        LOG_DBG << fname << "Waiting for SHM flag";
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(10))
        {
            LOG_WAR << fname << "Timeout after waiting for 10 seconds";
            break;
        }
    }

    return cleanupSharedMemory();
}

const std::string &HMACVerifier::getShmName() const noexcept
{
    return m_shmName;
}

bool HMACVerifier::cleanupSharedMemory()
{
    const static char fname[] = "HMACVerifier::cleanupSharedMemory() ";

#ifdef _WIN32
    // Windows cleanup using ACE
    if (m_aceShm)
    {
        std::string tempPath = std::string(ACE_OS::getenv("TEMP") ? ACE_OS::getenv("TEMP") : "C:\\temp") + m_shmName + ".shm";

        if (m_aceShm->close() == 0)
        {
            // Remove the temporary file
            ACE_OS::unlink(tempPath.c_str());
            LOG_INF << fname << "Cleaned shared memory: " << tempPath;
            delete m_aceShm;
            m_aceShm = nullptr;
            m_shmPtr = nullptr;
            return true;
        }
        else
        {
            LOG_WAR << fname << "ACE shared memory close failed with error: " << ACE_OS::strerror(errno);
            delete m_aceShm;
            m_aceShm = nullptr;
        }
    }
#else
    // Original POSIX cleanup for Linux/macOS
    if (m_shmPtr && munmap(m_shmPtr, PSK_SHM_TOTAL_SIZE) == 0)
    {
        auto shmPath = m_shmName;
#if defined(__APPLE__)
        shmPath = (std::string("/private/tmp") + m_shmName);
        unlink(shmPath.c_str());
#else
        shm_unlink(shmPath.c_str());
#endif
        LOG_INF << fname << "Cleaned shared memory: " << shmPath;
        m_shmPtr = nullptr;
        return true;
    }
    if (m_shmPtr)
    {
        LOG_WAR << fname << "munmap failed with error: " << std::strerror(errno);
    }
#endif

    return false;
}

std::string HMACVerifier::bytesToHex(const unsigned char *data, size_t len)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
    {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

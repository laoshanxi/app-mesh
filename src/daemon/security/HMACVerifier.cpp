#include <chrono>
#include <openssl/hmac.h>
#include <sstream>
#include <string>
#include <thread>

#include <fcntl.h>    //  shm_open  fcntl
#include <sys/mman.h> //  mmap munmap shm_unlink
#include <unistd.h>

#include "../../common/Password.h"
#include "../../common/Utility.h"
#include "HMACVerifier.h"

HMACVerifier::HMACVerifier()
    : m_shmName("/appmesh_" + Utility::createUUID()),
      m_psk(generatePassword(PSK_LENGTH, true, true, true, true)),
      m_shmPtr(nullptr)
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

    int fd = shm_open(m_shmName.c_str(), O_CREAT | O_RDWR, 0666);
    if (fd == -1)
    {
        LOG_ERR << fname << "Failed to create shared memory: " << strerror(errno);
        return false;
    }

    auto cleanup = [this, fd]()
    {
        close(fd);
        shm_unlink(m_shmName.c_str());
    };

    if (ftruncate(fd, PSK_SHM_TOTAL_SIZE) == -1)
    {
        LOG_ERR << fname << "Failed to set shared memory size: " << strerror(errno);
        cleanup();
        return false;
    }

    // modify permission, allow other user access
    if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) == -1)
    {
        LOG_ERR << fname << "Failed to change shared memory permissions: " << strerror(errno);
        cleanup();
        return false;
    }

    void *shmPtr = mmap(NULL, PSK_SHM_TOTAL_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shmPtr == MAP_FAILED)
    {
        LOG_ERR << fname << "Failed to map shared memory: " << strerror(errno);
        cleanup();
        return false;
    }

    close(fd); // close fd, still valid in memory

    std::memcpy(shmPtr, m_psk.data(), PSK_LENGTH + 1);
    *((char *)shmPtr + PSK_FLAG_OFFSET) = 0; // init flag to zero

    LOG_INF << fname << "PSK prepared in shared memory successfully";

    m_shmPtr = shmPtr;
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

    if (m_shmPtr && munmap(m_shmPtr, PSK_SHM_TOTAL_SIZE) == 0)
    {
        shm_unlink(m_shmName.c_str());
        LOG_INF << fname << "Cleaned shared memory address: " << m_shmPtr;
        m_shmPtr = nullptr;
        return true;
    }
    if (m_shmPtr)
    {
        LOG_WAR << fname << "munmap failed with error: " << std::strerror(errno);
    }
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

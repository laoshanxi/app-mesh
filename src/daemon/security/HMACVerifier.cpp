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
#include "SharedMemory.hpp"

HMACVerifier::HMACVerifier()
    : m_psk(generatePassword(PSK_MSG_LENGTH, true, true, true, true))
{
}

HMACVerifier::~HMACVerifier()
{
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

    m_shmPtr = std::make_shared<SharedMemory>();
    if (m_shmPtr->create())
    {
        m_shmPtr->writeData(m_psk.data());
        m_shmPtr->exportEnv(ENV_PSK_SHM);
        LOG_INF << fname << "PSK prepared in shared memory successfully";
        return true;
    }
    else
    {
        LOG_ERR << fname << "Failed to create shared memory for PSK";
        return false;
    }
}

bool HMACVerifier::waitPSKRead()
{
    const static char fname[] = "HMACVerifier::waitPSKRead() ";

    if (!m_shmPtr)
    {
        LOG_ERR << fname << "Shared memory pointer is not initialized";
        return false;
    }

    bool result = m_shmPtr->waitForFlag(10); // Wait for the flag to be set by the child process
    m_shmPtr->cleanup();                     // Clear the shared memory pointer after reading
    return result;
}

const std::string HMACVerifier::getShmName()
{
    const static char fname[] = "HMACVerifier::getShmName() ";

    if (!m_shmPtr)
    {
        LOG_ERR << fname << "Shared memory pointer is not initialized";
        return "";
    }
    return Utility::stdStringTrim(m_shmPtr->shmName(), "/");
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

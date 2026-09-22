// src/daemon/security/HMACVerifier.cpp
#include <openssl/hmac.h>
#include <chrono>
#include <sstream>

#include "../../common/Password.h"
#include "../../common/Utility.h"
#include "HMACVerifier.h"
#include "SharedMemory.h"

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
    return Utility::secureCompare(generateHMAC(message), receivedHmac);
}

std::string HMACVerifier::writePSKToSHM(const std::string &execUser)
{
    const static char fname[] = "HMACVerifier::writePSKToSHM() ";

    m_shmPtr = std::make_shared<SharedMemory>();
    if (m_shmPtr->create() && m_shmPtr->changeOwner(execUser))
    {
        m_shmPtr->writeData(m_psk.data());
        LOG_INF << fname << "PSK prepared in shared memory successfully";
        return m_shmPtr->shmPath();
    }
    else
    {
        LOG_ERR << fname << "Failed to create shared memory for PSK";
        m_shmPtr.reset();
        return "";
    }
}

bool HMACVerifier::waitPSKRead()
{
    const static char fname[] = "HMACVerifier::waitPSKRead() ";

    if (m_readResult.valid())
    {
        return m_readResult.get();
    }
    if (!m_shmPtr)
    {
        LOG_ERR << fname << "Shared memory pointer is not initialized";
        return false;
    }

    bool result = m_shmPtr->waitForFlag(10); // Wait for the flag to be set by the child process
    m_shmPtr->cleanup();                     // Clear the shared memory pointer after reading
    return result;
}

void HMACVerifier::waitPSKReadAsync()
{
    const static char fname[] = "HMACVerifier::waitPSKReadAsync() ";

    // Snapshot and release the SHM so a later writePSKToSHM never races this round's
    // wait/cleanup; the wait runs on the timer thread to keep the caller's thread free.
    auto shm = m_shmPtr;
    m_shmPtr.reset();
    if (!shm)
    {
        LOG_ERR << fname << "Shared memory pointer is not initialized";
        return;
    }

    // A recurring timer polls the flag with a non-blocking check, so the
    // timer-dispatch thread is never stalled; the promise carries the outcome to
    // a later waitPSKRead() call. The timer event holds this object alive until
    // the wait completes or times out.
    auto readResult = std::make_shared<std::promise<bool>>();
    m_readResult = readResult->get_future().share();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    const auto timerId = registerTimer(100, 100, fname, [shm, readResult, deadline]() {
        const static char timerFname[] = "HMACVerifier::waitPSKReadAsync() ";
        if (shm->isFlagSet())
        {
            shm->cleanup();
            readResult->set_value(true);
            return false;
        }
        if (std::chrono::steady_clock::now() > deadline)
        {
            LOG_WAR << timerFname << "Timed out waiting for flag after <10> seconds";
            shm->cleanup();
            readResult->set_value(false);
            return false;
        }
        return true;
    });
    if (!isValidTimerId(timerId))
    {
        shm->cleanup();
        readResult->set_value(false);
    }
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

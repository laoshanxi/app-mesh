#pragma once

#include <string>

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>

#define HMAC_HTTP_HEADER "X-Request-HMAC"
#define PSK_LENGTH 32
#define PSK_SHM_ENV "SHM_NAME"
#define PSK_FLAG_OFFSET (PSK_LENGTH + 1)
#define PSK_SHM_TOTAL_SIZE (PSK_LENGTH + 2) // PSK + null terminator + flag

#ifdef _WIN32
class ACE_Shared_Memory_MM; // Forward declaration
#endif

/*
Hash-based Message Authentication Code
*/
class HMACVerifier
{
public:
    HMACVerifier();
    ~HMACVerifier();

    std::string generateHMAC(const std::string &message) const;
    bool verifyHMAC(const std::string &message, const std::string &receivedHmac) const;

    // Pre-Shared-Key operations
    bool writePSKToSHM();
    bool waitPSKRead();
    const std::string &getShmName() const noexcept;
    bool cleanupSharedMemory();

private:
    static std::string bytesToHex(const unsigned char *data, size_t len);

private:
    const std::string m_shmName;
    const std::string m_psk;

    void *m_shmPtr;

#ifdef _WIN32
    ACE_Shared_Memory_MM *m_aceShm;
#endif

    HMACVerifier(const HMACVerifier &) = delete;
    HMACVerifier &operator=(const HMACVerifier &) = delete;
    HMACVerifier(HMACVerifier &&) = delete;
    HMACVerifier &operator=(HMACVerifier &&) = delete;

    friend class ACE_Singleton<HMACVerifier, ACE_Null_Mutex>;
};

typedef ACE_Singleton<HMACVerifier, ACE_Null_Mutex> HMACVerifierSingleton;

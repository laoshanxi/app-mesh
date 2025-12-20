// src/daemon/security/HMACVerifier.h
#pragma once

#include <memory>
#include <string>

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>

#define HMAC_HTTP_HEADER "X-Request-HMAC"
#define ENV_PSK_SHM "PSK_SHM_NAME"

class SharedMemory;

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
    std::string writePSKToSHM();
    bool waitPSKRead();
    const std::string getShmName();

private:
    static std::string bytesToHex(const unsigned char *data, size_t len);

private:
    const std::string m_psk;

    std::shared_ptr<SharedMemory> m_shmPtr;

    HMACVerifier(const HMACVerifier &) = delete;
    HMACVerifier &operator=(const HMACVerifier &) = delete;
    HMACVerifier(HMACVerifier &&) = delete;
    HMACVerifier &operator=(HMACVerifier &&) = delete;

    friend class ACE_Singleton<HMACVerifier, ACE_Null_Mutex>;
};

typedef ACE_Singleton<HMACVerifier, ACE_Null_Mutex> HMACVerifierSingleton;

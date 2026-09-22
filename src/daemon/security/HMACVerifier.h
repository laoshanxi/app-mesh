// src/daemon/security/HMACVerifier.h
#pragma once

#include <future>
#include <memory>
#include <string>

#include "../../common/TimerHandler.h"

#define HMAC_HTTP_HEADER "X-Request-HMAC"
#define ENV_PSK_SHM "PSK_SHM_NAME"

class SharedMemory;

/*
Hash-based Message Authentication Code.

One instance per managed system process spawn: the constructor generates a
fresh pre-shared key, so a restart always proves itself with a new key.
*/
class HMACVerifier : public TimerHandler
{
public:
    HMACVerifier();
    ~HMACVerifier();

    std::string generateHMAC(const std::string &message) const;
    bool verifyHMAC(const std::string &message, const std::string &receivedHmac) const;

    // Pre-Shared-Key operations
    // Returns the absolute path of the segment holding the key, for export to
    // the child via ENV_PSK_SHM (empty on failure).
    // execUser: when non-empty, the shared memory segment is handed to that
    // user so a child running under it can read the key.
    std::string writePSKToSHM(const std::string &execUser = "");
    bool waitPSKRead();      // blocking; after waitPSKReadAsync it reports the async result instead
    void waitPSKReadAsync(); // polls on the timer thread; for restart paths that must not block the caller

private:
    static std::string bytesToHex(const unsigned char *data, size_t len);

private:
    const std::string m_psk;

    std::shared_ptr<SharedMemory> m_shmPtr;
    std::shared_future<bool> m_readResult;

    HMACVerifier(const HMACVerifier &) = delete;
    HMACVerifier &operator=(const HMACVerifier &) = delete;
    HMACVerifier(HMACVerifier &&) = delete;
    HMACVerifier &operator=(HMACVerifier &&) = delete;
};

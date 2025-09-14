#pragma once

#include <atomic>
#include <memory>
#include <string>

#include <ace/Shared_Memory_MM.h>

#define PSK_MSG_LENGTH 32
#define PSK_FLAG_OFFSET 64
#define PSK_SHM_TOTAL_SIZE 128

struct psk_shared_memory_t
{
    char message[PSK_FLAG_OFFSET]; // 32 char + 32 buffer
    std::atomic<int32_t> flag;
};

class SharedMemory
{
public:
    SharedMemory();
    ~SharedMemory();

    SharedMemory(const SharedMemory &) = delete;
    SharedMemory &operator=(const SharedMemory &) = delete;
    SharedMemory(SharedMemory &&) = delete;
    SharedMemory &operator=(SharedMemory &&) = delete;

    bool create();
    bool waitForFlag(int timeoutSeconds = 10);
    bool writeData(const char *data);
    const char *readData() const;
    void writeFlag();
    std::string shmName() const;
    void cleanup();
    void exportEnv(const std::string &envName);

private:
    std::string m_shmName;
    std::shared_ptr<class ACE_Shared_Memory_MM> m_aceShm;
    psk_shared_memory_t *m_shmPtr;

    static std::string GetSharedMemoryName();
};
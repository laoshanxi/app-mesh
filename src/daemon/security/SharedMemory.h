// src/daemon/security/SharedMemory.h
#pragma once

#include <atomic>
#include <memory>
#include <string>

// File-backed mapping shared with the child processes (Go agent, workflow
// engine); they open the exported path and mmap the same 128 bytes.
namespace boost::interprocess
{
	class file_mapping;
	class mapped_region;
}

#define PSK_MSG_LENGTH 32
#define PSK_FLAG_OFFSET 64
#define PSK_SHM_TOTAL_SIZE 128

struct PskSharedMemory
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
	// Gives the segment file to the process user so a child running under a
	// different exec user can read it. No-op success for an empty user.
	bool changeOwner(const std::string &user);
	// Non-blocking check; true once the child process has read the key.
	bool isFlagSet() const;
	bool waitForFlag(int timeoutSeconds = 10);
	bool writeData(const char *data);
	const char *readData() const;
	void writeFlag();
	// Absolute path of the segment file, for environment export to the child.
	const std::string &shmPath() const;
	void cleanup();

private:
	std::string m_shmName;
	std::string m_shmPath;
	std::unique_ptr<boost::interprocess::file_mapping> m_mapping;
	std::unique_ptr<boost::interprocess::mapped_region> m_region;
	PskSharedMemory *m_shmPtr{nullptr};

	static std::string generateSharedMemoryName();
};

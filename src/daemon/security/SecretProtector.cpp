#include "SecretProtector.h"

#include "../../common/Utility.h"
#include "../../common/os/filesystem.h"
#include "../Configuration.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <stdexcept>

#include <ace/OS.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace
{
	const char *MASTER_KEY_FILE_ENV = "APPMESH_SECRET_MASTER_KEY_FILE";
	const char *MASTER_KEY_FILE_NAME = "secret-master-key";
	const char *FORMAT_PREFIX = "sp1:";
	const size_t KEY_SIZE = 32;
	const size_t NONCE_SIZE = 12;
	const size_t TAG_SIZE = 16;
	const size_t MAX_ENCODED_KEY_FILE_SIZE = 4096;
}

SecretProtector &SecretProtector::instance()
{
	static SecretProtector protector;
	return protector;
}

void SecretProtector::initialize()
{
	ensureKey();
}

void SecretProtector::ensureKey()
{
	std::lock_guard<std::mutex> guard(m_mutex);
	if (!m_key.empty())
		return;

	const auto keyFile = masterKeyFile();
	std::string encoded;
	try
	{
		encoded = readSecureKeyFile(keyFile);
	}
	catch (const NotFoundException &)
	{
		std::vector<unsigned char> generated(KEY_SIZE);
		if (RAND_bytes(generated.data(), static_cast<int>(generated.size())) != 1)
			throw std::runtime_error("failed to generate SecretProtector master key");
		const std::string raw(reinterpret_cast<const char *>(generated.data()), generated.size());
		const auto candidate = Utility::encode64(raw);
		OPENSSL_cleanse(generated.data(), generated.size());
		publishKeyFile(keyFile, candidate);
		encoded = readSecureKeyFile(keyFile);
	}

	m_key = decodeBase64(encoded);
	OPENSSL_cleanse(encoded.data(), encoded.size());
	if (m_key.size() != KEY_SIZE)
	{
		OPENSSL_cleanse(m_key.data(), m_key.size());
		m_key.clear();
		throw std::runtime_error("SecretProtector master key must decode to 32 bytes");
	}
}

std::string SecretProtector::masterKeyFile()
{
	if (const char *value = std::getenv(MASTER_KEY_FILE_ENV))
	{
		const auto configured = Utility::stdStringTrim(value);
		if (!configured.empty())
		{
			if (!fs::path(configured).is_absolute())
				throw std::invalid_argument("APPMESH_SECRET_MASTER_KEY_FILE must be an absolute path");
			return configured;
		}
	}
	const auto config = Configuration::instance();
	if (!config)
		throw std::logic_error("SecretProtector requires initialized daemon configuration");
	return (fs::path(config->getWorkDir()) / "auth" / "secrets" / MASTER_KEY_FILE_NAME).string();
}

std::string SecretProtector::readSecureKeyFile(const std::string &path)
{
#if defined(_WIN32)
	boost::system::error_code ec;
	const auto status = fs::symlink_status(path, ec);
	if (ec || !fs::exists(status))
		throw NotFoundException("SecretProtector master key file does not exist");
	if (fs::is_symlink(status) || !fs::is_regular_file(status))
		throw std::runtime_error("SecretProtector master key path must be a regular non-link file");
	const auto value = Utility::readFileCpp(path);
	if (value.size() > MAX_ENCODED_KEY_FILE_SIZE)
		throw std::runtime_error("SecretProtector master key file is unexpectedly large");
	return Utility::stdStringTrim(value);
#else
	const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
	{
		if (errno == ENOENT)
			throw NotFoundException("SecretProtector master key file does not exist");
		throw std::runtime_error(std::string("failed to open SecretProtector master key file: ") + std::strerror(errno));
	}
	struct stat status = {};
	if (::fstat(fd, &status) != 0)
	{
		const auto error = errno;
		::close(fd);
		throw std::runtime_error(std::string("failed to stat SecretProtector master key file: ") + std::strerror(error));
	}
	if (!S_ISREG(status.st_mode) || status.st_uid != ::geteuid() || (status.st_mode & 0077) != 0)
	{
		::close(fd);
		throw std::runtime_error("SecretProtector master key must be a regular owner-only file owned by the daemon user");
	}
	if (status.st_size <= 0 || static_cast<size_t>(status.st_size) > MAX_ENCODED_KEY_FILE_SIZE)
	{
		::close(fd);
		throw std::runtime_error("SecretProtector master key file has an invalid size");
	}
	std::string value(static_cast<size_t>(status.st_size), '\0');
	size_t offset = 0;
	while (offset < value.size())
	{
		const auto count = ::read(fd, &value[offset], value.size() - offset);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
		{
			const auto error = errno;
			::close(fd);
			throw std::runtime_error(std::string("failed to read SecretProtector master key file: ") + std::strerror(error));
		}
		offset += static_cast<size_t>(count);
	}
	::close(fd);
	return Utility::stdStringTrim(value);
#endif
}

void SecretProtector::publishKeyFile(const std::string &path, const std::string &encoded)
{
	const auto directory = fs::path(path).parent_path();
	if (!Utility::createDirectory(directory.string(), fs::perms::owner_all))
		throw std::runtime_error("failed to create SecretProtector key directory");
#if !defined(_WIN32)
	if (!os::fileChmod(directory.string(), 0700))
		throw std::runtime_error("failed to secure SecretProtector key directory");
#endif
	const auto temporary = os::createTmpFile(path, encoded + "\n", 0600);
	if (temporary.empty())
		throw std::runtime_error("failed to create temporary SecretProtector master key");

#if defined(_WIN32)
	if (!::MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH))
	{
		const auto error = ::GetLastError();
		Utility::removeFile(temporary);
		if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS)
			throw std::runtime_error("failed to atomically publish SecretProtector master key");
	}
#else
	// link(2) publishes the completely written temporary inode only when the
	// destination does not exist. A concurrent daemon therefore cannot replace a
	// key another process has already committed.
	if (::link(temporary.c_str(), path.c_str()) != 0 && errno != EEXIST)
	{
		const auto error = errno;
		Utility::removeFile(temporary);
		throw std::runtime_error(std::string("failed to atomically publish SecretProtector master key: ") + std::strerror(error));
	}
	Utility::removeFile(temporary);
	const int directoryFd = ::open(directory.string().c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
	if (directoryFd >= 0)
	{
		::fsync(directoryFd);
		::close(directoryFd);
	}
#endif
}

std::string SecretProtector::protect(const std::string &plaintext, const std::string &context)
{
	ensureKey();
	std::vector<unsigned char> nonce(NONCE_SIZE);
	if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
		throw std::runtime_error("failed to generate SecretProtector nonce");
	std::vector<unsigned char> cipher(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
	std::vector<unsigned char> tag(TAG_SIZE);
	int length = 0;
	int total = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		throw std::runtime_error("failed to create SecretProtector cipher context");
	const bool ok =
		EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
		EVP_EncryptInit_ex(ctx, nullptr, nullptr, m_key.data(), nonce.data()) == 1 &&
		EVP_EncryptUpdate(ctx, nullptr, &length,
			reinterpret_cast<const unsigned char *>(context.data()), static_cast<int>(context.size())) == 1 &&
		EVP_EncryptUpdate(ctx, cipher.data(), &length,
			reinterpret_cast<const unsigned char *>(plaintext.data()), static_cast<int>(plaintext.size())) == 1;
	total = length;
	const bool finalized = ok && EVP_EncryptFinal_ex(ctx, cipher.data() + total, &length) == 1;
	total += length;
	const bool tagged = finalized && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
		static_cast<int>(tag.size()), tag.data()) == 1;
	EVP_CIPHER_CTX_free(ctx);
	if (!tagged)
		throw std::runtime_error("failed to encrypt application secret");
	cipher.resize(static_cast<size_t>(total));

	std::string payload(reinterpret_cast<const char *>(nonce.data()), nonce.size());
	payload.append(reinterpret_cast<const char *>(tag.data()), tag.size());
	payload.append(reinterpret_cast<const char *>(cipher.data()), cipher.size());
	return std::string(FORMAT_PREFIX) + Utility::encode64(payload);
}

std::string SecretProtector::unprotect(const std::string &ciphertext, const std::string &context)
{
	ensureKey();
	if (!Utility::startWith(ciphertext, FORMAT_PREFIX))
		throw std::invalid_argument("unsupported SecretProtector ciphertext format");
	const auto payload = decodeBase64(ciphertext.substr(std::char_traits<char>::length(FORMAT_PREFIX)));
	if (payload.size() < NONCE_SIZE + TAG_SIZE)
		throw std::invalid_argument("SecretProtector ciphertext is truncated");
	const unsigned char *nonce = payload.data();
	const unsigned char *tag = payload.data() + NONCE_SIZE;
	const unsigned char *encrypted = payload.data() + NONCE_SIZE + TAG_SIZE;
	const size_t encryptedSize = payload.size() - NONCE_SIZE - TAG_SIZE;
	std::vector<unsigned char> plain(encryptedSize + EVP_MAX_BLOCK_LENGTH);
	int length = 0;
	int total = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		throw std::runtime_error("failed to create SecretProtector cipher context");
	const bool ok =
		EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) == 1 &&
		EVP_DecryptInit_ex(ctx, nullptr, nullptr, m_key.data(), nonce) == 1 &&
		EVP_DecryptUpdate(ctx, nullptr, &length,
			reinterpret_cast<const unsigned char *>(context.data()), static_cast<int>(context.size())) == 1 &&
		EVP_DecryptUpdate(ctx, plain.data(), &length, encrypted, static_cast<int>(encryptedSize)) == 1;
	total = length;
	const bool tagged = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
		const_cast<unsigned char *>(tag)) == 1;
	const bool finalized = tagged && EVP_DecryptFinal_ex(ctx, plain.data() + total, &length) == 1;
	total += length;
	EVP_CIPHER_CTX_free(ctx);
	if (!finalized)
		throw std::domain_error("application secret authentication failed");
	return std::string(reinterpret_cast<const char *>(plain.data()), static_cast<size_t>(total));
}

std::vector<unsigned char> SecretProtector::decodeBase64(const std::string &value)
{
	if (value.empty() || value.size() % 4 != 0)
		throw std::invalid_argument("invalid base64 SecretProtector value");
	std::vector<unsigned char> decoded((value.size() / 4) * 3 + 1);
	const int length = EVP_DecodeBlock(decoded.data(),
		reinterpret_cast<const unsigned char *>(value.data()), static_cast<int>(value.size()));
	if (length < 0)
		throw std::invalid_argument("invalid base64 SecretProtector value");
	size_t padding = 0;
	if (value[value.size() - 1] == '=')
		++padding;
	if (value.size() > 1 && value[value.size() - 2] == '=')
		++padding;
	decoded.resize(static_cast<size_t>(length) - padding);
	return decoded;
}

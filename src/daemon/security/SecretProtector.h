#pragma once

#include <mutex>
#include <string>
#include <vector>

/// Encrypts persisted application secrets with node/cluster master key material. Identity
/// passwords and Principal records never participate in encryption key derivation.
class SecretProtector
{
public:
	static SecretProtector &instance();

	/// Load or atomically provision the node-local master key. Calling this during
	/// daemon startup makes key/permission failures fatal before applications are
	/// recovered.
	void initialize();
	std::string protect(const std::string &plaintext, const std::string &context);
	std::string unprotect(const std::string &ciphertext, const std::string &context);

private:
	SecretProtector() = default;
	void ensureKey();
	static std::string masterKeyFile();
	static std::string readSecureKeyFile(const std::string &path);
	static void publishKeyFile(const std::string &path, const std::string &encoded);
	static std::vector<unsigned char> decodeBase64(const std::string &value);

	std::vector<unsigned char> m_key;
	std::mutex m_mutex;
};

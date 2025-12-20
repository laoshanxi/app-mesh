// src/daemon/security/User.cpp
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// OpenSSL (TOTP)
#include <openssl/evp.h>
#include <openssl/hmac.h>

// OpenSSL (Encrypt)
#include <cryptopp/aes.h>
#include <cryptopp/default.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include "../../common/Password.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.h"
#include "../Configuration.h"
#include "Security.h"
#include "User.h"

//////////////////////////////////////////////////////////////////////
/// Users
//////////////////////////////////////////////////////////////////////
nlohmann::json Users::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	nlohmann::json result = nlohmann::json::object();
	for (auto &user : m_users)
	{
		result[user.first] = user.second->AsJson();
	}
	return result;
}

std::shared_ptr<Users> Users::FromJson(const nlohmann::json &obj, std::shared_ptr<Roles> roles)
{
	std::shared_ptr<Users> users = std::make_shared<Users>();
	for (auto &user : obj.items())
	{
		const auto &name = user.key();
		users->m_users[name] = User::FromJson(name, user.value(), roles);
	}
	return users;
}

std::map<std::string, std::shared_ptr<User>> Users::getUsers()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_users;
}

std::shared_ptr<User> Users::getUser(std::string name) const
{
	const static char fname[] = "Users::getUser() ";
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto user = m_users.find(name);
	if (user != m_users.end())
	{
		return user->second;
	}
	else
	{
		LOG_WAR << fname << "no such user: " << name;
		throw NotFoundException("no such user");
	}
}

std::set<std::string> Users::getGroups() const
{
	std::set<std::string> result;
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	for (const auto &usr : m_users)
	{
		if (usr.second->getGroup().length())
			result.insert(usr.second->getGroup());
	}
	return result;
}

void Users::addUsers(const nlohmann::json &obj, std::shared_ptr<Roles> roles)
{
	if (!obj.is_null() && obj.is_object())
	{
		for (auto &userJson : obj.items())
		{
			addUser((userJson.key()), userJson.value(), roles);
		}
	}
	else
	{
		throw std::invalid_argument("incorrect user json section");
	}
}

std::shared_ptr<User> Users::addUser(const std::string &userName, const nlohmann::json &userJson, std::shared_ptr<Roles> roles)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto user = User::FromJson(userName, userJson, roles);

	if (m_users.count(userName))
	{
		// update
		m_users[userName]->updateUser(user);
	}
	else
	{
		if (user->getKey().empty())
		{
			throw std::invalid_argument("no password provided");
		}
		// insert
		m_users[userName] = user;
	}
	user->updateKey(user->getKey());
	return user;
}

void Users::delUser(const std::string &name)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	getUser(name);
	m_users.erase(name);
}

//////////////////////////////////////////////////////////////////////
/// User
//////////////////////////////////////////////////////////////////////
User::User(const std::string &name) : m_locked(false), m_enableMfa(false), m_name(name)
{
}

nlohmann::json &User::clearConfidentialInfo(nlohmann::json &userJson)
{
	if (HAS_JSON_FIELD(userJson, JSON_KEY_USER_key))
		userJson.erase(JSON_KEY_USER_key);
	if (HAS_JSON_FIELD(userJson, JSON_KEY_USER_mfa_key))
		userJson.erase(JSON_KEY_USER_mfa_key);
	return userJson;
}

nlohmann::json User::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	nlohmann::json result = nlohmann::json::object();

	result[JSON_KEY_USER_readonly_name] = std::string(m_name);
	result[JSON_KEY_USER_key] = std::string(m_key);
	result[JSON_KEY_USER_email] = std::string(m_email);
	result[JSON_KEY_USER_group] = std::string(m_group);
	result[JSON_KEY_USER_exec_user] = getExecUserOverride();
	result[JSON_KEY_USER_locked] = (m_locked);
	result[JSON_KEY_USER_mfa_enabled] = (m_enableMfa);
	if (!m_metadata.empty())
		result[JSON_KEY_USER_metadata] = std::string(m_metadata);
	if (!m_mfaKey.empty())
		result[JSON_KEY_USER_mfa_key] = std::string(m_mfaKey);
	auto roles = nlohmann::json::array();
	for (auto &role : m_roles)
	{
		roles.push_back(std::string(role->getName()));
	}
	result[JSON_KEY_USER_roles] = std::move(roles);
	return result;
}

std::shared_ptr<User> User::FromJson(const std::string &userName, const nlohmann::json &obj, const std::shared_ptr<Roles> roles)
{
	std::shared_ptr<User> result;
	if (!obj.is_null())
	{
		result = std::make_shared<User>(userName);
		result->m_key = GET_JSON_STR_INT_TEXT(obj, JSON_KEY_USER_key);
		result->m_email = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_email);
		result->m_group = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_group);
		result->m_execUser = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_exec_user);
		result->m_metadata = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_metadata);
		result->m_mfaKey = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_mfa_key);
		result->m_locked = GET_JSON_BOOL_VALUE(obj, JSON_KEY_USER_locked);
		result->m_enableMfa = GET_JSON_BOOL_VALUE(obj, JSON_KEY_USER_mfa_enabled);
		if (HAS_JSON_FIELD(obj, JSON_KEY_USER_roles))
		{
			for (auto &jsonRole : obj.at(JSON_KEY_USER_roles).items())
				result->m_roles.insert(roles->getRole(jsonRole.value().get<std::string>()));
		}
	}
	return result;
}

void User::lock()
{
	this->m_locked = true;
}

void User::unlock()
{
	this->m_locked = false;
}

void User::updateUser(std::shared_ptr<User> user)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	this->m_roles = user->m_roles;
	this->m_execUser = user->m_execUser;
	this->m_group = user->m_group;
	this->m_metadata = user->m_metadata;
	// this->m_mfaKey = user->m_mfaKey;
	// this->m_key = user->m_key;
	this->m_locked = user->m_locked;
	this->m_enableMfa = user->m_enableMfa;
	this->m_email = user->m_email;
}

void User::updateKey(const std::string &passwd)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (Security::instance()->encryptKey())
	{
		m_key = Utility::hash(passwd);
	}
	else
	{
		m_key = passwd;
	}
}

void User::totpActive(bool active)
{
	m_enableMfa = active;
}

void User::totpDeactive()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_mfaKey.clear();
	m_enableMfa = false;
}
constexpr char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// decode base32 (RFC 4648, uppercase, no padding required). Returns true on success, false on invalid char.
bool base32Decode(const std::string &in, std::vector<uint8_t> &out)
{
	out.clear();
	// Mapping table: ASCII -> value or 0xFF if invalid
	static uint8_t map[256];
	static bool init = false;
	if (!init)
	{
		for (size_t i = 0; i < sizeof(map); ++i)
			map[i] = 0xFF;
		for (uint8_t i = 0; i < 32; ++i)
		{
			map[static_cast<unsigned char>(BASE32_ALPHABET[i])] = i;
			// also accept lowercase
			map[static_cast<unsigned char>(std::tolower(BASE32_ALPHABET[i]))] = i;
		}
		// optionally accept '=' as padding (map to 0xFE to skip)
		map[static_cast<unsigned char>('=')] = 0xFE;
		init = true;
	}

	uint32_t buffer = 0;
	int bitsLeft = 0;
	for (size_t i = 0; i < in.size(); ++i)
	{
		unsigned char ch = static_cast<unsigned char>(in[i]);
		uint8_t val = map[ch];
		if (val == 0xFF)
		{
			// ignore whitespace
			if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
				continue;
			return false; // invalid character
		}
		if (val == 0xFE)
		{
			// padding - stop processing further meaningful characters
			break;
		}

		buffer = (buffer << 5) | val;
		bitsLeft += 5;
		if (bitsLeft >= 8)
		{
			bitsLeft -= 8;
			uint8_t byte = static_cast<uint8_t>((buffer >> bitsLeft) & 0xFF);
			out.push_back(byte);
		}
	}

	return true;
}

// Generate HOTP per RFC 4226 (HMAC-SHA1) and return numeric code as integer
// key: raw secret bytes
// keyLen: length of secret bytes
// counter: 64-bit moving factor
// digits: number of digits (commonly 6)
uint32_t hotp_truncate_and_digits(const uint8_t *key, size_t keyLen, uint64_t counter, unsigned digits = 6)
{
	// counter big-endian 8 bytes
	uint8_t counterBytes[8];
	for (int i = 7; i >= 0; --i)
	{
		counterBytes[i] = static_cast<uint8_t>(counter & 0xFF);
		counter >>= 8;
	}

	unsigned int hmacLen = EVP_MAX_MD_SIZE;
	uint8_t hmacResult[EVP_MAX_MD_SIZE];

	// HMAC-SHA1
	unsigned char *hres = HMAC(EVP_sha1(),
							   key, static_cast<int>(keyLen),
							   counterBytes, sizeof(counterBytes),
							   hmacResult, &hmacLen);
	if (!hres || hmacLen < 20)
	{
		// HMAC failed; treat as zero code (caller will treat as mismatch)
		return UINT32_MAX; // sentinel indicating error
	}

	// dynamic truncation
	int offset = hmacResult[hmacLen - 1] & 0x0F;
	uint32_t binary =
		((static_cast<uint32_t>(hmacResult[offset]) & 0x7F) << 24) |
		((static_cast<uint32_t>(hmacResult[offset + 1]) & 0xFF) << 16) |
		((static_cast<uint32_t>(hmacResult[offset + 2]) & 0xFF) << 8) |
		((static_cast<uint32_t>(hmacResult[offset + 3]) & 0xFF));

	uint32_t mod = 1;
	for (unsigned i = 0; i < digits; ++i)
		mod *= 10u;
	return binary % mod;
}

// Convert integer to zero-padded string with width = digits
std::string intToZeroPadded(uint32_t v, unsigned digits)
{
	std::ostringstream oss;
	oss << std::setw(static_cast<int>(digits)) << std::setfill('0') << v;
	return oss.str();
}

const std::string User::totpGenerateKey()
{
	const static char fname[] = "User::totpGenerateKey() ";

	// Generate 32 random bytes (256 bits entropy)
	std::random_device rd;
	std::uniform_int_distribution<unsigned int> dist(0, 255);
	std::vector<uint8_t> randomBytes(32);
	for (auto &b : randomBytes)
	{
		b = static_cast<uint8_t>(dist(rd));
	}

	// RFC 4648 Base32 alphabet (uppercase, no padding)
	std::string base32Result;
	base32Result.reserve(52); // max possible output from 32 bytes

	const uint8_t *buffer = randomBytes.data();
	size_t bufferSize = randomBytes.size();
	size_t bits = 0;
	uint32_t value = 0;

	// Process input in 5-byte blocks (40 bits => 8 Base32 characters)
	for (size_t i = 0; i < bufferSize; ++i)
	{
		value = (value << 8) | buffer[i];
		bits += 8;
		while (bits >= 5)
		{
			bits -= 5;
			base32Result.push_back(BASE32_ALPHABET[(value >> bits) & 0x1F]);
		}
	}
	if (bits > 0)
	{
		base32Result.push_back(BASE32_ALPHABET[(value << (5 - bits)) & 0x1F]);
	}

	// Normalize length to 32 characters
	constexpr size_t desiredLength = 32;
	if (base32Result.size() > desiredLength)
	{
		base32Result.resize(desiredLength);
	}
	else if (base32Result.size() < desiredLength)
	{
		// Should not occur with 32 input bytes, but pad with 'A' (zero) if needed
		base32Result.append(desiredLength - base32Result.size(), 'A');
	}

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_mfaKey = base32Result;

	LOG_INF << fname << "2FA TOTP secret generated for user: " << m_name;
	return m_mfaKey;
}

bool User::totpValidateCode(const std::string &totpCode)
{
	const static char fname[] = "User::totpValidateCode() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);

	// Decode base32 secret
	std::vector<uint8_t> keyBytes;
	if (!base32Decode(m_mfaKey, keyBytes))
	{
		LOG_WAR << fname << "base32 decode failed for key";
		throw std::domain_error(Utility::stringFormat("Failed to base32 decode TOTP key"));
	}
	if (keyBytes.empty())
	{
		LOG_WAR << fname << "decoded key empty";
		throw std::domain_error(Utility::stringFormat("Decoded TOTP key empty"));
	}

	constexpr int totp_time_duration_seconds = 30;
	constexpr unsigned totp_digits = 6;
	// Accept +/- 1 time-step (window = 1)
	constexpr int window = 1;

	std::time_t now = std::time(nullptr);
	if (now < 0)
	{
		LOG_WAR << fname << "time() failed";
		throw std::domain_error(Utility::stringFormat("Failed to get current time"));
	}

	uint64_t t = static_cast<uint64_t>(now) / totp_time_duration_seconds;

	bool matched = false;
	for (int i = -window; i <= window && !matched; ++i)
	{
		uint64_t counter = static_cast<uint64_t>(static_cast<int64_t>(t) + i);
		uint32_t code = hotp_truncate_and_digits(keyBytes.data(), keyBytes.size(), counter, totp_digits);
		if (code == UINT32_MAX) // HMAC error
		{
			LOG_WAR << fname << "HMAC computation failed";
			throw std::domain_error(Utility::stringFormat("HMAC computation failed during TOTP validation"));
		}
		std::string codeStr = intToZeroPadded(code, totp_digits);
		if (codeStr == totpCode)
		{
			matched = true;
		}
	}

	if (!matched)
	{
		LOG_WAR << fname << "invalid token <" << totpCode << ">";
		throw std::domain_error(Utility::stringFormat("Invalid TOTP token"));
	}

	LOG_INF << fname << "2FA validate success for user: " << m_name;
	return true;
}

const std::string User::totpGenerateChallenge(const std::string &token, const int &timeoutSeconds)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_totpChallenge = token;
	m_totpChallengeExpire = std::chrono::system_clock::now() + std::chrono::seconds(timeoutSeconds);
	return Utility::hash(m_totpChallenge);
}

bool User::totpValidateChallenge(const std::string &totpChallenge, std::string &outToken)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (totpChallenge == Utility::hash(m_totpChallenge))
	{
		if (std::chrono::system_clock::now() < m_totpChallengeExpire)
		{
			outToken = m_totpChallenge;
			return true;
		}
		else
			throw jwt::error::signature_verification_exception(jwt::error::token_verification_error::token_expired);
	}
	throw jwt::error::signature_verification_exception(jwt::error::signature_verification_error::invalid_signature);
}

bool User::locked() const
{
	return m_locked;
}

bool User::mfaEnabled() const
{
	return m_enableMfa;
}

const std::string &User::getKey()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_key;
}

bool User::verifyKey(const std::string &key)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (Security::instance()->encryptKey())
	{
		return m_key == Utility::hash(key);
	}
	return m_key == key;
}

const std::string &User::getMfaKey()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_mfaKey;
}

const std::string User::getExecUserOverride() const
{
	std::string executeUser;
	if (!Configuration::instance()->getDisableExecUser())
	{
		executeUser = getExecUser();
		if (executeUser.empty())
		{
			executeUser = Configuration::instance()->getDefaultExecUser();
		}
	}
	if (executeUser.empty())
		executeUser = os::getUsernameByUid();
	return executeUser;
}

const std::set<std::shared_ptr<Role>> User::getRoles()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_roles;
}

bool User::hasPermission(const std::string &permission)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	for (auto &role : m_roles)
	{
		if (role->hasPermission(permission))
			return true;
	}
	return false;
}

const std::string User::encrypt(const std::string &message)
{
	// https://www.cryptopp.com/wiki/Advanced_Encryption_Standard
	// https://github.com/weidai11/cryptopp/blob/master/Install.txt
	// https://github.com/shanet/Crypto-Example/blob/master/crypto_example.cpp

	// #include <cryptopp/osrng.h>
	//  AutoSeededRandomPool rnd;
	//  Generate a random key
	//  rnd.GenerateBlock(key, key.size());

	using namespace CryptoPP;
	// prepare Key & IV
	SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
	size_t size = 0;
	while (size < key.size())
	{
		for (size_t i = 0; i < m_key.length(); i++)
		{
			key[size++] = m_key[i];
			if (size >= key.size())
			{
				break;
			}
		}
	}

	SecByteBlock iv(AES::BLOCKSIZE);
	size = 0;
	while (size < iv.size())
	{
		for (size_t i = 0; i < m_name.length(); i++)
		{
			iv[size++] = m_name[i];
			if (size >= iv.size())
			{
				break;
			}
		}
	}

	size_t messageLen = std::strlen(message.c_str()) + 1;
	std::shared_ptr<byte> plainText = make_shared_array<byte>(messageLen);

	//////////////////////////////////////////////////////////////////////////
	// Encrypt
	//////////////////////////////////////////////////////////////////////////
	CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
	cfbEncryption.ProcessData(&(*plainText), (const byte *)message.c_str(), messageLen);

	// use base64 for persist
	return Utility::encode64((char *)(&(*plainText)));
}

const std::string User::decrypt(const std::string &encryptedMessage)
{
	using namespace CryptoPP;
	// decode base64
	std::string message = Utility::decode64(encryptedMessage);

	// prepare Key & IV
	SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
	size_t size = 0;
	while (size < key.size())
	{
		for (size_t i = 0; i < m_key.length(); i++)
		{
			key[size++] = m_key[i];
			if (size >= key.size())
			{
				break;
			}
		}
	}

	SecByteBlock iv(AES::BLOCKSIZE);
	size = 0;
	while (size < iv.size())
	{
		for (size_t i = 0; i < m_name.length(); i++)
		{
			iv[size++] = m_name[i];
			if (size >= iv.size())
			{
				break;
			}
		}
	}

	size_t messageLen = std::strlen(message.c_str()) + 1;
	std::shared_ptr<byte> plainText = make_shared_array<byte>(messageLen);

	//////////////////////////////////////////////////////////////////////////
	// Decrypt
	//////////////////////////////////////////////////////////////////////////
	CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
	cfbDecryption.ProcessData(&(*plainText), (const byte *)message.c_str(), messageLen);

	return std::string((char *)(&(*plainText)));
}

//////////////////////////////////////////////////////////////////////////
// JsonSecurity
//////////////////////////////////////////////////////////////////////////
JsonSecurity::JsonSecurity()
	: m_encryptKey(false)
{
	m_roles = std::make_shared<Roles>();
	m_users = std::make_shared<Users>();
}

std::shared_ptr<JsonSecurity> JsonSecurity::FromJson(nlohmann::json &jsonValue)
{
	// Accept ENV override
	Configuration::overrideConfigWithEnv(jsonValue);

	auto security = std::make_shared<JsonSecurity>();
	// Roles
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Roles))
		security->m_roles = Roles::FromJson(jsonValue.at(JSON_KEY_Roles));
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_SECURITY_EncryptKey, security->m_encryptKey);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_JWT_Users))
		security->m_users = Users::FromJson(jsonValue.at(JSON_KEY_JWT_Users), security->m_roles);
	return security;
}

nlohmann::json JsonSecurity::AsJson()
{
	auto result = nlohmann::json::object();
	result[JSON_KEY_SECURITY_EncryptKey] = (m_encryptKey);
	// Users
	result[JSON_KEY_JWT_Users] = m_users->AsJson();
	// Roles
	result[JSON_KEY_Roles] = m_roles->AsJson();
	return result;
}

#include <cryptopp/aes.h>
#include <cryptopp/default.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <liboath/oath.h>

#include "../../common/Utility.h"
#include "Security.h"
#include "User.h"

//////////////////////////////////////////////////////////////////////
/// Users
//////////////////////////////////////////////////////////////////////
Users::Users()
{
}

Users::~Users()
{
}

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
		throw std::invalid_argument("no such user");
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

User::~User()
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

	result[JSON_KEY_USER_key] = std::string(m_key);
	result[JSON_KEY_USER_email] = std::string(m_email);
	result[JSON_KEY_USER_group] = std::string(m_group);
	result[JSON_KEY_USER_exec_user] = std::string(m_execUser);
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
		result->m_key = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_key);
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

const std::string User::totpGenerateKey()
{
	const static char fname[] = "User::totpGenerateKey() ";

	char *secret = NULL;
	char randomBuffer[32];
	constexpr int mfaKeyLen = 16;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
	{
		throw std::runtime_error(Utility::stringFormat("Failed to open /dev/urandom: %s", std::strerror(errno)));
	}
	if (read(fd, randomBuffer, sizeof(randomBuffer)) != sizeof(randomBuffer))
	{
		close(fd);
		throw std::runtime_error(Utility::stringFormat("Failed to read /dev/urandom: %s", std::strerror(errno)));
	}
	close(fd);

	// oath_base32_encode(const char *in, size_t inlen, char **out, size_t *outlen);
	auto res = oath_base32_encode(randomBuffer, sizeof(randomBuffer), &secret, NULL);
	std::shared_ptr<char> autoDelete(secret);
	if (res != OATH_OK)
	{
		throw std::runtime_error(Utility::stringFormat("Failed to oath_base32_encode: %s", oath_strerror(res)));
	}

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_mfaKey = secret;
	if (m_mfaKey.length() > mfaKeyLen)
	{
		m_mfaKey = m_mfaKey.substr(0, mfaKeyLen);
	}
	LOG_INF << fname << "2FA secret generated for user: " << m_name;
	return m_mfaKey;
}

bool User::totpValidateCode(const std::string &totpCode)
{
	const static char fname[] = "User::totpValidateCode() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	char *key = NULL;
	size_t keyLen = 0;
	constexpr int totp_time_duration_seconds = 30;
	// int oath_base32_decode(const char *in, size_t inlen, char **out, size_t *outlen);
	int res = oath_base32_decode(m_mfaKey.c_str(), m_mfaKey.length(), &key, &keyLen);
	std::shared_ptr<char> autoDelete(key);
	if (res != OATH_OK)
	{
		LOG_WAR << fname << "oath_base32_decode failed: " << oath_strerror(res);
		throw std::runtime_error(Utility::stringFormat("Failed to oath_base32_decode: %s", oath_strerror(res)));
	}
	res = oath_totp_validate(key, keyLen, time(NULL), totp_time_duration_seconds, 0, 1, totpCode.c_str());
	if (res < 0)
	{
		LOG_WAR << fname << "invalid token <" << totpCode << ">:" << oath_strerror(res);
		throw std::runtime_error(Utility::stringFormat("%s", oath_strerror(res)));
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

const std::string &User::getMfaKey()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_mfaKey;
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

std::shared_ptr<JsonSecurity> JsonSecurity::FromJson(const nlohmann::json &jsonValue)
{
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

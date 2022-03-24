#include <cryptopp/aes.h>
#include <cryptopp/default.h>
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

web::json::value Users::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	web::json::value result = web::json::value::object();
	for (auto user : m_users)
	{
		result[user.first] = user.second->AsJson();
	}
	return result;
}

std::shared_ptr<Users> Users::FromJson(const web::json::value &obj, std::shared_ptr<Roles> roles)
{
	std::shared_ptr<Users> users = std::make_shared<Users>();
	auto jsonOj = obj.as_object();
	for (auto user : jsonOj)
	{
		auto name = GET_STD_STRING(user.first);
		users->m_users[name] = User::FromJson(name, user.second, roles);
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
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto user = m_users.find(name);
	if (user != m_users.end())
	{
		return user->second;
	}
	else
	{
		throw std::invalid_argument(Utility::stringFormat("no such user <%s>", name.c_str()));
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

void Users::addUsers(const web::json::value &obj, std::shared_ptr<Roles> roles)
{
	if (!obj.is_null() && obj.is_object())
	{
		auto users = obj.as_object();
		for (auto userJson : users)
		{
			addUser(GET_STD_STRING(userJson.first), userJson.second, roles);
		}
	}
	else
	{
		throw std::invalid_argument("incorrect user json section");
	}
}

std::shared_ptr<User> Users::addUser(const std::string &userName, const web::json::value &userJson, std::shared_ptr<Roles> roles)
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

web::json::value User::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	web::json::value result = web::json::value::object();

	result[JSON_KEY_USER_key] = web::json::value::string(m_key);
	result[JSON_KEY_USER_email] = web::json::value::string(m_email);
	result[JSON_KEY_USER_group] = web::json::value::string(m_group);
	result[JSON_KEY_USER_exec_user] = web::json::value::string(m_execUser);
	result[JSON_KEY_USER_locked] = web::json::value::boolean(m_locked);
	result[JSON_KEY_USER_mfa_enabled] = web::json::value::boolean(m_enableMfa);
	if (!m_metadata.empty())
		result[JSON_KEY_USER_metadata] = web::json::value::string(m_metadata);
	if (!m_mfaKey.empty())
		result[JSON_KEY_USER_mfa_key] = web::json::value::string(m_mfaKey);
	auto roles = web::json::value::array(m_roles.size());
	int i = 0;
	for (auto role : m_roles)
	{
		roles[i++] = web::json::value::string(role->getName());
	}
	result[JSON_KEY_USER_roles] = roles;
	return result;
}

std::shared_ptr<User> User::FromJson(const std::string &userName, const web::json::value &obj, const std::shared_ptr<Roles> roles)
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
			auto arr = obj.at(JSON_KEY_USER_roles).as_array();
			for (auto jsonRole : arr)
				result->m_roles.insert(roles->getRole(jsonRole.as_string()));
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

const std::string User::generateMfaKey()
{
	const static char fname[] = "User::generateMfaKey() ";

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
	m_enableMfa = true;
	if (m_mfaKey.length() > mfaKeyLen)
	{
		m_mfaKey = m_mfaKey.substr(0, mfaKeyLen);
	}
	LOG_INF << fname << "2FA secret generated for user: " << m_name;
	return m_mfaKey;
}

bool User::validateMfaCode(const std::string &totpCode)
{
	const static char fname[] = "User::validateMfaCode() ";

	if (!m_enableMfa)
	{
		LOG_DBG << fname << "MFA is not enabled for user: " << m_name;
		return true;
	}
	if (m_mfaKey.empty())
	{
		LOG_DBG << fname << "user have not registered 2fa: " << m_name;
		return true;
	}
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

bool User::locked() const
{
	return m_locked;
}

const std::string User::getKey()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_key;
}

const std::set<std::shared_ptr<Role>> User::getRoles()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_roles;
}

bool User::hasPermission(const std::string &permission)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	for (auto role : m_roles)
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

	//#include <cryptopp/osrng.h>
	// AutoSeededRandomPool rnd;
	// Generate a random key
	// rnd.GenerateBlock(key, key.size());

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

std::shared_ptr<JsonSecurity> JsonSecurity::FromJson(const web::json::value &jsonValue)
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

web::json::value JsonSecurity::AsJson()
{
	auto result = web::json::value::object();
	result[JSON_KEY_SECURITY_EncryptKey] = web::json::value::boolean(m_encryptKey);
	// Users
	result[JSON_KEY_JWT_Users] = m_users->AsJson();
	// Roles
	result[JSON_KEY_Roles] = m_roles->AsJson();
	return result;
}

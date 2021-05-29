#include <cryptopp/aes.h>
#include <cryptopp/default.h>

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
User::User(const std::string &name) : m_locked(false), m_name(name)
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
	result[JSON_KEY_USER_group] = web::json::value::string(m_group);
	result[JSON_KEY_USER_exec_user] = web::json::value::string(m_execUser);
	result[JSON_KEY_USER_locked] = web::json::value::boolean(m_locked);
	if (m_metadata.length())
		result[JSON_KEY_USER_metadata] = web::json::value::string(m_metadata);
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
		if (!HAS_JSON_FIELD(obj, JSON_KEY_USER_key))
		{
			throw std::invalid_argument("user should have key attribute");
		}
		result = std::make_shared<User>(userName);
		result->m_key = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_key);
		result->m_group = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_group);
		result->m_execUser = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_exec_user);
		result->m_metadata = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_metadata);
		result->m_locked = GET_JSON_BOOL_VALUE(obj, JSON_KEY_USER_locked);
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
	//this->m_key = user->m_key;
	this->m_locked = user->m_locked;
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
	//AutoSeededRandomPool rnd;
	//Generate a random key
	//rnd.GenerateBlock(key, key.size());

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
	m_jwtUsers = std::make_shared<Users>();
}

std::shared_ptr<JsonSecurity> JsonSecurity::FromJson(const web::json::value &jsonValue)
{
	auto security = std::make_shared<JsonSecurity>();
	// Roles
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Roles))
		security->m_roles = Roles::FromJson(jsonValue.at(JSON_KEY_Roles));
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_SECURITY_EncryptKey, security->m_encryptKey);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_JWT_Users))
		security->m_jwtUsers = Users::FromJson(jsonValue.at(JSON_KEY_JWT_Users), security->m_roles);
	return security;
}

web::json::value JsonSecurity::AsJson()
{
	auto result = web::json::value::object();
	result[JSON_KEY_SECURITY_EncryptKey] = web::json::value::boolean(m_encryptKey);
	// Users
	result[JSON_KEY_JWT_Users] = m_jwtUsers->AsJson();
	// Roles
	result[JSON_KEY_Roles] = m_roles->AsJson();
	return result;
}

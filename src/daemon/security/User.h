#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include <nlohmann/json.hpp>

#include "Role.h"

//////////////////////////////////////////////////////////////////////////
/// User
//////////////////////////////////////////////////////////////////////////
class User
{
public:
	explicit User(const std::string &name);
	virtual ~User() = default;

	// serialize
	nlohmann::json AsJson() const;
	static std::shared_ptr<User> FromJson(const std::string &userName, const nlohmann::json &obj, const std::shared_ptr<Roles> roles) noexcept(false);
	static nlohmann::json &clearConfidentialInfo(nlohmann::json &userJson);

	// user update
	void lock();
	void unlock();
	void updateUser(std::shared_ptr<User> user);
	void updateKey(const std::string &passwd);
	const std::string totpGenerateKey();
	void totpActive(bool active);
	void totpDeactive();
	bool totpValidateCode(const std::string &totpCode);
	const std::string totpGenerateChallenge(const std::string &token, const int &timeoutSeconds);
	bool totpValidateChallenge(const std::string &totpChallenge, std::string &outToken);

	// get user info
	bool locked() const;
	bool mfaEnabled() const;
	const std::string &getKey();
	bool verifyKey(const std::string &key);
	const std::string &getMfaKey();
	const std::string getExecUserOverride() const;
	const std::string &getExecUser() const
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		return m_execUser;
	}
	const std::string &getGroup() const
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		return m_group;
	}
	const std::string &getName() const
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		return m_name;
	}
	const std::set<std::shared_ptr<Role>> getRoles();
	bool hasPermission(const std::string &permission);

	const std::string encrypt(const std::string &msg);
	const std::string decrypt(const std::string &msg);

private:
	std::string m_key;
	bool m_locked;
	bool m_enableMfa;
	std::string m_name;
	std::string m_email;
	std::string m_group;
	std::string m_metadata;
	std::string m_execUser;
	std::string m_mfaKey;
	std::string m_totpChallenge;
	std::chrono::system_clock::time_point m_totpChallengeExpire;
	mutable std::recursive_mutex m_mutex;
	std::set<std::shared_ptr<Role>> m_roles;
};

class Users
{
public:
	Users() = default;
	virtual ~Users() = default;

	nlohmann::json AsJson() const;
	static std::shared_ptr<Users> FromJson(const nlohmann::json &obj, std::shared_ptr<Roles> roles) noexcept(false);

	// find user
	std::map<std::string, std::shared_ptr<User>> getUsers();
	std::shared_ptr<User> getUser(std::string name) const;
	std::set<std::string> getGroups() const;

	// manage users
	void addUsers(const nlohmann::json &obj, std::shared_ptr<Roles> roles);
	std::shared_ptr<User> addUser(const std::string &userName, const nlohmann::json &userJson, std::shared_ptr<Roles> roles);
	void delUser(const std::string &name);

private:
	std::map<std::string, std::shared_ptr<User>> m_users;
	mutable std::recursive_mutex m_mutex;
};

struct JsonSecurity
{
	JsonSecurity();
	static std::shared_ptr<JsonSecurity> FromJson(nlohmann::json &jsonObj);
	nlohmann::json AsJson();

	bool m_encryptKey;
	std::shared_ptr<Users> m_users;
	std::shared_ptr<Roles> m_roles;
};

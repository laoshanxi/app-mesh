#pragma once

#include <string>
#include <set>
#include <map>
#include <mutex>
#include <cpprest/json.h>
#include "Role.h"

//////////////////////////////////////////////////////////////////////////
/// User
//////////////////////////////////////////////////////////////////////////
class User
{
public:
	explicit User(std::string name);
	virtual ~User();

	// seriarize
	virtual web::json::value AsJson();
	static std::shared_ptr<User> FromJson(std::string userName, const web::json::value& obj, std::shared_ptr<Roles> roles) noexcept(false);

	// user update
	void lock();
	void unlock();
	void updateRoles(std::set<std::shared_ptr<Role>> roles);
	void updateKey(std::string passswd);

	// get user info
	bool locked() const;
	const std::string getKey();
	const std::set<std::shared_ptr<Role>> getRoles();
	bool hasPermission(std::string permission);

private:
	std::string m_key;
	bool m_locked;
	std::string m_name;
	std::recursive_mutex m_mutex;
	std::set<std::shared_ptr<Role>> m_roles;
};

class Users
{
public:
	Users();
	virtual ~Users();

	virtual web::json::value AsJson();
	static std::shared_ptr<Users> FromJson(const web::json::value& obj, std::shared_ptr<Roles> roles) noexcept(false);

	// find user
	std::map<std::string, std::shared_ptr<User>> getUsers();
	std::shared_ptr<User> getUser(std::string name);

	// manage users
	void addUser(const web::json::value& obj, std::shared_ptr<Roles> roles);
	void delUser(std::string name);
private:
	std::map<std::string, std::shared_ptr<User>> m_users;
	std::recursive_mutex m_mutex;
};

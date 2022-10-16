#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <nlohmann/json.hpp>

//////////////////////////////////////////////////////////////////////////
/// Role
//////////////////////////////////////////////////////////////////////////
class Role
{
public:
	explicit Role(const std::string &name);
	virtual ~Role();

	// serialize
	nlohmann::json AsJson() const;
	static std::shared_ptr<Role> FromJson(std::string roleName, const nlohmann::json &obj) noexcept(false);

	// get information
	bool hasPermission(std::string permission);
	const std::set<std::string> getPermissions();
	const std::string getName() const;

private:
	std::set<std::string> m_permissions;
	std::string m_name;
	mutable std::recursive_mutex m_mutex;
};

class Roles
{
public:
	Roles();
	virtual ~Roles();

	std::shared_ptr<Role> getRole(const std::string &roleName);

	nlohmann::json AsJson() const;
	static const std::shared_ptr<Roles> FromJson(const nlohmann::json &obj) noexcept(false);

	void addRole(const nlohmann::json &obj, std::string name);
	void delRole(std::string name);
	std::map<std::string, std::shared_ptr<Role>> getRoles();

private:
	std::map<std::string, std::shared_ptr<Role>> m_roles;
	mutable std::recursive_mutex m_mutex;
};

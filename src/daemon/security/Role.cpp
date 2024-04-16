#include "Role.h"
#include "../../common/Utility.h"

//////////////////////////////////////////////////////////////////////
/// Users
//////////////////////////////////////////////////////////////////////
Roles::Roles()
{
}

Roles::~Roles()
{
}

std::shared_ptr<Role> Roles::getRole(const std::string &roleName)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto role = m_roles.find(roleName);
	if (role != m_roles.end())
	{
		return role->second;
	}
	else
	{
		throw std::invalid_argument("No such user role");
	}
}

nlohmann::json Roles::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	nlohmann::json result = nlohmann::json::object();
	for (auto &role : m_roles)
	{
		result[role.first] = role.second->AsJson();
	}
	return result;
}

const std::shared_ptr<Roles> Roles::FromJson(const nlohmann::json &obj)
{
	std::shared_ptr<Roles> roles = std::make_shared<Roles>();
	for (auto &roleJson : obj.items())
	{
		const auto &roleName = roleJson.key();
		auto role = Role::FromJson(roleName, roleJson.value());
		roles->m_roles[roleName] = role;
	}
	return roles;
}

void Roles::addRole(const nlohmann::json &obj, std::string name)
{
	nlohmann::json result = nlohmann::json::object();
	result[name] = obj;
	auto roles = Roles::FromJson(result);
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	for (auto &role : roles->m_roles)
	{
		m_roles[role.first] = role.second;
		// remove role if have no permission
		if (role.second->getPermissions().size() == 0)
		{
			m_roles.erase(role.first);
		}
	}
}

void Roles::delRole(std::string name)
{
	getRole(name);
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_roles.erase(name);
}

std::map<std::string, std::shared_ptr<Role>> Roles::getRoles()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_roles;
}

//////////////////////////////////////////////////////////////////////
/// Role
//////////////////////////////////////////////////////////////////////
Role::Role(const std::string &name) : m_name(name)
{
}

Role::~Role()
{
}

nlohmann::json Role::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto rolePermissions = nlohmann::json::array();
	for (auto &perm : m_permissions)
	{
		// fill role permission
		rolePermissions.push_back(std::string(perm));
	}
	return rolePermissions;
}

std::shared_ptr<Role> Role::FromJson(std::string roleName, const nlohmann::json &obj)
{
	auto role = std::make_shared<Role>(roleName);
	for (auto &permissionJson : obj.items())
	{
		auto perm = permissionJson.value().get<std::string>();
		if (perm.length())
			role->m_permissions.insert(perm);
	}
	return role;
}

bool Role::hasPermission(std::string permission)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_permissions.count(permission);
}

const std::set<std::string> Role::getPermissions()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_permissions;
}

const std::string Role::getName() const
{
	return m_name;
}

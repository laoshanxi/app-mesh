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
		throw std::invalid_argument(Utility::stringFormat("No such role <%s>", roleName.c_str()));
	}
}

web::json::value Roles::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	web::json::value result = web::json::value::object();
	for (auto role : m_roles)
	{
		result[role.first] = role.second->AsJson();
	}
	return result;
}

const std::shared_ptr<Roles> Roles::FromJson(const web::json::value &obj)
{
	std::shared_ptr<Roles> roles = std::make_shared<Roles>();
	auto rolesJson = obj.as_object();
	for (auto roleJson : rolesJson)
	{
		auto roleName = GET_STD_STRING(roleJson.first);
		auto role = Role::FromJson(roleName, roleJson.second);
		roles->m_roles[roleName] = role;
	}
	return roles;
}

void Roles::addRole(const web::json::value &obj, std::string name)
{
	web::json::value result = web::json::value::object();
	result[name] = obj;
	auto roles = Roles::FromJson(result);
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	for (auto role : roles->m_roles)
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

//////////////////////////////////////////////////////////////////////
/// Role
//////////////////////////////////////////////////////////////////////
Role::Role(const std::string &name) : m_name(name)
{
}

Role::~Role()
{
}

web::json::value Role::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto rolePermissions = web::json::value::array(m_permissions.size());
	int i = 0;
	for (auto perm : m_permissions)
	{
		// fill role permission
		rolePermissions[i++] = web::json::value::string(perm);
	}
	return rolePermissions;
}

std::shared_ptr<Role> Role::FromJson(std::string roleName, web::json::value &obj)
{
	auto role = std::make_shared<Role>(roleName);
	auto permissions = obj.as_array();
	for (auto permissionJson : permissions)
	{
		auto perm = permissionJson.as_string();
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

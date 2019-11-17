#include "Role.h"
#include "../common/Utility.h"

//////////////////////////////////////////////////////////////////////
/// pre-defined permissions
//////////////////////////////////////////////////////////////////////
std::set<std::string> Role::APP_MANAGER_PERMISSIONS = {
	PERMISSION_KEY_view_app ,
	PERMISSION_KEY_view_app_output,
	PERMISSION_KEY_view_all_app,
	PERMISSION_KEY_view_host_resource,
	PERMISSION_KEY_app_reg,
	PERMISSION_KEY_app_reg_shell,
	PERMISSION_KEY_app_control,
	PERMISSION_KEY_app_delete,
	PERMISSION_KEY_run_app_async,
	PERMISSION_KEY_run_app_sync,
	PERMISSION_KEY_run_app_async_output,
	PERMISSION_KEY_file_download,
	PERMISSION_KEY_file_upload,
	PERMISSION_KEY_label_view,
	PERMISSION_KEY_label_update,
	PERMISSION_KEY_label_set,
	PERMISSION_KEY_label_delete,
	PERMISSION_KEY_loglevel,
	PERMISSION_KEY_config_view,
	PERMISSION_KEY_config_set
};

//////////////////////////////////////////////////////////////////////
/// Users
//////////////////////////////////////////////////////////////////////
Roles::Roles()
{
}

Roles::~Roles()
{
}

std::shared_ptr<Role> Roles::getRole(std::string roleName)
{
	auto role = m_roles.find(roleName);
	if (role != m_roles.end())
	{
		return role->second;
	}
	else
	{
		throw std::invalid_argument("no such role");
	}
}

web::json::value Roles::AsJson()
{
	web::json::value result = web::json::value::object();
	for (auto role : m_roles)
	{
		result[role.first] = role.second->AsJson();
	}
	return result;
}

const std::shared_ptr<Roles> Roles::FromJson(const web::json::object & obj)
{
	std::shared_ptr<Roles> roles = std::make_shared<Roles>();
	for (auto roleJson : obj)
	{
		auto roleName = GET_STD_STRING(roleJson.first);
		auto role = Role::FromJson(roleName, roleJson.second);
		roles->m_roles[roleName] = role;
	}
	return roles;
}

void Roles::addRole(const web::json::object & obj)
{
	auto roles = Roles::FromJson(obj);
	for (auto role : roles->m_roles)
	{
		m_roles[role.first] = role.second;
	}
}

void Roles::delRole(std::string name)
{
	getRole(name);
	m_roles.erase(name);
}

//////////////////////////////////////////////////////////////////////
/// Role
//////////////////////////////////////////////////////////////////////
Role::Role(std::string name) :m_name(name)
{
}

Role::~Role()
{
}

web::json::value Role::AsJson()
{
	web::json::value result = web::json::value::object();
	auto rolePermissions = web::json::value::array(m_permissions.size());
	int i = 0;
	for (auto perm : m_permissions)
	{
		// fill role permission
		rolePermissions[i++] = web::json::value::string(perm);
	}

	result[m_name] = rolePermissions;
	return result;
}

std::shared_ptr<Role> Role::FromJson(std::string roleName, web::json::value & obj)
{
	auto role = std::make_shared<Role>(roleName);
	auto permissions = obj.as_array();
	for (auto permmisionJson : permissions)
	{
		if (APP_MANAGER_PERMISSIONS.count(permmisionJson.as_string()))
		{
			role->m_permissions.insert(permmisionJson.as_string());
		}
		else
		{
			throw std::invalid_argument("no such permission defined");
		}
	}
	return role;
}

bool Role::hasPermission(std::string permission)
{
	return m_permissions.count(permission);
}

const std::set<std::string>& Role::getPermissions()
{
	return m_permissions;
}

const std::string Role::getName() const
{
	return m_name;
}

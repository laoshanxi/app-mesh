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
	PERMISSION_KEY_app_control,
	PERMISSION_KEY_app_delete,
	PERMISSION_KEY_run_app_async,
	PERMISSION_KEY_run_app_sync,
	PERMISSION_KEY_run_app_async_output,
	PERMISSION_KEY_file_download,
	PERMISSION_KEY_file_upload,
	PERMISSION_KEY_label_view,
	PERMISSION_KEY_label_set,
	PERMISSION_KEY_label_delete,
	PERMISSION_KEY_loglevel,
	PERMISSION_KEY_config_view,
	PERMISSION_KEY_config_set,
	PERMISSION_KEY_change_passwd,
	PERMISSION_KEY_lock_user,
	PERMISSION_KEY_unlock_user,
	PERMISSION_KEY_add_user,
	PERMISSION_KEY_delete_user,
	PERMISSION_KEY_get_users
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
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
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
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	web::json::value result = web::json::value::object();
	for (auto role : m_roles)
	{
		result[role.first] = role.second->AsJson();
	}
	return result;
}

const std::shared_ptr<Roles> Roles::FromJson(const web::json::value& obj)
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

void Roles::addRole(const web::json::value& obj)
{
	auto roles = Roles::FromJson(obj);
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	for (auto role : roles->m_roles)
	{
		m_roles[role.first] = role.second;
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
Role::Role(std::string name) :m_name(name)
{
}

Role::~Role()
{
}

web::json::value Role::AsJson()
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

std::shared_ptr<Role> Role::FromJson(std::string roleName, web::json::value& obj)
{
	const static char fname[] = "Role::FromJson() ";

	auto role = std::make_shared<Role>(roleName);
	auto permissions = obj.as_array();
	for (auto permmisionJson : permissions)
	{
		auto perm = permmisionJson.as_string();
		if (APP_MANAGER_PERMISSIONS.count(perm))
		{
			role->m_permissions.insert(perm);
		}
		else
		{
			LOG_WAR << fname << "No such permission " << perm << " defined";
			//throw std::invalid_argument("no such permission defined");
		}
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

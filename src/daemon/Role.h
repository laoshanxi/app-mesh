#ifndef APMANAGER_ROLE_H
#define APMANAGER_ROLE_H
#include <string>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <cpprest/json.h>

class Role
{
public:
	explicit Role(std::string name);
	virtual ~Role();

	// seriarize
	virtual web::json::value AsJson();
	static std::shared_ptr<Role> FromJson(std::string roleName, web::json::value& obj);

	// get infomation
	bool hasPermission(std::string permission);
	const std::set<std::string> getPermissions();
	const std::string getName() const;

private:
	static std::set<std::string> APP_MANAGER_PERMISSIONS;
	std::set<std::string> m_permissions;
	std::string m_name;
	std::recursive_mutex m_mutex;
};


class Roles
{
public:
	Roles();
	virtual ~Roles();

	std::shared_ptr<Role> getRole(std::string roleName);

	virtual web::json::value AsJson();
	static const std::shared_ptr<Roles> FromJson(const web::json::value& obj);

	void addRole(const web::json::value& obj);
	void delRole(std::string name);

private:
	std::map<std::string, std::shared_ptr<Role>> m_roles;
	std::recursive_mutex m_mutex;

};

#endif

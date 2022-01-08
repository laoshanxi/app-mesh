#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <cpprest/json.h>

class Role;
class Roles;
class User;
namespace Ldap
{
    class Server;
}
//////////////////////////////////////////////////////////////////////////
/// LDAP Group
//////////////////////////////////////////////////////////////////////////
class LdapGroup
{
public:
    explicit LdapGroup(const std::string &name) : m_groupName(name){};
    virtual ~LdapGroup(){};

    // serialize
    web::json::value AsJson() const;
    // de-serialize
    static std::shared_ptr<LdapGroup> FromJson(const std::string &groupName, const web::json::value &obj, const std::shared_ptr<Roles> roles) noexcept(false);
    void updateGroup(std::shared_ptr<LdapGroup> group);
    // sync LDAP
    void syncGroupUsers(std::shared_ptr<Ldap::Server> ldap, std::shared_ptr<Roles> roles);
    std::shared_ptr<User> getUser(const std::string &userName);

public:
    mutable std::recursive_mutex m_mutex;
    const std::string m_groupName;
    std::string m_bindDN;
    std::set<std::shared_ptr<Role>> m_roles;
    std::map<std::string, std::shared_ptr<User>> m_users;
};
//////////////////////////////////////////////////////////////////////////
/// LDAP Groups
//////////////////////////////////////////////////////////////////////////
class LdapGroups
{
public:
    LdapGroups(){};
    virtual ~LdapGroups(){};

    std::shared_ptr<LdapGroup> getGroup(const std::string &name);
    web::json::value AsJson() const;
    static const std::shared_ptr<LdapGroups> FromJson(const web::json::value &obj, std::shared_ptr<Roles> roles) noexcept(false);

    std::shared_ptr<LdapGroup> addGroup(const web::json::value &obj, std::string name, std::shared_ptr<Roles> roles);
    void delGroup(const std::string &name);
    std::map<std::string, std::shared_ptr<LdapGroup>> getGroups() const;

private:
    std::map<std::string, std::shared_ptr<LdapGroup>> m_groups;
    mutable std::recursive_mutex m_mutex;
};

//////////////////////////////////////////////////////////////////////////
/// JsonLdap
//////////////////////////////////////////////////////////////////////////
struct JsonLdap
{
    JsonLdap();
    static std::shared_ptr<JsonLdap> FromJson(const web::json::value &jsonValue);
    web::json::value AsJson() const;

    std::string m_ldapUri;
    std::string m_ldapAdmin;
    std::string m_ldapAdminPwd;
    int m_syncSeconds;
    std::shared_ptr<LdapGroups> m_groups;
    std::shared_ptr<Roles> m_roles;
};

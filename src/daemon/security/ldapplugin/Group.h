#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <cpprest/json.h>

class Role;
class Roles;
//////////////////////////////////////////////////////////////////////////
/// LDAP Group
//////////////////////////////////////////////////////////////////////////
class Group
{
public:
    explicit Group(const std::string &name) : m_groupName(name){};
    virtual ~Group(){};

    // serialize
    web::json::value AsJson() const;
    // de-serialize
    static std::shared_ptr<Group> FromJson(const std::string groupName, const web::json::value &obj, const std::shared_ptr<Roles> roles) noexcept(false);
    void updateGroup(std::shared_ptr<Group> group);

public:
    mutable std::recursive_mutex m_mutex;
    const std::string m_groupName;
    std::string m_bindDN;
    std::set<std::shared_ptr<Role>> m_roles;
};
//////////////////////////////////////////////////////////////////////////
/// LDAP Groups
//////////////////////////////////////////////////////////////////////////
class Groups
{
public:
    Groups(){};
    virtual ~Groups(){};

    std::shared_ptr<Group> getGroup(const std::string &name);
    web::json::value AsJson() const;
    static const std::shared_ptr<Groups> FromJson(const web::json::value &obj, std::shared_ptr<Roles> roles) noexcept(false);

    std::shared_ptr<Group> addGroup(const web::json::value &obj, std::string name, std::shared_ptr<Roles> roles);
    void delGroup(std::string name);
    std::map<std::string, std::shared_ptr<Group>> getGroups();

private:
    std::map<std::string, std::shared_ptr<Group>> m_groups;
    mutable std::recursive_mutex m_mutex;
};

//////////////////////////////////////////////////////////////////////////
/// JsonLdap
//////////////////////////////////////////////////////////////////////////
struct JsonLdap
{
    JsonLdap();
    static std::shared_ptr<JsonLdap> FromJson(const web::json::value &jsonValue);
    web::json::value AsJson();

    std::string m_ldapUri;
    std::shared_ptr<Groups> m_groups;
    std::shared_ptr<Roles> m_roles;
};

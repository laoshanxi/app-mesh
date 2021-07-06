#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <cpprest/json.h>

#include "../../../common/Utility.h"
#include "../Role.h"
#include "LdapGroup.h"

//////////////////////////////////////////////////////////////////////////
/// LDAP Group
//////////////////////////////////////////////////////////////////////////

// serialize
web::json::value LdapGroup::AsJson() const
{
    web::json::value result = web::json::value::object();

    result[JSON_KEY_USER_LDAP_bind_dn] = web::json::value::string(m_bindDN);
    auto roles = web::json::value::array(m_roles.size());
    int i = 0;
    for (const auto &role : m_roles)
    {
        roles[i++] = web::json::value::string(role->getName());
    }
    return result;
};
// de-serialize
std::shared_ptr<LdapGroup> LdapGroup::FromJson(const std::string &groupName, const web::json::value &obj, const std::shared_ptr<Roles> roles) noexcept(false)
{
    std::shared_ptr<LdapGroup> result = std::make_shared<LdapGroup>(groupName);
    if (!obj.is_null())
    {
        result->m_bindDN = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_LDAP_bind_dn);
        if (HAS_JSON_FIELD(obj, JSON_KEY_USER_roles))
        {
            auto arr = obj.at(JSON_KEY_USER_roles).as_array();
            for (auto jsonRole : arr)
                result->m_roles.insert(roles->getRole(jsonRole.as_string()));
        }
    }
    return result;
};
void LdapGroup::updateGroup(std::shared_ptr<LdapGroup> group)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    this->m_roles = group->m_roles;
    this->m_bindDN = group->m_bindDN;
}

//////////////////////////////////////////////////////////////////////////
/// LDAP Groups
//////////////////////////////////////////////////////////////////////////

std::shared_ptr<LdapGroup> LdapGroups::getGroup(const std::string &name)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    auto group = m_groups.find(name);
    if (group != m_groups.end())
    {
        return group->second;
    }
    else
    {
        throw std::invalid_argument(Utility::stringFormat("no such group <%s>", name.c_str()));
    }
};
web::json::value LdapGroups::AsJson() const
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    web::json::value result = web::json::value::object();
    for (const auto &group : m_groups)
    {
        result[group.first] = group.second->AsJson();
    }
    return result;
};
const std::shared_ptr<LdapGroups> LdapGroups::FromJson(const web::json::value &obj, std::shared_ptr<Roles> roles) noexcept(false)
{
    std::shared_ptr<LdapGroups> groups = std::make_shared<LdapGroups>();
    auto jsonOj = obj.as_object();
    for (const auto &group : jsonOj)
    {
        auto name = GET_STD_STRING(group.first);
        groups->m_groups[name] = LdapGroup::FromJson(name, group.second, roles);
    }
    return groups;
};

std::shared_ptr<LdapGroup> LdapGroups::addGroup(const web::json::value &obj, std::string name, std::shared_ptr<Roles> roles)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    auto group = LdapGroup::FromJson(name, obj, roles);
    if (m_groups.count(name))
    {
        // update
        m_groups[name]->updateGroup(group);
    }
    else
    {
        // insert
        m_groups[name] = group;
    }
    return group;
};
void LdapGroups::delGroup(const std::string &name)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    if (m_groups.count(name))
    {
        // delete
        m_groups.erase(m_groups.find(name));
    }
};
std::map<std::string, std::shared_ptr<LdapGroup>> LdapGroups::getGroups() const
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    return m_groups;
};

//////////////////////////////////////////////////////////////////////////
/// JsonLdap
//////////////////////////////////////////////////////////////////////////
JsonLdap::JsonLdap()
{
    m_roles = std::make_shared<Roles>();
    m_groups = std::make_shared<LdapGroups>();
}
std::shared_ptr<JsonLdap> JsonLdap::FromJson(const web::json::value &jsonValue)
{
    auto security = std::make_shared<JsonLdap>();
    security->m_ldapUri = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_USER_LDAP_ldap_uri);
    // Roles
    if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Roles))
        security->m_roles = Roles::FromJson(jsonValue.at(JSON_KEY_Roles));
    // Groups
    if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Groups))
        security->m_groups = LdapGroups::FromJson(jsonValue.at(JSON_KEY_Groups), security->m_roles);
    return security;
}
web::json::value JsonLdap::AsJson() const
{
    auto result = web::json::value::object();
    result[JSON_KEY_USER_LDAP_ldap_uri] = web::json::value::string(m_ldapUri);
    // Users
    result[JSON_KEY_JWT_Users] = m_groups->AsJson();
    // Roles
    result[JSON_KEY_Roles] = m_roles->AsJson();
    return result;
}

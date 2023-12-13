#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <nlohmann/json.hpp>
#include <ldapc++/cldap.h>

#include "../../../common/Utility.h"
#include "../Role.h"
#include "../Security.h"
#include "../User.h"
#include "LdapGroup.h"

//////////////////////////////////////////////////////////////////////////
/// LDAP Group
//////////////////////////////////////////////////////////////////////////

// serialize
nlohmann::json LdapGroup::AsJson() const
{
    nlohmann::json result = nlohmann::json::object();

    result[JSON_KEY_USER_LDAP_bind_dn] = std::string(m_bindDN);
    auto roles = nlohmann::json::array();
    for (const auto &role : m_roles)
    {
        roles.push_back(std::string(role->getName()));
    }
    return result;
};
// de-serialize
std::shared_ptr<LdapGroup> LdapGroup::FromJson(const std::string &groupName, const nlohmann::json &obj, const std::shared_ptr<Roles> roles) noexcept(false)
{
    std::shared_ptr<LdapGroup> result = std::make_shared<LdapGroup>(groupName);
    if (!obj.is_null())
    {
        result->m_bindDN = GET_JSON_STR_VALUE(obj, JSON_KEY_USER_LDAP_bind_dn);
        if (HAS_JSON_FIELD(obj, JSON_KEY_USER_roles))
        {
            for (auto &jsonRole : obj.at(JSON_KEY_USER_roles).items())
                result->m_roles.insert(roles->getRole(jsonRole.value().get<std::string>()));
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

void LdapGroup::syncGroupUsers(std::shared_ptr<Ldap::Server> ldap, std::shared_ptr<Roles> roles)
{
    const static char fname[] = "LdapGroup::syncGroupUsers() ";

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    m_users.clear();
    if (ldap)
    {
        auto baseDN = Utility::stringReplace(this->m_bindDN, "cn={USER}", "");
        baseDN = Utility::stdStringTrim(baseDN, ',');
        auto result = ldap->Search(baseDN, Ldap::ScopeTree, "sn=*");
        for (auto &entry : result)
        {
            nlohmann::json result = nlohmann::json::object();
            auto userName = Utility::stdStringTrim(entry.GetStringValue("cn"));
            auto userMail = Utility::stdStringTrim(entry.GetStringValue("mail"));
            auto userSN = Utility::stdStringTrim(entry.GetStringValue("sn"));
            result[JSON_KEY_USER_group] = std::string(this->m_groupName);
            result[JSON_KEY_USER_exec_user] = std::string(userSN);
            result[JSON_KEY_USER_locked] = (false);
            result[JSON_KEY_USER_metadata] = std::string(entry.DN());
            result[JSON_KEY_USER_email] = std::string(userMail);
            // Roles
            auto rolesArray = nlohmann::json::array();
            for (const auto &role : this->m_roles)
            {
                rolesArray.push_back(std::string(role->getName()));
            }
            result[JSON_KEY_USER_roles] = rolesArray;

            m_users[userName] = User::FromJson(userName, result, roles);
            LOG_DBG << fname << "syncing <" << userName << "> to group <" << m_groupName << ">";
        }
        LOG_DBG << fname << "Sync <" << m_users.size() << "> users to group <" << m_groupName << ">";
    }
}

std::shared_ptr<User> LdapGroup::getUser(const std::string &userName)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    if (m_users.count(userName) > 0)
    {
        return m_users[userName];
    }
    return nullptr;
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
        throw std::invalid_argument("no such user group");
    }
};
nlohmann::json LdapGroups::AsJson() const
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    nlohmann::json result = nlohmann::json::object();
    for (const auto &group : m_groups)
    {
        result[group.first] = group.second->AsJson();
    }
    return result;
};
const std::shared_ptr<LdapGroups> LdapGroups::FromJson(const nlohmann::json &obj, std::shared_ptr<Roles> roles) noexcept(false)
{
    std::shared_ptr<LdapGroups> groups = std::make_shared<LdapGroups>();
    for (auto &group : obj.items())
    {
        auto name = (group.key());
        groups->m_groups[name] = LdapGroup::FromJson(name, group.value(), roles);
    }
    return groups;
};

std::shared_ptr<LdapGroup> LdapGroups::addGroup(const nlohmann::json &obj, std::string name, std::shared_ptr<Roles> roles)
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
JsonLdap::JsonLdap() : m_syncSeconds(0)
{
    m_roles = std::make_shared<Roles>();
    m_groups = std::make_shared<LdapGroups>();
}
std::shared_ptr<JsonLdap> JsonLdap::FromJson(const nlohmann::json &jsonValue)
{
    auto security = std::make_shared<JsonLdap>();
    security->m_ldapUri = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_USER_LDAP_ldap_uri);
    security->m_ldapAdmin = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_USER_LDAP_ldap_LoginDN);
    security->m_ldapAdminPwd = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_USER_LDAP_ldap_LoginPWD);
    security->m_syncSeconds = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_USER_LDAP_ldap_SyncPeriodSeconds);
    // Roles
    if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Roles))
        security->m_roles = Roles::FromJson(jsonValue.at(JSON_KEY_Roles));
    // Groups
    if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Groups))
        security->m_groups = LdapGroups::FromJson(jsonValue.at(JSON_KEY_Groups), security->m_roles);
    return security;
}
nlohmann::json JsonLdap::AsJson() const
{
    auto result = nlohmann::json::object();
    result[JSON_KEY_USER_LDAP_ldap_uri] = std::string(m_ldapUri);
    result[JSON_KEY_USER_LDAP_ldap_LoginDN] = std::string(m_ldapAdmin);
    result[JSON_KEY_USER_LDAP_ldap_LoginPWD] = std::string(m_ldapAdminPwd);
    result[JSON_KEY_USER_LDAP_ldap_SyncPeriodSeconds] = (m_syncSeconds);
    // Users
    result[JSON_KEY_JWT_Users] = m_groups->AsJson();
    // Roles
    result[JSON_KEY_Roles] = m_roles->AsJson();
    return result;
}

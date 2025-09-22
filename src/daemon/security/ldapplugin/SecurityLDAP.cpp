#include <ace/OS.h>
#include <ldapc++/cldap.h>

#include "../../../common/Utility.h"
#include "../../Configuration.h"
#include "LdapGroup.h"
#include "SecurityLDAP.h"

//////////////////////////////////////////////////////////////////////
/// LDAP wrapper
//////////////////////////////////////////////////////////////////////
SecurityLDAP::SecurityLDAP() : m_syncTimerId(INVALID_TIMER_ID)
{
    m_ldap = std::make_shared<JsonLdap>();
}

void SecurityLDAP::init()
{
    const static char fname[] = "SecurityLDAP::init() ";
    LOG_DBG << fname;

    const auto securityYamlFile = Utility::getConfigFilePath(APPMESH_SECURITY_LDAP_YAML_FILE);
    m_ldap = JsonLdap::FromJson(Utility::yamlToJson(YAML::LoadFile(securityYamlFile)));

    LOG_DBG << fname << "LDAP URI: " << m_ldap->m_ldapUri;
    LOG_DBG << fname << "LDAP Admin: " << m_ldap->m_ldapAdmin;
    LOG_DBG << fname << "LDAP Admin Password: " << Utility::maskSecret(m_ldap->m_ldapAdminPwd);
    LOG_DBG << fname << "LDAP Sync Period: " << m_ldap->m_syncSeconds;

    this->syncGroupUsers();

    LOG_DBG << fname << "LDAP Sync Groups: " << m_ldap->m_groups->getGroups().size();
    LOG_DBG << fname << "LDAP Sync Roles: " << m_ldap->m_roles->getRoles().size();
}

std::shared_ptr<User> SecurityLDAP::getUserInfo(const std::string &userName)
{
    const static char fname[] = "SecurityLDAP::getUserInfo() ";

    auto groups = this->m_ldap->m_groups->getGroups();
    for (const auto &group : groups)
    {
        auto user = group.second->getUser(userName);
        if (user)
        {
            return user;
        }
    }
    LOG_WAR << fname << "No such user in LDAP: " << userName;
    throw std::invalid_argument("No such user in LDAP");
}

std::set<std::string> SecurityLDAP::getUserPermissions(const std::string &userName, const std::string &userGroup)
{
    std::set<std::string> permissionSet;
    const auto group = m_ldap->m_groups->getGroup(userGroup);
    for (const auto &role : group->m_roles)
    {
        const auto perms = role->getPermissions();
        permissionSet.insert(perms.begin(), perms.end());
    }
    return permissionSet;
}

std::shared_ptr<Ldap::Server> SecurityLDAP::connect()
{
    const static char fname[] = "SecurityLDAP::connect() ";

    if (m_ldap->m_ldapUri.empty())
    {
        LOG_WAR << fname << "LDAP URI is empty";
        return nullptr;
    }

    auto ldap = std::make_shared<Ldap::Server>();
    LOG_DBG << fname << "connecting to LDAP: " << m_ldap->m_ldapUri;
    if (ldap->Connect(m_ldap->m_ldapUri))
    {
        return ldap;
    }
    else
    {
        LOG_WAR << fname << "Connect LDAP failed: " << ldap->Message();
    }

    return nullptr;
}

bool SecurityLDAP::syncGroupUsers()
{
    const static char fname[] = "SecurityLDAP::syncGroupUsers() ";
    LOG_DBG << fname;

    try
    {
        auto ldap = connect();
        if (ldap)
        {
            static const std::string prefix = "APP_";
            static const std::string postfix = "_MESH";
            auto pwd = Utility::stdStringTrim(Utility::decode64(m_ldap->m_ldapAdminPwd), prefix, true, false);
            pwd = Utility::stdStringTrim(pwd, postfix, false, true);
            // LOG_ERR << fname << "bind " << m_ldap->m_ldapAdmin << " with " << pwd;
            if (ldap->Bind(m_ldap->m_ldapAdmin, pwd))
            {
                auto groups = m_ldap->m_groups->getGroups();
                for (const auto &group : groups)
                {
                    group.second->syncGroupUsers(ldap, m_ldap->m_roles);
                }
            }
            else
            {
                LOG_WAR << fname << "Failed to sync LDAP users due to incorrect password or bind credentials";
                return false;
            }
        }
        else
        {
            LOG_WAR << fname << "Failed to sync LDAP users due to can not connect to LDAP Server";
            return false;
        }
    }
    catch (const std::exception &ex)
    {
        LOG_WAR << fname << "Exception during LDAP sync: " << ex.what();
        return false;
    }

    if (!IS_VALID_TIMER_ID(m_syncTimerId) && m_ldap->m_syncSeconds > 0)
    {
        m_syncTimerId = this->registerTimer(1000L, m_ldap->m_syncSeconds, std::bind(&SecurityLDAP::syncGroupUsers, this), fname);
    }
    return true;
}

bool SecurityLDAP::verifyUserKey(const std::string &userName, const std::string &userKey)
{
    const static char fname[] = "SecurityLDAP::verifyUserKey() ";
    LOG_DBG << fname << "Verifying user: " << userName;

    if (userName.empty() || userKey.empty())
    {
        LOG_WAR << fname << "Empty username or password";
        throw std::domain_error("username and password cannot be empty");
    }

    auto ldap = connect();
    if (ldap)
    {
        auto groups = m_ldap->m_groups->getGroups();
        for (const auto &group : groups)
        {
            LOG_DBG << fname << "Try bind LDAP group: " << group.second->m_groupName;
            auto cn = Utility::stringReplace(group.second->m_bindDN, JSON_KEY_USER_LDAP_USER_REPLACE_HOLDER, userName);
            if (ldap->Bind(cn, userKey))
            {
                return true;
            }
            // TODO: validate TOTP
        }
        LOG_WAR << fname << "Authentication failed for user: " << userName;
        throw std::domain_error("verify user password failed");
    }
    else
    {
        LOG_ERR << fname << "Failed to connect to LDAP server";
        throw std::runtime_error("failed to connect to LDAP server");
    }
}

std::set<std::string> SecurityLDAP::getAllUserGroups() const
{
    const static char fname[] = "SecurityLDAP::getAllUserGroups() ";
    LOG_DBG << fname;

    std::set<std::string> groupSet;
    auto groups = m_ldap->m_groups->getGroups();
    for (auto &group : groups)
    {
        groupSet.insert(group.second->m_groupName);
    }
    return groupSet;
}

std::set<std::string> SecurityLDAP::getAllPermissions()
{
    const static char fname[] = "SecurityLDAP::getAllPermissions() ";
    LOG_DBG << fname;

    std::set<std::string> permissionSet;
    auto roles = m_ldap->m_roles->getRoles();
    for (const auto &role : roles)
    {
        auto rolePerms = role.second->getPermissions();
        permissionSet.insert(rolePerms.begin(), rolePerms.end());
    }
    return permissionSet;
}

#include <ace/OS.h>

#include "../../../common/Utility.h"
#include "../../Configuration.h"
#include "LdapGroup.h"
#include "LdapImpl.h"
#include "ldapcpp/cldap.h"

//////////////////////////////////////////////////////////////////////
/// LDAP wrapper
//////////////////////////////////////////////////////////////////////
LdapImpl::LdapImpl(std::shared_ptr<JsonLdap> ldap)
    : Security(nullptr), m_ldap(ldap), m_syncTimerId(INVALID_TIMER_ID)
{
}

LdapImpl::~LdapImpl()
{
}

void LdapImpl::init()
{
    const static char fname[] = "LdapImpl::init() ";
    LOG_DBG << fname;

    if (Configuration::instance()->getJwt()->m_jwtInterface == JSON_KEY_USER_key_method_ldap)
    {
        const auto securityJsonFile = (fs::path(Utility::getParentDir()) / APPMESH_SECURITY_LDAP_JSON_FILE).string();
        const auto security = LdapImpl::FromJson(web::json::value::parse(Utility::readFileCpp(securityJsonFile)));
        Security::instance(security);

        security->syncGroupUsers();
    }
    else
    {
        throw std::invalid_argument(Utility::stringFormat("not supported security plugin <%s>", Configuration::instance()->getJwt()->m_jwtInterface.c_str()));
    }
}

web::json::value LdapImpl::AsJson() const
{
    const static char fname[] = "LdapImpl::AsJson() ";
    LOG_DBG << fname;

    return this->m_ldap->AsJson();
}

std::shared_ptr<LdapImpl> LdapImpl::FromJson(const web::json::value &obj) noexcept(false)
{
    const static char fname[] = "LdapImpl::FromJson() ";
    LOG_DBG << fname;

    std::shared_ptr<LdapImpl> security(new LdapImpl(JsonLdap::FromJson(obj)));
    return security;
}

std::shared_ptr<User> LdapImpl::getUserInfo(const std::string &userName)
{
    auto groups = this->m_ldap->m_groups->getGroups();
    for (const auto &group : groups)
    {
        auto user = group.second->getUser(userName);
        if (user)
        {
            return user;
        }
    }
    throw std::invalid_argument(Utility::stringFormat("No such user <%s> exist in LDAP", userName.c_str()));
}

std::set<std::string> LdapImpl::getUserPermissions(const std::string &userName, const std::string &userGroup)
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

std::shared_ptr<Ldap::Server> LdapImpl::connect()
{
    const static char fname[] = "LdapImpl::connect() ";

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

void LdapImpl::syncGroupUsers(int timerId)
{
    const static char fname[] = "LdapImpl::syncGroupUsers() ";
    LOG_DBG << fname;

    try
    {
        auto ldap = connect();
        if (ldap)
        {
            char prefix[5] = {'A', 'P', 'P', '_', '\0'};
            char postfix[6] = {'_', 'M', 'E', 'S', 'H', '\0'};
            auto pwd = Utility::stdStringTrim(Utility::decode64(m_ldap->m_ldapAdminPwd), std::string(prefix), true, false);
            pwd = Utility::stdStringTrim(pwd, std::string(postfix), false, true);
            // LOG_ERR << fname << "bind " << m_ldap->m_ldapAdmin << " with " << pwd;
            if (ldap->Bind(m_ldap->m_ldapAdmin, pwd))
            {
                auto groups = m_ldap->m_groups->getGroups();
                for (const auto &group : groups)
                {
                    group.second->syncGroupUsers(ldap, m_ldap->m_roles);
                }
            }
            else if (timerId == INVALID_TIMER_ID)
            {
                throw std::invalid_argument("Failed to sync LDAP users due to incorrect password");
            }
        }
        else if (timerId == INVALID_TIMER_ID)
        {
            throw std::invalid_argument("Failed to sync LDAP users due to can not connect to LDAP Server");
        }
    }
    catch (const std::exception &ex)
    {
        LOG_WAR << fname << ex.what();

        if (timerId == INVALID_TIMER_ID)
        {
            throw ex;
        }
    }

    if (timerId == INVALID_TIMER_ID && m_ldap->m_syncSeconds > 0)
    {
        m_syncTimerId = this->registerTimer(1000L, m_ldap->m_syncSeconds, std::bind(&LdapImpl::syncGroupUsers, this, std::placeholders::_1), fname);
    }
}

bool LdapImpl::verifyUserKey(const std::string &userName, const std::string &userKey, std::string &outUserGroup)
{
    const static char fname[] = "LdapImpl::verifyUserKey() ";
    LOG_DBG << fname;

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
                outUserGroup = group.second->m_groupName;
                return true;
            }
        }
        throw std::invalid_argument("verify user password failed");
    }
    else
    {
        throw std::invalid_argument("failed to connect to LDAP server");
    }

    return false;
}

std::set<std::string> LdapImpl::getAllUserGroups() const
{
    const static char fname[] = "LdapImpl::getAllUserGroups() ";
    LOG_DBG << fname;

    std::set<std::string> groupSet;
    auto groups = m_ldap->m_groups->getGroups();
    for (auto group : groups)
    {
        groupSet.insert(group.second->m_groupName);
    }
    return groupSet;
}

std::set<std::string> LdapImpl::getAllPermissions()
{
    const static char fname[] = "LdapImpl::getAllPermissions() ";
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

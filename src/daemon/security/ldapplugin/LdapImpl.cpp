#include <ace/OS.h>

#include "../../../common/Utility.h"
#include "../../Configuration.h"
#include "Group.h"
#include "LdapImpl.h"
#include "ldapcpp/cldap.h"

//////////////////////////////////////////////////////////////////////
/// LDAP wrapper
//////////////////////////////////////////////////////////////////////
LdapImpl::LdapImpl(std::shared_ptr<JsonLdap> ldap)
    : Security(nullptr), m_ldap(ldap)
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
        auto securityJsonFile = Utility::getParentDir() + ACE_DIRECTORY_SEPARATOR_STR + APPMESH_SECURITY_LDAP_JSON_FILE;
        auto security = LdapImpl::FromJson(web::json::value::parse(Utility::readFileCpp(securityJsonFile)));
        Security::instance(security);
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

std::shared_ptr<User> LdapImpl::getUserInfo(const std::string &userName) const
{
    web::json::value result = web::json::value::object();

    result[JSON_KEY_USER_key] = web::json::value::string("");
    result[JSON_KEY_USER_group] = web::json::value::string("");
    // TODO: make sure the host have such user
    result[JSON_KEY_USER_exec_user] = web::json::value::string(userName);
    result[JSON_KEY_USER_locked] = web::json::value::boolean(false);
    // result[JSON_KEY_USER_metadata] = web::json::value::string(m_metadata);
    auto allRoles = m_ldap->m_roles->getRoles();
    auto roles = web::json::value::array(allRoles.size());
    int i = 0;
    for (const auto &role : allRoles)
    {
        roles[i++] = web::json::value::string(role.second->getName());
    }
    result[JSON_KEY_USER_roles] = roles;
    return User::FromJson(userName, result, m_ldap->m_roles);
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
    if (ldap->Connect("ldap://172.17.0.5:389"))
    {
        return ldap;
    }
    else
    {
        LOG_WAR << fname << "Connect LDAP failed: " << ldap->Message();
    }

    return nullptr;
}

bool LdapImpl::verifyUserKey(const std::string &userName, const std::string &userKey, std::string &outUserGroup)
{
    const static char fname[] = "LdapImpl::verifyUserKey() ";
    LOG_DBG << fname;

    if (auto ldap = connect())
    {
        auto groups = m_ldap->m_groups->getGroups();
        for (const auto &group : groups)
        {
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

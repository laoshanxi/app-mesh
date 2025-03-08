#include <fstream>

#include <ace/OS.h>
#include <boost/filesystem.hpp>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "./ldapplugin/LdapImpl.h"
#include "ConsulConnection.h"
#include "Security.h"

std::shared_ptr<Security> Security::m_instance = nullptr;
std::recursive_mutex Security::m_mutex;
Security::Security(std::shared_ptr<JsonSecurity> jsonSecurity)
    : m_securityConfig(jsonSecurity)
{
}

Security::~Security()
{
}

void Security::init(const std::string &interface)
{
    const static char fname[] = "Security::init() ";
    LOG_INF << fname << "Security plugin: " << interface;

    // TODO: re-design security plugin interface for local, consul, oauth
    if (interface == JSON_KEY_USER_key_method_local || interface == JSON_KEY_USER_key_method_oauth2)
    {
        const auto securityYamlFile = Utility::getConfigFilePath(APPMESH_SECURITY_YAML_FILE);
        const auto security = Security::FromJson(Utility::yamlToJson(YAML::LoadFile(securityYamlFile)));
        Security::instance(std::move(security));
    }
    else if (interface == JSON_KEY_USER_key_method_consul)
    {
        ConsulConnection::instance()->initialize();
        auto securityObj = Security::FromJson(ConsulConnection::instance()->fetchSecurityJson());
        if (securityObj->getUsers().size())
        {
            Security::instance(securityObj);
            LOG_INF << fname << "Security information successfully retrieved from Consul";
        }
        else
        {
            throw std::invalid_argument("no security info found in Consul");
        }
    }
    else if (interface == JSON_KEY_USER_key_method_ldap)
    {
        LdapImpl::init(interface);
    }
    else
    {
        throw std::invalid_argument("not supported security plugin");
    }
}

std::shared_ptr<Security> Security::instance()
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    return m_instance;
}

void Security::instance(std::shared_ptr<Security> instance)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    m_instance = instance;
}

bool Security::encryptKey()
{
    return m_securityConfig->m_encryptKey;
}

void Security::save(const std::string &interface)
{
    const static char fname[] = "Security::save() ";

    if (interface == JSON_KEY_USER_key_method_consul)
    {
        ConsulConnection::instance()->saveSecurity();
        return;
    }

    // distinguish security.yaml and ldap.yaml
    std::string securityFile = APPMESH_SECURITY_YAML_FILE;
    if (interface == JSON_KEY_USER_key_method_ldap)
    {
        securityFile = APPMESH_SECURITY_LDAP_YAML_FILE;
    }

    auto content = this->AsJson();
    const auto securityYamlFile = Utility::getConfigFilePath(securityFile, true);
    auto tmpFile = securityYamlFile + std::string(".") + std::to_string(Utility::getThreadId());
    if (Utility::runningInContainer())
    {
        tmpFile = securityYamlFile;
    }
    std::ofstream ofs(tmpFile, ios::trunc);
    if (ofs.is_open())
    {
        auto formatJson = Utility::jsonToYaml(content);
        ofs << formatJson;
        ofs.close();
        if (tmpFile != securityYamlFile)
        {
            if (ACE_OS::rename(tmpFile.c_str(), securityYamlFile.c_str()) == 0)
            {
                LOG_DBG << fname << "local security saved";
            }
            else
            {
                LOG_ERR << fname << "Failed to write configuration file <" << securityYamlFile << ">, error :" << std::strerror(errno);
            }
        }
        boost::filesystem::permissions(securityYamlFile, fs::perms::owner_all);
    }
}

std::shared_ptr<Security> Security::FromJson(const nlohmann::json &obj) noexcept(false)
{
    std::shared_ptr<Security> security(new Security(JsonSecurity::FromJson(obj)));
    return security;
}

nlohmann::json Security::AsJson() const
{
    return this->m_securityConfig->AsJson();
}

bool Security::verifyUserKey(const std::string &userName, const std::string &userKey)
{
    const static char fname[] = "Security::verifyUserKey() ";
    auto key = userKey;
    if (m_securityConfig->m_encryptKey)
    {
        key = Utility::hash(userKey);
    }
    auto user = this->getUserInfo(userName);
    if (user)
    {
        if (user->getKey() != key)
            return false;
        if (user->locked())
            return false;

        return true;
    }
    LOG_WAR << fname << "user not exist: " << userName;
    throw std::invalid_argument("user not exist");
}

std::set<std::string> Security::getUserPermissions(const std::string &userName, const std::string &userGroup)
{
    std::set<std::string> permissionSet;
    const auto user = this->getUserInfo(userName);
    for (const auto &role : user->getRoles())
    {
        for (const auto &perm : role->getPermissions())
            permissionSet.insert(perm);
    }
    return permissionSet;
}

std::set<std::string> Security::getAllPermissions()
{
    std::set<std::string> permissionSet;
    for (const auto &role : m_securityConfig->m_roles->getRoles())
    {
        auto rolePerms = role.second->getPermissions();
        permissionSet.insert(rolePerms.begin(), rolePerms.end());
    }
    return permissionSet;
}

void Security::changeUserPasswd(const std::string &userName, const std::string &newPwd)
{
    const static char fname[] = "Security::changeUserPasswd() ";
    auto user = this->getUserInfo(userName);
    if (user)
    {
        return user->updateKey(newPwd);
    }
    LOG_WAR << fname << "user not exist: " << userName;
    throw std::invalid_argument("user not exist");
}

std::shared_ptr<User> Security::getUserInfo(const std::string &userName)
{
    return m_securityConfig->m_users->getUser(userName);
}

std::map<std::string, std::shared_ptr<User>> Security::getUsers() const
{
    return m_securityConfig->m_users->getUsers();
}

nlohmann::json Security::getUsersJson() const
{
    return m_securityConfig->m_users->AsJson();
}

nlohmann::json Security::getRolesJson() const
{
    return m_securityConfig->m_roles->AsJson();
}

std::shared_ptr<User> Security::addUser(const std::string &userName, const nlohmann::json &userJson)
{
    return m_securityConfig->m_users->addUser(userName, userJson, m_securityConfig->m_roles);
}

void Security::delUser(const std::string &name)
{
    m_securityConfig->m_users->delUser(name);
}

void Security::addRole(const nlohmann::json &obj, std::string name)
{
    m_securityConfig->m_roles->addRole(obj, name);
}

void Security::delRole(const std::string &name)
{
    m_securityConfig->m_roles->delRole(name);
}

std::shared_ptr<Role> Security::getRole(const std::string &roleName)
{
    return m_securityConfig->m_roles->getRole(roleName);
}

std::set<std::string> Security::getAllUserGroups() const
{
    return m_securityConfig->m_users->getGroups();
}

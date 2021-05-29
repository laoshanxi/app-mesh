#include <ace/OS.h>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Security.h"

std::shared_ptr<Security> Security::m_instance = nullptr;
std::recursive_mutex Security::m_mutex;
Security::Security()
{
}

Security::~Security()
{
}

void Security::init()
{
    if (Configuration::instance()->getJwt()->m_jwtInterface == "json")
    {
        auto securityJsonFile = Utility::getParentDir() + ACE_DIRECTORY_SEPARATOR_STR + APPMESH_SECURITY_JSON_FILE;
        auto security = Security::FromJson(web::json::value::parse(Utility::readFileCpp(securityJsonFile)));
        Security::instance(security);
    }
    else
    {
        throw std::invalid_argument(Utility::stringFormat("not supported security plugin <%s>", Configuration::instance()->getJwt()->m_jwtInterface.c_str()));
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

void Security::save()
{
    const static char fname[] = "Security::save() ";

    auto content = this->AsJson().serialize();
    if (content.length())
    {
        auto securityJsonFile = Utility::getParentDir() + ACE_DIRECTORY_SEPARATOR_STR + APPMESH_SECURITY_JSON_FILE;
        auto tmpFile = securityJsonFile + "." + std::to_string(Utility::getThreadId());
        std::ofstream ofs(tmpFile, ios::trunc);
        if (ofs.is_open())
        {
            auto formatJson = Utility::prettyJson(content);
            ofs << formatJson;
            ofs.close();
            if (ACE_OS::rename(tmpFile.c_str(), securityJsonFile.c_str()) == 0)
            {
                LOG_DBG << fname << "local security saved";
            }
            else
            {
                LOG_ERR << fname << "Failed to write configuration file <" << securityJsonFile << ">, error :" << std::strerror(errno);
            }
        }
    }
    else
    {
        LOG_ERR << fname << "Configuration content is empty";
    }
}

std::shared_ptr<Security> Security::FromJson(const web::json::value &obj) noexcept(false)
{
    std::shared_ptr<Security> security(new Security());
    security->m_securityConfig = JsonSecurity::FromJson(obj);
    return security;
}

web::json::value Security::AsJson() const
{
    return this->m_securityConfig->AsJson();
}

bool Security::verifyUserKey(const std::string &userName, const std::string &userKey)
{
    auto key = userKey;
    if (m_securityConfig->m_encryptKey)
    {
        key = Utility::hash(userKey);
    }
    auto user = this->getUserInfo(userName);
    if (user)
    {
        return (user->getKey() == key) && !user->locked();
    }
    throw std::invalid_argument(Utility::stringFormat("user %s not exist", userName.c_str()));
}

std::set<std::string> Security::getUserPermissions(const std::string &userName)
{
    std::set<std::string> permissionSet;
    auto user = this->getUserInfo(userName);
    for (auto role : user->getRoles())
    {
        for (auto perm : role->getPermissions())
            permissionSet.insert(perm);
    }
    return permissionSet;
}

std::set<std::string> Security::getAllPermissions()
{
    std::set<std::string> permissionSet;
    for (auto user : this->getUsers())
    {
        for (auto role : user.second->getRoles())
        {
            for (auto perm : role->getPermissions())
                permissionSet.insert(perm);
        }
    }
    return permissionSet;
}

void Security::changeUserPasswd(const std::string &userName, const std::string &newPwd)
{
    auto user = this->getUserInfo(userName);
    if (user)
    {
        return user->updateKey(newPwd);
    }
    throw std::invalid_argument(Utility::stringFormat("user %s not exist", userName.c_str()));
}

std::shared_ptr<User> Security::getUserInfo(const std::string &userName) const
{
    return m_securityConfig->m_users->getUser(userName);
}

std::map<std::string, std::shared_ptr<User>> Security::getUsers() const
{
    return m_securityConfig->m_users->getUsers();
}

web::json::value Security::getUsersJson() const
{
    return m_securityConfig->m_users->AsJson();
}

web::json::value Security::getRolesJson() const
{
    return m_securityConfig->m_roles->AsJson();
}

std::shared_ptr<User> Security::addUser(const std::string &userName, const web::json::value &userJson)
{
    return m_securityConfig->m_users->addUser(userName, userJson, m_securityConfig->m_roles);
}

void Security::delUser(const std::string &name)
{
    m_securityConfig->m_users->delUser(name);
}

void Security::addRole(const web::json::value &obj, std::string name)
{
    m_securityConfig->m_roles->addRole(obj, name);
}

void Security::delRole(const std::string &name)
{
    m_securityConfig->m_roles->delRole(name);
}

std::set<std::string> Security::getAllUserGroups() const
{
    return m_securityConfig->m_users->getGroups();
}

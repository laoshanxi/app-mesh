#include <ace/OS.h>

#include "../../common/Utility.h"
#include "Security.h"

std::shared_ptr<Security> Security::m_instance = nullptr;
std::recursive_mutex Security::m_mutex;
Security::Security()
{
}

Security::~Security()
{
}

std::shared_ptr<Security> Security::init()
{
    auto securityJsonFile = Utility::getParentDir() + ACE_DIRECTORY_SEPARATOR_STR + APPMESH_SECURITY_JSON_FILE;
    auto security = Security::FromJson(web::json::value::parse(Utility::readFileCpp(securityJsonFile)));
    Security::instance(security);
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
    for (auto user : this->UsersObject()->getUsers())
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
    return this->UsersObject()->getUser(userName);
}

std::shared_ptr<Users> Security::UsersObject() const
{
    return m_securityConfig->m_jwtUsers;
}

std::shared_ptr<Roles> Security::RolesObject() const
{
    return m_securityConfig->m_roles;
}

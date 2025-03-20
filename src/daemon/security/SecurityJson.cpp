#include "SecurityJson.h"
#include "../../common/Utility.h"
#include "../Configuration.h"

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

SecurityJson::SecurityJson()
{
    m_jsonSecurity = std::make_shared<JsonSecurity>();
}

SecurityJson::~SecurityJson() = default;

void SecurityJson::init()
{
    const auto securityYamlFile = Utility::getConfigFilePath(APPMESH_SECURITY_YAML_FILE);
    m_jsonSecurity = JsonSecurity::FromJson(Utility::yamlToJson(YAML::LoadFile(securityYamlFile)));
}

nlohmann::json SecurityJson::AsJson() const
{
    return this->m_jsonSecurity->AsJson();
}

bool SecurityJson::verifyUserKey(const std::string &userName, const std::string &userKey)
{
    const auto user = m_jsonSecurity->m_users->getUser(userName);
    return user && !user->locked() && user->verifyKey(userKey);
}

void SecurityJson::changeUserPasswd(const std::string &userName, const std::string &newPwd)
{
    m_jsonSecurity->m_users->getUser(userName)->updateKey(newPwd);
}

std::set<std::string> SecurityJson::getUserPermissions(const std::string &userName, const std::string &userGroup)
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

std::set<std::string> SecurityJson::getAllPermissions()
{
    std::set<std::string> permissionSet;
    for (const auto &role : m_jsonSecurity->m_roles->getRoles())
    {
        auto rolePerms = role.second->getPermissions();
        permissionSet.insert(rolePerms.begin(), rolePerms.end());
    }
    return permissionSet;
}

std::set<std::string> SecurityJson::getAllUserGroups() const
{
    return m_jsonSecurity->m_users->getGroups();
}

void SecurityJson::save()
{
    const static char fname[] = "SecurityJson::save() ";

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    std::string securityFile = APPMESH_SECURITY_YAML_FILE;

    try
    {
        auto content = m_jsonSecurity->AsJson();
        const auto securityYamlFile = Utility::getConfigFilePath(securityFile, true);
        auto tmpFile = Utility::runningInContainer() ? securityYamlFile : securityYamlFile + std::string(".") + std::to_string(Utility::getThreadId());

        std::ofstream ofs(tmpFile, std::ios::trunc);
        if (!ofs.is_open())
        {
            throw std::runtime_error("Could not open file for writing: " + tmpFile);
        }

        auto formatJson = Utility::jsonToYaml(content);
        ofs << formatJson;
        ofs.close();

        if (tmpFile != securityYamlFile)
        {
            if (ACE_OS::rename(tmpFile.c_str(), securityYamlFile.c_str()) != 0)
            {
                throw std::runtime_error("Failed to rename temporary file: " + std::string(std::strerror(errno)));
            }
            LOG_DBG << fname << "local security saved";
        }

        boost::filesystem::permissions(securityYamlFile, fs::perms::owner_all);
    }
    catch (const std::exception &ex)
    {
        LOG_ERR << fname << "Failed to save security information: " << ex.what();
    }
}

std::shared_ptr<User> SecurityJson::getUserInfo(const std::string &userName)
{
    return m_jsonSecurity->m_users->getUser(userName);
}

std::map<std::string, std::shared_ptr<User>> SecurityJson::getUsers() const
{
    return m_jsonSecurity->m_users->getUsers();
}

nlohmann::json SecurityJson::getUsersJson() const
{
    return m_jsonSecurity->m_users->AsJson();
}

nlohmann::json SecurityJson::getRolesJson() const
{
    return m_jsonSecurity->m_roles->AsJson();
}

std::shared_ptr<User> SecurityJson::addUser(const std::string &userName, const nlohmann::json &userJson)
{
    auto user = m_jsonSecurity->m_users->addUser(userName, userJson, m_jsonSecurity->m_roles);
    return user;
}

void SecurityJson::delUser(const std::string &name)
{
    m_jsonSecurity->m_users->delUser(name);
}

void SecurityJson::addRole(const nlohmann::json &obj, std::string name)
{
    m_jsonSecurity->m_roles->addRole(obj, name);
}

void SecurityJson::delRole(const std::string &name)
{
    m_jsonSecurity->m_roles->delRole(name);
}

std::shared_ptr<Role> SecurityJson::getRole(const std::string &roleName)
{
    return m_jsonSecurity->m_roles->getRole(roleName);
}

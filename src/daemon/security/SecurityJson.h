#pragma once

#include "Security.h"
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

struct JsonSecurity;
class User;
class Role;

/**
 * @brief Security implementation using local JSON storage
 */
class SecurityJson : public Security
{
public:
    SecurityJson();
    virtual ~SecurityJson() override;
    virtual void init() override;

public:
    virtual nlohmann::json AsJson() const;
    virtual void save() override;
    virtual bool encryptKey() { return m_jsonSecurity->m_encryptKey; }

    // Authentication
    virtual bool verifyUserKey(const std::string &userName, const std::string &userKey) override;
    virtual void changeUserPasswd(const std::string &userName, const std::string &newPwd) override;

    // User management
    virtual std::shared_ptr<User> getUserInfo(const std::string &userName);
    virtual std::map<std::string, std::shared_ptr<User>> getUsers() const;
    virtual nlohmann::json getUsersJson() const;
    virtual std::shared_ptr<User> addUser(const std::string &userName, const nlohmann::json &userJson);
    virtual void delUser(const std::string &name);

    // Role management
    virtual nlohmann::json getRolesJson() const;
    virtual void addRole(const nlohmann::json &obj, std::string name);
    virtual void delRole(const std::string &name);
    virtual std::shared_ptr<Role> getRole(const std::string &roleName);

    // Permission management
    virtual std::set<std::string> getAllUserGroups() const;
    virtual std::set<std::string> getUserPermissions(const std::string &userName, const std::string &userGroup);
    virtual std::set<std::string> getAllPermissions();

protected:
    std::shared_ptr<JsonSecurity> m_jsonSecurity;
    std::recursive_mutex m_mutex;
};

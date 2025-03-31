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
    virtual bool encryptKey() override { return m_jsonSecurity->m_encryptKey; }

    // Authentication
    virtual bool verifyUserKey(const std::string &userName, const std::string &userKey) override;
    virtual void changeUserPasswd(const std::string &userName, const std::string &newPwd) override;

    // User management
    virtual std::shared_ptr<User> getUserInfo(const std::string &userName) override;
    virtual std::map<std::string, std::shared_ptr<User>> getUsers() const override;
    virtual nlohmann::json getUsersJson() const override;
    virtual std::shared_ptr<User> addUser(const std::string &userName, const nlohmann::json &userJson) override;
    virtual void delUser(const std::string &name) override;

    // Role management
    virtual nlohmann::json getRolesJson() const override;
    virtual void addRole(const nlohmann::json &obj, std::string name) override;
    virtual void delRole(const std::string &name) override;
    virtual std::shared_ptr<Role> getRole(const std::string &roleName) override;

    // Permission management
    virtual std::set<std::string> getAllUserGroups() const override;
    virtual std::set<std::string> getUserPermissions(const std::string &userName, const std::string &userGroup) override;
    virtual std::set<std::string> getAllPermissions() override;

protected:
    std::shared_ptr<JsonSecurity> m_jsonSecurity;
    std::recursive_mutex m_mutex;
};

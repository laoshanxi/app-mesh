#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <string>

#include "User.h"

#define NOT_APPLICABLE_THROW                                    \
    override                                                    \
    {                                                           \
        throw std::invalid_argument("not applicable function"); \
    }

class Security
{
public:
    // Virtual destructor to ensure proper destruction of derived class objects
    virtual ~Security() = default;
    virtual void init() = 0;
    virtual void save() = 0;
    virtual bool encryptKey() { return false; };

    // Global singleton instance management
    static void init(const std::string &interface);
    static std::shared_ptr<Security> instance();
    static void instance(std::shared_ptr<Security> instance);

    // Authentication
    virtual bool verifyUserKey(const std::string &userName, const std::string &userKey) = 0;
    virtual void changeUserPasswd(const std::string &userName, const std::string &newPwd) = 0;

    // User management
    virtual std::shared_ptr<User> getUserInfo(const std::string &userName) = 0;
    virtual std::map<std::string, std::shared_ptr<User>> getUsers() const = 0;
    virtual nlohmann::json getUsersJson() const = 0;
    virtual std::shared_ptr<User> addUser(const std::string &userName, const nlohmann::json &userJson) = 0;
    virtual void delUser(const std::string &name) = 0;

    // Role management
    virtual nlohmann::json getRolesJson() const = 0;
    virtual void addRole(const nlohmann::json &obj, std::string name) = 0;
    virtual void delRole(const std::string &name) = 0;
    virtual std::shared_ptr<Role> getRole(const std::string &roleName) = 0;

    // Permission management
    virtual std::set<std::string> getAllUserGroups() const = 0;
    virtual std::set<std::string> getUserPermissions(const std::string &userName, const std::string &userGroup) = 0;
    virtual std::set<std::string> getAllPermissions() = 0;

    // Prevent direct instantiation of this class
    Security() = default;

private:
    // Disable copy and assignment
    Security(const Security &) = delete;
    Security &operator=(const Security &) = delete;
    Security(Security &&) = delete;
    Security &operator=(Security &&) = delete;

    static std::shared_ptr<Security> m_instance;
    static std::recursive_mutex m_mutex;
};

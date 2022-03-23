#pragma once

#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <cpprest/json.h>

#include "User.h"

//////////////////////////////////////////////////////////////////////////
/// Security base implementation based on local JSON file
//////////////////////////////////////////////////////////////////////////
class Security
{
protected:
    explicit Security(std::shared_ptr<JsonSecurity> jsonSecurity);

public:
    virtual ~Security();
    virtual web::json::value AsJson() const;
    static std::shared_ptr<Security> FromJson(const web::json::value &obj) noexcept(false);
    virtual void save(const std::string &interface);
    virtual bool encryptKey();
    static void init(const std::string &interface);
    static std::shared_ptr<Security> instance();
    static void instance(std::shared_ptr<Security> instance);

public:
    virtual bool verifyUserKey(const std::string &userName, const std::string &userKey, std::string &outUserGroup);
    virtual void changeUserPasswd(const std::string &userName, const std::string &newPwd);

    virtual std::shared_ptr<User> getUserInfo(const std::string &userName);
    virtual std::map<std::string, std::shared_ptr<User>> getUsers() const;
    virtual web::json::value getUsersJson() const;
    virtual std::shared_ptr<User> addUser(const std::string &userName, const web::json::value &userJson);
    virtual void delUser(const std::string &name);

    virtual web::json::value getRolesJson() const;
    virtual void addRole(const web::json::value &obj, std::string name);
    virtual void delRole(const std::string &name);

    virtual std::set<std::string> getAllUserGroups() const;
    virtual std::set<std::string> getUserPermissions(const std::string &userName, const std::string &userGroup);
    virtual std::set<std::string> getAllPermissions();

private:
    std::shared_ptr<JsonSecurity> m_securityConfig;
    static std::shared_ptr<Security> m_instance;
    static std::recursive_mutex m_mutex;
};

#pragma once

#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

#include "../../../common/TimerHandler.h"
#include "../SecurityJson.h"

namespace Ldap
{
    class Server;
}
struct JsonLdap;

/**
 * @brief Security implemention with LDAP authentication and authorization
 */
class SecurityLDAP : public SecurityJson, public TimerHandler
{
public:
    explicit SecurityLDAP();
    virtual ~SecurityLDAP() = default;

    void init() override;
    virtual void save() NOT_APPLICABLE_THROW;
    bool syncGroupUsers();

public:
    // Authentication
    virtual bool verifyUserKey(const std::string &userName, const std::string &userKey) override;
    virtual void changeUserPasswd(const std::string &userName, const std::string &newPwd) NOT_APPLICABLE_THROW;

    // User management
    virtual std::shared_ptr<User> getUserInfo(const std::string &userName) override;
    virtual std::map<std::string, std::shared_ptr<User>> getUsers() const NOT_APPLICABLE_THROW;
    virtual nlohmann::json getUsersJson() const NOT_APPLICABLE_THROW;
    virtual std::shared_ptr<User> addUser(const std::string &userName, const nlohmann::json &userJson) NOT_APPLICABLE_THROW;
    virtual void delUser(const std::string &name) NOT_APPLICABLE_THROW;

    // Role management
    virtual nlohmann::json getRolesJson() const NOT_APPLICABLE_THROW;
    virtual void addRole(const nlohmann::json &obj, std::string name) NOT_APPLICABLE_THROW;
    virtual void delRole(const std::string &name) NOT_APPLICABLE_THROW;

    // Permission management
    virtual std::set<std::string> getAllUserGroups() const override;
    virtual std::set<std::string> getUserPermissions(const std::string &userName, const std::string &userGroup) override;
    virtual std::set<std::string> getAllPermissions() override;

private:
    std::shared_ptr<Ldap::Server> connect();

private:
    std::shared_ptr<JsonLdap> m_ldap; ///< LDAP configuration
    std::atomic_long m_syncTimerId;   ///< Timer ID for periodic sync
};

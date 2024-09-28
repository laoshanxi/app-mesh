#pragma once

#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

#include "../../../common/TimerHandler.h"
#include "../Security.h"

#define NOT_APPLICABLE_THROW                                                   \
    override                                                                   \
    {                                                                          \
        throw std::invalid_argument("not applicable for LDAP authentication"); \
    }

namespace Ldap
{
    class Server;
}
struct JsonLdap;
//////////////////////////////////////////////////////////////////////////
/// LdapImpl
//////////////////////////////////////////////////////////////////////////
class LdapImpl : public Security, public TimerHandler
{
public:
    explicit LdapImpl(std::shared_ptr<JsonLdap> ldap);
    virtual ~LdapImpl();

    virtual bool encryptKey() override { return true; };

    virtual nlohmann::json AsJson() const override;
    static std::shared_ptr<LdapImpl> FromJson(const nlohmann::json &obj) noexcept(false);

    static void init(const std::string &interface);
    bool syncGroupUsers();

public:
    virtual bool verifyUserKey(const std::string &userName, const std::string &userKey) override;
    virtual void changeUserPasswd(const std::string &userName, const std::string &newPwd) NOT_APPLICABLE_THROW;

    virtual std::shared_ptr<User> getUserInfo(const std::string &userName) override;
    virtual std::map<std::string, std::shared_ptr<User>> getUsers() const NOT_APPLICABLE_THROW;
    virtual nlohmann::json getUsersJson() const NOT_APPLICABLE_THROW;
    virtual std::shared_ptr<User> addUser(const std::string &userName, const nlohmann::json &userJson) NOT_APPLICABLE_THROW;
    virtual void delUser(const std::string &name) NOT_APPLICABLE_THROW;

    virtual nlohmann::json getRolesJson() const NOT_APPLICABLE_THROW;
    virtual void addRole(const nlohmann::json &obj, std::string name) NOT_APPLICABLE_THROW;
    virtual void delRole(const std::string &name) NOT_APPLICABLE_THROW;

    virtual std::set<std::string> getAllUserGroups() const override;
    virtual std::set<std::string> getUserPermissions(const std::string &userName, const std::string &userGroup) override;
    virtual std::set<std::string> getAllPermissions() override;

private:
    std::shared_ptr<Ldap::Server> connect();

private:
    std::shared_ptr<JsonLdap> m_ldap;
    std::atomic_long m_syncTimerId;
};

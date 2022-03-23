#pragma once

#include <cpprest/json.h>
#include <mutex>
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
class JsonLdap;
//////////////////////////////////////////////////////////////////////////
/// LdapImpl
//////////////////////////////////////////////////////////////////////////
class LdapImpl : public Security, public TimerHandler
{
public:
    explicit LdapImpl(std::shared_ptr<JsonLdap> ldap);
    virtual ~LdapImpl();

    virtual bool encryptKey() override { return true; };

    virtual web::json::value AsJson() const override;
    static std::shared_ptr<LdapImpl> FromJson(const web::json::value &obj) noexcept(false);

    static void init(const std::string &interface);
    void syncGroupUsers(int timerId = INVALID_TIMER_ID);

public:
    virtual bool verifyUserKey(const std::string &userName, const std::string &userKey, std::string &outUserGroup) override;
    virtual void changeUserPasswd(const std::string &userName, const std::string &newPwd) NOT_APPLICABLE_THROW;

    virtual std::shared_ptr<User> getUserInfo(const std::string &userName);
    virtual std::map<std::string, std::shared_ptr<User>> getUsers() const NOT_APPLICABLE_THROW;
    virtual web::json::value getUsersJson() const NOT_APPLICABLE_THROW;
    virtual std::shared_ptr<User> addUser(const std::string &userName, const web::json::value &userJson) NOT_APPLICABLE_THROW;
    virtual void delUser(const std::string &name) NOT_APPLICABLE_THROW;

    virtual web::json::value getRolesJson() const NOT_APPLICABLE_THROW;
    virtual void addRole(const web::json::value &obj, std::string name) NOT_APPLICABLE_THROW;
    virtual void delRole(const std::string &name) NOT_APPLICABLE_THROW;

    virtual std::set<std::string> getAllUserGroups() const override;
    virtual std::set<std::string> getUserPermissions(const std::string &userName, const std::string &userGroup) override;
    virtual std::set<std::string> getAllPermissions() override;

private:
    std::shared_ptr<Ldap::Server> connect();

private:
    std::shared_ptr<JsonLdap> m_ldap;
    int m_syncTimerId;
};

// src/sdk/cpp/ClientHttp.h
#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>

#include <nlohmann/json.hpp>

#include "../../common/Utility.h"

struct CurlResponse;

struct AppOutput
{
    int statusCode = 0;
    std::string output;
    int outputPosition = 0;
    std::shared_ptr<int> exitCode;
};

class ClientHttp;

// TODO: forward
struct AppRun
{
    AppRun(ClientHttp *client, const std::string &appName, const std::string &procUid);

    ClientHttp *m_client;
    const std::string m_appName;
    const std::string m_procUid;

    std::shared_ptr<int> wait(int timeout = 0, bool printToSTD = true);
};

class ClientHttp
{
public:
    ClientHttp() = default;
    virtual ~ClientHttp() = default;

    // Session/Client
    void init(const std::string url = "https://127.0.0.1:6060",
              const std::string ssl_verify = "ssl/ca.pem",
              const std::string ssl_client_cert = "ssl/client.pem",
              const std::string ssl_client_certkey = "ssl/client-key.pem",
              const std::string cookieFile = ""); // cookieFile is not thread-safe
    void forwardTo(const std::string url = "");

    // Authentication Management
    std::string login(const std::string &user, const std::string &passwd,
                      const std::string totp = "", int timeoutSeconds = 0,
                      std::string audience = "");
    void validateTotp(const std::string &user, const std::string &challenge,
                      const std::string totp, int timeoutSeconds);
    std::tuple<bool, std::string> authenticate(const std::string &token,
                                               const std::string permission = "",
                                               const std::string audience = "",
                                               bool apply = true);
    void logout();
    void renewToken(int timeoutSeconds = 0);
    std::string getTotpSecret();
    void enableTotp(const std::string totp);
    void disableTotp(const std::string user = "self");

    // Application View
    nlohmann::json getApp(const std::string &app) const;
    nlohmann::json listApps() const;
    AppOutput getAppOutput(const std::string &app, int outputPosition = 0,
                           int stdoutIndex = 0, int stdoutMaxsize = 10240,
                           const std::string &processUuid = "", int timeout = 0) const;
    bool checkAppHealth(const std::string &app) const;

    // Application Manage
    nlohmann::json addApp(const nlohmann::json &app);
    void deleteApp(const std::string &app);
    void enableApp(const std::string &app);
    void disableApp(const std::string &app);

    // Run Application Operations
    std::tuple<std::shared_ptr<int>, std::string> runAppSync(const nlohmann::json &app,
                                                             int maxTimeout = 60 * 60 * 24,
                                                             int lifeCycleSeconds = 60 * 60 * 24 * 2);
    AppRun runAppAsync(const nlohmann::json &app,
                       int maxTimeout = 60 * 60 * 24,
                       int lifeCycleSeconds = 60 * 60 * 24 * 2);
    std::shared_ptr<int> waitForAsyncRun(AppRun *run, int timeout = 0, bool printToSTD = true);
    std::string runTask(const std::string &app, const nlohmann::json &data, int timeout);
    bool cancelTask(const std::string &app);

    // File Management
    void downloadFile(const std::string &remoteFile, const std::string &localFile, bool preservePermissions = true);
    void uploadFile(const std::string &localFile, const std::string &remoteFile, bool preservePermissions = true);

    // System Management
    nlohmann::json getHostResources() const;
    nlohmann::json getConfig() const;
    nlohmann::json setConfig(const nlohmann::json &config);
    std::string setLogLevel(const std::string &level);
    std::string getMetrics();

    // Tag Management
    nlohmann::json getTags() const;
    void addTag(const std::string &tag, const std::string &value);
    void deleteTag(const std::string &tag);

    // User Management
    void updatePassword(const std::string oldPwd, const std::string newPwd, const std::string user = "self");
    nlohmann::json getCurrentUser() const;
    nlohmann::json listUsers() const;
    void addUser(const nlohmann::json &user);
    void deleteUser(const std::string &user);
    void lockUser(const std::string user);
    void unlockUser(const std::string user);
    std::set<std::string> getUserPermissions();
    std::set<std::string> listPermissions();
    std::map<std::string, std::set<std::string>> listRoles();
    std::set<std::string> listGroups();
    void updateRole(const std::string &role, std::set<std::string> rolePermissions);
    void deleteRole(const std::string &role);

protected:
    std::shared_ptr<CurlResponse> requestHttp(bool throwOnFail,
                                              const web::http::method &mtd,
                                              const std::string &path,
                                              const nlohmann::json *body = nullptr,
                                              std::map<std::string, std::string> header = {},
                                              std::map<std::string, std::string> query = {}) const;
    void addCommonHeaders(std::map<std::string, std::string> &header) const;

private:
    std::string m_url;
    std::string m_forwardTo;
};

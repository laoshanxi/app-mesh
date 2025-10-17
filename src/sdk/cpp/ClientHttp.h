#pragma once

#include <map>
#include <memory>
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

// TODO: forward
class ClientHttp;

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

    void init(const std::string url = "https://127.0.0.1:6060",
              const std::string ssl_verify = "ssl/ca.pem",
              const std::string ssl_client_cert = "ssl/client.pem",
              const std::string ssl_client_certkey = "ssl/client-key.pem",
              const std::string cookieFile = "");
    void forwardTo(const std::string url = "");

    std::string login(const std::string &user, const std::string &passwd,
                      const std::string totp = "", int timeoutSeconds = 0,
                      std::string audience = "");
    void validateTotp(const std::string &user, const std::string &challenge,
                      const std::string totp, int timeoutSeconds);
    std::tuple<bool, std::string> authenticate(const std::string &token,
                                               const std::string permission = "",
                                               const std::string audience = "",
                                               bool apply = true);
    void logoff();
    void renewToken(int timeoutSeconds = 0);
    std::string getTotpSecret();
    void setupTotp(const std::string totp);
    void disableTotp(const std::string user = "self");

    void updatePassword(const std::string oldPwd, const std::string newPwd,
                        const std::string user = "self");
    nlohmann::json viewSelf() const;
    nlohmann::json viewUsers() const;
    void addUser(const nlohmann::json &user);
    void lockUser(const std::string user);
    void unlockUser(const std::string user);

    nlohmann::json viewAllApp() const;
    nlohmann::json viewApp(const std::string &app) const;
    AppOutput getAppOutput(const std::string &app, int outputPosition = 0,
                           int stdoutIndex = 0, int stdoutMaxsize = 10240,
                           const std::string &processUuid = "", int timeout = 0) const;
    nlohmann::json addApp(const nlohmann::json &app);
    void deleteApp(const std::string &app);
    bool checkAppHealth(const std::string &app) const;
    void enableApp(const std::string &app);
    void disableApp(const std::string &app);

    std::tuple<std::shared_ptr<int>, std::string> runAppSync(const nlohmann::json &app,
                                                             int maxTimeout = 60 * 60 * 24,
                                                             int lifeCycleSeconds = 60 * 60 * 24 * 2);
    AppRun runAppAsync(const nlohmann::json &app,
                       int maxTimeout = 60 * 60 * 24,
                       int lifeCycleSeconds = 60 * 60 * 24 * 2);
    std::shared_ptr<int> waitForAsyncRun(AppRun *run, int timeout = 1, bool printToSTD = true);

    nlohmann::json viewHostResources() const;
    nlohmann::json viewConfig() const;
    nlohmann::json setConfig(const nlohmann::json &config);

    nlohmann::json viewTags() const;
    void addTag(const std::string &tag, const std::string &value);
    void deleteTag(const std::string &tag);

protected:
    std::shared_ptr<CurlResponse> requestHttp(bool shouldThrow,
                                              const web::http::method &mtd,
                                              const std::string &path,
                                              const nlohmann::json *body = nullptr,
                                              std::map<std::string, std::string> header = {},
                                              std::map<std::string, std::string> query = {}) const;

    static std::string parseUrlHost(const std::string &url);
    static std::string parseUrlPort(const std::string &url);

private:
    std::string m_url;
    std::string m_forwardTo;
};

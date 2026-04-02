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

/// Result of an asynchronous application run, used to monitor and retrieve output.
struct AppRun
{
    AppRun(ClientHttp *client, const std::string &appName, const std::string &procUid);

    ClientHttp *m_client;
    const std::string m_appName;
    const std::string m_procUid;

    /// Wait for the asynchronous run to complete.
    /// Temporarily restores the forward_to target that was active at run creation,
    /// ensuring output queries reach the correct cluster node.
    std::shared_ptr<int> wait(int timeout = 0, bool printToStdout = true);

private:
    std::string m_forwardTo; ///< Saved forward_to target from run creation time
};

class ClientHttp
{
public:
    ClientHttp() = default;
    virtual ~ClientHttp() = default;

    // Session/Client
    /// Configure the REST endpoint, TLS material, and optional cookie persistence.
    /// This only prepares the client; it does not authenticate with the server.
    void init(const std::string &url = "https://127.0.0.1:6060",
              const std::string &ssl_verify = "ssl/ca.pem",
              const std::string &ssl_client_cert = "ssl/client.pem",
              const std::string &ssl_client_certkey = "ssl/client-key.pem",
              const std::string &cookieFile = ""); // cookieFile is not thread-safe
    /// Set the cluster forwarding target used for subsequent requests.
    /// If the port is omitted, the current service port is used.
    void forwardTo(const std::string &url = "");
    const std::string &getForwardTo() const;

    // Authentication Management
    /// Login with username/password.
    /// Returns a TOTP challenge string on HTTP 428 when no valid TOTP code is supplied;
    /// otherwise returns an empty string after updating this client session token.
    std::string login(const std::string &username, const std::string &password,
                      const std::string &totp = "", int tokenExpire = 7 * 24 * 60 * 60,
                      const std::string &audience = "");
    /// Complete a TOTP challenge and store the returned JWT in this client session.
    void validateTotp(const std::string &username, const std::string &challenge,
                      const std::string &totp, int tokenExpire);
    /// Verify a JWT token with the server and optionally check permission/audience.
    /// When updateSession is true and verification succeeds, the token is also persisted into this client.
    std::tuple<bool, std::string> authenticate(const std::string &token,
                                               const std::string &permission = "",
                                               const std::string &audience = "",
                                               bool updateSession = true);
    /// Log out of the current session and clear locally stored token state.
    void logout();
    /// Renew the JWT token already attached to this client session.
    void renewToken(int tokenExpire = 0);
    /// Return the raw TOTP secret for the current user.
    std::string getTotpSecret();
    /// Enable TOTP for the current user and refresh the session token.
    void enableTotp(const std::string &totp);
    void disableTotp(const std::string &user = "self");

    // Application View
    nlohmann::json getApp(const std::string &app) const;
    nlohmann::json listApps() const;
    /// Fetch incremental stdout/stderr for a running or completed process.
    /// outputPosition is the next cursor to read from; exitCode is populated once the process exits.
    AppOutput getAppOutput(const std::string &app, int outputPosition = 0,
                           int stdoutIndex = 0, int stdoutMaxsize = 10240,
                           const std::string &processUuid = "", int timeout = 0) const;
    bool checkAppHealth(const std::string &app) const;

    // Application Manage
    nlohmann::json addApp(const nlohmann::json &app);
    bool deleteApp(const std::string &app);
    void enableApp(const std::string &app);
    void disableApp(const std::string &app);

    // Run Application Operations
    /// Run an application synchronously and return {exitCode, stdoutText}.
    std::tuple<std::shared_ptr<int>, std::string> runAppSync(const nlohmann::json &app,
                                                             int maxTime = 60 * 60 * 24 * 2,
                                                             int lifecycle = 60 * 60 * 24 * 2 + 60 * 60 * 12);
    /// Run an application asynchronously and return a handle that snapshots the current forward target.
    AppRun runAppAsync(const nlohmann::json &app,
                       int maxTime = 60 * 60 * 24 * 2,
                       int lifecycle = 60 * 60 * 24 * 2 + 60 * 60 * 12);
    /// Poll an async run until completion or timeout.
    /// On success, the implementation may best-effort remove the temporary run app.
    std::shared_ptr<int> waitForAsyncRun(AppRun *run, int timeout = 0, bool printToStdout = true);
    /// Send a payload to a running application task endpoint and wait for the response body.
    std::string runTask(const std::string &app, const nlohmann::json &data, int timeout);
    bool cancelTask(const std::string &app);

    // File Management
    /// Download a remote file and optionally apply returned POSIX metadata locally.
    void downloadFile(const std::string &remoteFile, const std::string &localFile, bool preservePermissions = true);
    /// Upload a local file and optionally send local POSIX metadata for server-side recreation.
    void uploadFile(const std::string &localFile, const std::string &remoteFile, bool preservePermissions = true);

    // System Management
    nlohmann::json getHostResources() const;
    nlohmann::json getConfig() const;
    nlohmann::json setConfig(const nlohmann::json &config);
    std::string setLogLevel(const std::string &level);
    std::string getMetrics() const;

    // Label Management
    nlohmann::json getLabels() const;
    void addLabel(const std::string &label, const std::string &value);
    void deleteLabel(const std::string &label);

    // User Management
    void updatePassword(const std::string &oldPwd, const std::string &newPwd, const std::string &user = "self");
    nlohmann::json getCurrentUser() const;
    nlohmann::json listUsers() const;
    void addUser(const nlohmann::json &user);
    void deleteUser(const std::string &user);
    void lockUser(const std::string &user);
    void unlockUser(const std::string &user);
    std::set<std::string> getUserPermissions() const;
    std::set<std::string> listPermissions() const;
    std::map<std::string, std::set<std::string>> listRoles() const;
    std::set<std::string> listGroups() const;
    void updateRole(const std::string &role, const std::set<std::string> &rolePermissions);
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

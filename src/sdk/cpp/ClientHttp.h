// src/sdk/cpp/ClientHttp.h
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>

#include <nlohmann/json.hpp>

struct CurlResponse;

/// HTTP failure carrying the response status code and body text.
/// Derives from std::invalid_argument so existing catch sites keep working.
class AppMeshHttpError : public std::invalid_argument
{
public:
    AppMeshHttpError(int statusCode, const std::string &body) : std::invalid_argument(body), m_statusCode(statusCode) {}
    int statusCode() const { return m_statusCode; }

private:
    int m_statusCode;
};

struct AppOutput
{
    int statusCode = 0;
    std::string output;
    int64_t outputPosition = 0;
    std::shared_ptr<int> exitCode; ///< nullptr = process has not exited yet
};

class AppMeshClient;

/// Callback for incremental stdout output.
/// @param data  text chunk
/// @param position  byte offset in the full output stream
using OutputHandler = std::function<void(const std::string &data, int64_t position)>;

/// Result of an asynchronous application run, used to monitor and retrieve output.
/// The AppMeshClient passed at construction is NOT owned and must outlive this AppRun.
struct AppRun
{
    AppRun(AppMeshClient *client, const std::string &appName, const std::string &procUid);

    const std::string &appName() const { return m_appName; }
    const std::string &procUid() const { return m_procUid; }

    /// Wait for the asynchronous run to complete.
    /// Temporarily restores the forward_to target that was active at run creation,
    /// ensuring output queries reach the correct cluster node.
    /// Returns the process exit code, or nullptr on timeout (not exited);
    /// throws AppMeshHttpError on HTTP/transport error.
    std::shared_ptr<int> wait(OutputHandler stdoutHandler = nullptr, int timeout = 0);

private:
    AppMeshClient *m_client; ///< Non-owning; must outlive this AppRun
    const std::string m_appName;
    const std::string m_procUid;
    std::string m_forwardTo; ///< Saved forward_to target from run creation time
};

/// Connection settings for AppMeshClient.
/// No transport timeout knob here: RestClient hardcodes a process-global request
/// timeout of 200s (1000s for file transfer); see src/common/RestClient.cpp.
struct ClientHttpConfig
{
    std::string url = "https://127.0.0.1:6060";
    /// Trusted CA cert file or directory; empty = system trust store. An absent default
    /// path falls back to the system trust store (verification stays on); any other
    /// missing/unreadable path is a hard error, never a silent fallback to no-verification.
    std::string caCertPath = "ssl/ca.pem";
    /// The ONLY way to disable server certificate verification.
    bool verifyServer = true;
    std::string clientCert = "ssl/client.pem";
    std::string clientKey = "ssl/client-key.pem";
    /// Empty keeps the session cookie in memory; file storage is not thread-safe.
    std::string cookieFile;
};

/// IMPORTANT: RestClient state is process-global (static): all AppMeshClient instances
/// share ONE session/SSL configuration and ONE credential cookie jar (incl. the login
/// token); constructing another client with different settings silently
/// reconfigures every instance. Only one logically-distinct client per process.
/// Transport timeouts: RestClient hardcodes a process-global 200s request timeout
/// (1000s for file transfer); the `timeout` params on getAppOutput()/runTask() are
/// server-side long-poll/task timeouts, NOT transport timeouts.
class AppMeshClient
{
public:
    AppMeshClient() = default;
    /// Configure endpoint, TLS material, and optional cookie persistence (no authentication;
    /// reconfigures the process-global RestClient state, see class note).
    /// Throws std::invalid_argument when config.verifyServer is true and config.caCertPath
    /// is a missing/unreadable non-default path (absent default = system trust store).
    explicit AppMeshClient(const ClientHttpConfig &config);
    virtual ~AppMeshClient() = default;

    // Session/Client
    /// Set the cluster forwarding target used for subsequent requests.
    /// If the port is omitted, the current service port is used.
    void setForwardTo(const std::string &url = "");
    const std::string &getForwardTo() const;

    // Authentication Management
    /// Login with username/password.
    /// Returns a TOTP challenge string on HTTP 428; empty string on success (JWT persisted
    /// to the process-global cookie jar, see getAuthToken()). Throws AppMeshHttpError otherwise.
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
    /// Return the JWT from the (process-global) session cookie jar; empty when not logged in.
    std::string getAuthToken() const;
    /// Return the TOTP provisioning URI (otpauth://totp/...) for the current user.
    std::string getTotpUri();
    /// Enable TOTP for the current user and refresh the session token.
    void enableTotp(const std::string &totp);
    void disableTotp(const std::string &user = "self");

    // Application View
    nlohmann::json getApp(const std::string &app) const;
    nlohmann::json listApps() const;
    /// Fetch incremental stdout/stderr for a running or completed process.
    /// outputPosition is the next read cursor; exitCode is populated once the process
    /// exits (nullptr = not exited). timeout is a server-side long-poll timeout (seconds).
    AppOutput getAppOutput(const std::string &app, int64_t outputPosition = 0,
                           int stdoutIndex = 0, int stdoutMaxsize = 10240,
                           const std::string &processUuid = "", int timeout = 0) const;
    bool checkAppHealth(const std::string &app) const;

    // Application Manage
    nlohmann::json addApp(const nlohmann::json &app);
    /// Remove an application.
    /// Returns true when deleted, false when not found (404); throws AppMeshHttpError otherwise.
    bool deleteApp(const std::string &app);
    /// Enable an application. Throws AppMeshHttpError on failure.
    void enableApp(const std::string &app);
    /// Disable an application. Throws AppMeshHttpError on failure.
    void disableApp(const std::string &app);

    // Run Application Operations
    /// Run an application synchronously and return {exitCode, stdoutText}.
    /// exitCode is nullptr when the server reported no exit code (process not exited).
    std::tuple<std::shared_ptr<int>, std::string> runAppSync(const nlohmann::json &app,
                                                             int maxTime = 60 * 60 * 24 * 2,
                                                             int lifecycle = 60 * 60 * 24 * 2 + 60 * 60 * 12);
    /// Run an application asynchronously and return a handle that snapshots the current forward target.
    AppRun runAppAsync(const nlohmann::json &app,
                       int maxTime = 60 * 60 * 24 * 2,
                       int lifecycle = 60 * 60 * 24 * 2 + 60 * 60 * 12);
    /// Poll an async run until completion or timeout.
    /// Returns the exit code, or nullptr on timeout (not exited); throws AppMeshHttpError
    /// on HTTP/transport error.
    /// On success may best-effort remove the temp run app. Throws std::invalid_argument on null run.
    std::shared_ptr<int> waitForAsyncRun(AppRun *run, OutputHandler stdoutHandler = nullptr, int timeout = 0);
    /// Send a payload to a running application task endpoint and wait for the response body.
    /// timeout is a server-side task timeout (seconds), not a transport timeout.
    std::string runTask(const std::string &app, const nlohmann::json &data, int timeout);
    /// Cancel the pending task of an application.
    /// Returns true when cancelled, false when no task to cancel (404); throws AppMeshHttpError otherwise.
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
    nlohmann::json listLabels() const;
    void addLabel(const std::string &label, const std::string &value);
    void deleteLabel(const std::string &label);

    // User Management
    void updatePassword(const std::string &oldPwd, const std::string &newPwd, const std::string &user = "self");
    nlohmann::json getCurrentUser() const;
    nlohmann::json listUsers() const;
    void addUser(const std::string &username, const nlohmann::json &user);
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
    /// Whether a non-2xx response throws AppMeshHttpError or is returned to the caller.
    enum class ErrorPolicy
    {
        Throw, ///< non-OK status throws AppMeshHttpError
        Return ///< the raw response is returned for caller-side status handling
    };
    std::shared_ptr<CurlResponse> requestHttp(ErrorPolicy errorPolicy,
                                              const std::string &method,
                                              const std::string &path,
                                              const nlohmann::json *body = nullptr,
                                              std::map<std::string, std::string> header = {},
                                              std::map<std::string, std::string> query = {}) const;
    void addCommonHeaders(std::map<std::string, std::string> &header) const;

private:
    void applyConfig(const ClientHttpConfig &config);

    std::string m_url;
    std::string m_forwardTo;
};

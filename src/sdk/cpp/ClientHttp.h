// src/sdk/cpp/ClientHttp.h
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>

#include <nlohmann/json.hpp>

struct CurlResponse;

/// HTTP failure carrying the response status code and body text (derives from std::invalid_argument).
class AppMeshHttpError : public std::invalid_argument
{
public:
    AppMeshHttpError(int statusCode, const std::string &body) : std::invalid_argument(body), m_statusCode(statusCode) {}
    int statusCode() const { return m_statusCode; }

private:
    int m_statusCode;
};

/// Provides access tokens to AppMeshClient. Providers own token acquisition and
/// refresh; only the resulting access token crosses this boundary into the client
/// (refresh credentials stay provider-private).
class TokenProvider
{
public:
    virtual ~TokenProvider() = default;
    /// Return a current access token, refreshing before expiry when possible.
    virtual std::string getAccessToken() = 0;
    /// Whether this provider can replace a rejected or expiring token.
    virtual bool canRefresh() const { return false; }
    /// Replace a rejected token; called at most once per HTTP 401. Use the
    /// rejected token to avoid duplicate refreshes when requests race.
    virtual std::string refreshAccessToken(const std::string &rejectedToken)
    {
        (void)rejectedToken;
        return getAccessToken();
    }
    /// Forget provider-owned in-memory token state.
    virtual void clear() {}
};

/// In-memory provider for a caller-supplied, non-refreshing access token.
class StaticAccessTokenProvider : public TokenProvider
{
public:
    explicit StaticAccessTokenProvider(const std::string &token)
    {
        const auto begin = token.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos)
            throw std::invalid_argument("bearer token must be a non-empty string");
        m_token = token.substr(begin, token.find_last_not_of(" \t\r\n") - begin + 1);
    }
    std::string getAccessToken() override
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        return m_token;
    }
    void clear() override
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        m_token.clear();
    }

private:
    std::mutex m_mutex;
    std::string m_token;
};

/// Configuration for RefreshTokenProvider.
struct RefreshTokenConfig
{
    std::string tokenUrl;     ///< Token endpoint, e.g. https://host:6060/auth/token
    std::string clientId;     ///< OAuth public client id; defaults to "appmesh-cli" when empty
    std::string accessToken;  ///< Current access token
    std::string refreshToken; ///< Refresh credential; kept provider-private, never logged
    long expiresIn = 0;       ///< Access-token lifetime in seconds; 0/unknown = refresh only on HTTP 401
    // TLS verification follows the process-global RestClient SSL configuration
    // installed by AppMeshClient (ClientHttpConfig::verifyServer / caCertPath).
};

/// TokenProvider that refreshes an access token via the OAuth 2.0 refresh-token
/// grant (RFC 6749 section 6) against a caller-supplied token endpoint.
class RefreshTokenProvider : public TokenProvider
{
public:
    /// Throws std::invalid_argument unless tokenUrl is HTTPS, or HTTP on a loopback host.
    explicit RefreshTokenProvider(const RefreshTokenConfig &config);
    /// Return the current access token, refreshing proactively shortly before expiry.
    std::string getAccessToken() override;
    bool canRefresh() const override;
    /// Refresh a rejected token, coalescing with a racing caller that already refreshed.
    std::string refreshAccessToken(const std::string &rejectedToken) override;
    /// Forget both tokens.
    void clear() override;

private:
    /// Perform the refresh grant; caller must hold m_mutex. Throws std::runtime_error
    /// on failure; token state is cleared only on invalid_grant.
    void refreshLocked();

    mutable std::mutex m_mutex;
    std::string m_tokenUrl;
    std::string m_clientId;
    std::string m_accessToken;
    std::string m_refreshToken;
    long m_lifetime;     ///< Lifetime of the current access token in seconds (0 = unknown)
    int64_t m_expiresAt; ///< Epoch expiry of the current access token (0 = unknown: refresh only on 401)
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

    /// Wait for the asynchronous run to complete (routed to the node where the run started).
    /// Returns the process exit code, or nullptr on timeout (not exited); throws AppMeshHttpError on HTTP/transport error.
    std::shared_ptr<int> wait(OutputHandler stdoutHandler = nullptr, int timeout = 0);

private:
    AppMeshClient *m_client; ///< Non-owning; must outlive this AppRun
    const std::string m_appName;
    const std::string m_procUid;
    std::string m_forwardTo; ///< Saved forward_to target from run creation time
};

/// Connection settings for AppMeshClient.
struct ClientHttpConfig
{
    std::string url = "https://127.0.0.1:6060";
    /// Trusted CA cert file or directory; empty = system trust store. An absent default
    /// path falls back to the system trust store (verification stays on); any other
    /// missing/unreadable path is a hard error, never a silent fallback to no-verification.
    std::string caCertPath = "ssl/ca.pem";
    /// The ONLY way to disable server certificate verification.
    bool verifyServer = true;
    /// Optional mutual-TLS client identity. Empty by default; bearer authentication
    /// does not silently depend on files in the current working directory.
    std::string clientCert;
    std::string clientKey;
    /// Optional caller-owned access token, kept in memory only. Ignored when
    /// tokenProvider is set (an explicit provider wins).
    std::string bearerToken;
    /// Optional refresh-capable token provider; refresh credentials stay provider-private.
    std::shared_ptr<TokenProvider> tokenProvider;
};

/// IMPORTANT: RestClient state is process-global (static): all AppMeshClient instances
/// share ONE session/SSL configuration; constructing another client with different settings silently
/// reconfigures every instance. Only one logically-distinct client per process.
/// Transport timeouts: RestClient hardcodes a process-global 200s request timeout
/// (1000s for file transfer); the `timeout` params on getAppOutput()/runTask() are
/// server-side long-poll/task timeouts, NOT transport timeouts.
class AppMeshClient
{
public:
    AppMeshClient();
    /// Configure endpoint, TLS material, and an optional caller-owned bearer;
    /// reconfigures the process-global RestClient state (see class note).
    /// Throws std::invalid_argument on an inaccessible non-default caCertPath (see ClientHttpConfig::caCertPath).
    explicit AppMeshClient(const ClientHttpConfig &config);
    virtual ~AppMeshClient() = default;

    // Session/Client
    /// Set the cluster forwarding target used for subsequent requests.
    /// If the port is omitted, the current service port is used.
    void setForwardTo(const std::string &url = "");
    const std::string &getForwardTo() const;

    // Authentication boundary
    /// Attach a caller-owned, non-refreshing access token: the token is wrapped
    /// in a StaticAccessTokenProvider, replacing any previously set provider.
    /// The SDK never logs in to Engine, persists cookies, or refreshes this token.
    void setBearerToken(const std::string &token);
    /// Attach a refresh-capable token provider, replacing any bearer token.
    /// On HTTP 401 the client asks the provider to refresh and retries once.
    void setTokenProvider(std::shared_ptr<TokenProvider> provider);
    void clearBearerToken();

    // The mutex members below make this type non-copyable and non-movable. Spelled out so a
    // downstream `AppMeshClient c = makeClient();` fails with a legible error rather than
    // "call to implicitly-deleted copy constructor".
    AppMeshClient(const AppMeshClient &) = delete;
    AppMeshClient &operator=(const AppMeshClient &) = delete;
    AppMeshClient(AppMeshClient &&) = delete;
    AppMeshClient &operator=(AppMeshClient &&) = delete;
    /// Source-compatible name for the current in-memory bearer; empty when unset.
    std::string getAuthToken() const;
    /// Return Engine's public OAuth/OIDC client configuration.
    nlohmann::json getAuthConfig() const;

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
    /// Enable an application.
    void enableApp(const std::string &app);
    /// Disable an application.
    void disableApp(const std::string &app);

    // Run Application Operations
    /// Run an application synchronously and return {exitCode, stdoutText}.
    /// exitCode is nullptr when the server reported no exit code (process not exited).
    std::tuple<std::shared_ptr<int>, std::string> runAppSync(const nlohmann::json &app,
                                                             int maxTime = 60 * 60 * 24 * 2,
                                                             int lifecycle = 60 * 60 * 24 * 2 + 60 * 60 * 12);
    /// Run an application asynchronously and return a handle to monitor it.
    AppRun runAppAsync(const nlohmann::json &app,
                       int maxTime = 60 * 60 * 24 * 2,
                       int lifecycle = 60 * 60 * 24 * 2 + 60 * 60 * 12);
    /// Poll an async run until completion or timeout.
    /// Returns the exit code, or nullptr on timeout (not exited); throws AppMeshHttpError on HTTP/transport error, or std::invalid_argument on null run.
    std::shared_ptr<int> waitForAsyncRun(AppRun *run, OutputHandler stdoutHandler = nullptr, int timeout = 0);
    /// Send a payload to a running application task endpoint and wait for the response body.
    /// timeout is a server-side task timeout (seconds), not a transport timeout.
    std::string runTask(const std::string &app, const nlohmann::json &data, int timeout);
    /// Cancel the pending task of an application.
    /// Returns true when cancelled, false when no task to cancel (404); throws AppMeshHttpError otherwise.
    bool cancelTask(const std::string &app);

    // File Management
    /// Download a remote file and optionally apply returned POSIX metadata locally.
    void downloadFile(const std::string &remoteFile, const std::string &localFile = "", bool preservePermissions = false);
    /// Upload a local file and optionally send local POSIX metadata for server-side recreation.
    void uploadFile(const std::string &localFile, const std::string &remoteFile = "", bool preservePermissions = false);

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

    // Principal and RBAC Management
    nlohmann::json getCurrentPrincipal() const;
    nlohmann::json listPrincipals() const;
    void updatePrincipal(const std::string &principal, const nlohmann::json &value);
    void deletePrincipal(const std::string &principal);
    std::set<std::string> getPrincipalPermissions() const;
    /// Compatibility aliases for callers that only need the current verified identity.
    nlohmann::json getCurrentUser() const;
    std::set<std::string> getUserPermissions() const;
    std::set<std::string> listPermissions() const;
    std::map<std::string, std::set<std::string>> listRoles() const;
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
    /// Attach forwarding and caller-owned bearer headers to every request.
    virtual void addCommonHeaders(std::map<std::string, std::string> &header) const;

private:
    void applyConfig(const ClientHttpConfig &config);
    std::shared_ptr<TokenProvider> getTokenProvider() const;
    /// Return the provider's current access token, trimmed; empty when no provider
    /// or no token. Throws std::invalid_argument on a whitespace-only token.
    std::string getBearerToken(bool forceRefresh, const std::string &rejectedToken) const;

    std::string m_url;
    std::string m_forwardTo;
    mutable std::mutex m_authMutex;
    std::shared_ptr<TokenProvider> m_tokenProvider;
};

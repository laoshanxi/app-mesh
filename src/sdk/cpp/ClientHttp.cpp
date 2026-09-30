// src/sdk/cpp/ClientHttp.cpp
#include "ClientHttp.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <map>
#include <string>

#include <ace/OS_NS_time.h>
#include <nlohmann/json.hpp>

#include "../../common/JwtHelper.h"
#include "../../common/RestClient.h"
#include "../../common/UriParser.hpp"
#include "../../common/Utility.h"
#include "../../common/os/filesystem.h"

// === RefreshTokenProvider implementation ===

namespace
{
bool isLoopbackHost(std::string host)
{
    // uriparser strips IPv6 brackets; tolerate either form
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    for (auto &ch : host)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return host == "127.0.0.1" || host == "localhost" || host == "::1";
}
} // namespace

RefreshTokenProvider::RefreshTokenProvider(const RefreshTokenConfig &config)
    : m_clientId(config.clientId.empty() ? "appmesh-cli" : config.clientId),
      m_accessToken(config.accessToken),
      m_refreshToken(config.refreshToken),
      m_lifetime(config.expiresIn > 0 ? config.expiresIn : 0),
      m_expiresAt(0)
{
    const auto uri = Uri::parse(config.tokenUrl);
    std::string scheme = uri.scheme;
    for (auto &ch : scheme)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (uri.host.empty() ||
        !(scheme == "https" || (scheme == "http" && isLoopbackHost(uri.host))))
    {
        throw std::invalid_argument("refresh token URL must be HTTPS, or HTTP only for a loopback host (127.0.0.1, localhost, ::1)");
    }
    m_tokenUrl = config.tokenUrl;
    if (m_lifetime > 0)
        m_expiresAt = static_cast<int64_t>(std::time(nullptr)) + m_lifetime;
}

std::string RefreshTokenProvider::getAccessToken()
{
    std::lock_guard<std::mutex> guard(m_mutex);
    // Proactive refresh shortly before expiry: margin = max(30s, 10% of lifetime).
    if (m_expiresAt > 0 && !m_refreshToken.empty())
    {
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (now >= m_expiresAt - std::max(30L, m_lifetime / 10))
            refreshLocked();
    }
    return m_accessToken;
}

bool RefreshTokenProvider::canRefresh() const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return !m_refreshToken.empty();
}

std::string RefreshTokenProvider::refreshAccessToken(const std::string &rejectedToken)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    // A racing caller already refreshed: the rejected token is no longer current.
    if (!rejectedToken.empty() && rejectedToken != m_accessToken)
        return m_accessToken;
    refreshLocked();
    return m_accessToken;
}

void RefreshTokenProvider::clear()
{
    std::lock_guard<std::mutex> guard(m_mutex);
    m_accessToken.clear();
    m_refreshToken.clear();
    m_lifetime = 0;
    m_expiresAt = 0;
}

void RefreshTokenProvider::refreshLocked()
{
    if (m_refreshToken.empty())
        throw std::runtime_error("no refresh token is available");

    // Split the endpoint into a RestClient host base and request path.
    const auto uri = Uri::parse(m_tokenUrl);
    std::string host = uri.host.find(':') != std::string::npos
                           ? uri.scheme + "://[" + uri.host + "]" // IPv6 literal
                           : uri.scheme + "://" + uri.host;
    if (uri.port > 0)
        host += ":" + std::to_string(uri.port);

    const std::map<std::string, std::string> form = {
        {"grant_type", "refresh_token"},
        {"refresh_token", m_refreshToken},
        {"client_id", m_clientId}};
    // TLS verification follows the process-global RestClient SSL configuration
    // installed by AppMeshClient (ClientHttpConfig::verifyServer / caCertPath).
    const auto response = RestClient::request(host, web::http::methods::POST, uri.path, std::string(), {}, {}, form);

    // Transport failure (status 0): keep token state; the credentials may still be valid.
    if (response->status_code == 0)
        throw std::runtime_error("token refresh request failed: " + response->text);

    if (response->status_code != web::http::status_codes::OK)
    {
        // invalid_grant means the refresh credential is dead: drop both tokens so
        // canRefresh() turns false and the client stops retrying on 401.
        std::string error;
        try
        {
            error = nlohmann::json::parse(response->text).value("error", std::string());
        }
        catch (const nlohmann::json::exception &)
        {
        }
        if (error == "invalid_grant")
        {
            m_accessToken.clear();
            m_refreshToken.clear();
            m_expiresAt = 0;
        }
        throw std::runtime_error("token refresh rejected with HTTP " + std::to_string(response->status_code));
    }

    const auto body = nlohmann::json::parse(response->text); // non-JSON throws; state kept
    const auto accessToken = body.value("access_token", std::string());
    if (accessToken.empty())
        throw std::runtime_error("token response did not include an access token");
    m_accessToken = accessToken;
    // Dex may omit refresh_token when the old one stays valid (reuseInterval):
    // replace the stored credential only when the response carries a new one.
    const auto newRefreshToken = body.value("refresh_token", std::string());
    if (!newRefreshToken.empty())
        m_refreshToken = newRefreshToken;
    long expiresIn = 0;
    if (body.contains("expires_in") && body["expires_in"].is_number())
        expiresIn = body["expires_in"].get<long>();
    m_lifetime = expiresIn;
    m_expiresAt = expiresIn > 0 ? static_cast<int64_t>(std::time(nullptr)) + expiresIn : 0;
}

// === AppRun implementation ===

AppRun::AppRun(AppMeshClient *client, const std::string &appName, const std::string &procUid)
    : m_client(client), m_appName(appName), m_procUid(procUid), m_forwardTo(client->getForwardTo())
{
}

std::shared_ptr<int> AppRun::wait(OutputHandler stdoutHandler, int timeout)
{
    // Temporarily restore the forward_to target that was active at run creation,
    // ensuring output queries reach the correct cluster node.
    // RAII guard guarantees restore on every exit path, including exceptions.
    struct ForwardToGuard
    {
        AppMeshClient *client;
        std::string original;
        ~ForwardToGuard() { client->setForwardTo(original); }
    } guard = {m_client, m_client->getForwardTo()};
    m_client->setForwardTo(m_forwardTo);
    return m_client->waitForAsyncRun(this, stdoutHandler, timeout);
}

// === AppMeshClient implementation ===

AppMeshClient::AppMeshClient()
{
    applyConfig(ClientHttpConfig());
}

AppMeshClient::AppMeshClient(const ClientHttpConfig &config)
{
    applyConfig(config);
}

void AppMeshClient::applyConfig(const ClientHttpConfig &config)
{
    m_url = config.url;
    // Engine accepts only Authorization: Bearer. Disable libcurl's cookie engine so
    // a proxy or legacy server cannot create an implicit authentication session.
    RestClient::setSessionConfiguration(SessionConfig());
    setBearerToken(config.bearerToken);
    if (config.tokenProvider)
        setTokenProvider(config.tokenProvider); // explicit provider wins over bearerToken

    // Missing/unreadable CA path: absent default falls back to the system trust store
    // (verification stays on); an explicit path is a hard error (RestClient would silently skip CAINFO/CAPATH).
    std::string caPath = config.verifyServer ? config.caCertPath : std::string();
    if (!caPath.empty() && !Utility::isFileExist(caPath) && !Utility::isDirExist(caPath))
    {
        if (caPath == ClientHttpConfig().caCertPath)
            caPath.clear(); // default CA absent: use system trust roots
        else
            throw std::invalid_argument("CA certificate path not accessible: " + caPath);
    }

    ClientSSLConfig ssl;
    ssl.m_verify_server = config.verifyServer;
    ssl.m_ca_location = caPath;
    ssl.m_verify_client = !config.clientCert.empty() && !config.clientKey.empty();
    ssl.m_certificate = config.clientCert;
    ssl.m_private_key = config.clientKey;

    RestClient::defaultSslConfiguration(ssl);
}

void AppMeshClient::setForwardTo(const std::string &url)
{
    m_forwardTo = url;
}

const std::string &AppMeshClient::getForwardTo() const
{
    return m_forwardTo;
}

// Authentication boundary
void AppMeshClient::setBearerToken(const std::string &token)
{
    std::lock_guard<std::mutex> guard(m_authMutex);
    if (token.empty())
        m_tokenProvider.reset();
    else
        m_tokenProvider = std::make_shared<StaticAccessTokenProvider>(token);
}

void AppMeshClient::setTokenProvider(std::shared_ptr<TokenProvider> provider)
{
    if (!provider)
        throw std::invalid_argument("token provider must not be null");
    std::lock_guard<std::mutex> guard(m_authMutex);
    m_tokenProvider = std::move(provider);
}

void AppMeshClient::clearBearerToken()
{
    setBearerToken(std::string());
}

std::string AppMeshClient::getAuthToken() const
{
    const auto provider = getTokenProvider();
    return provider ? provider->getAccessToken() : std::string();
}

std::shared_ptr<TokenProvider> AppMeshClient::getTokenProvider() const
{
    std::lock_guard<std::mutex> guard(m_authMutex);
    return m_tokenProvider;
}

std::string AppMeshClient::getBearerToken(bool forceRefresh, const std::string &rejectedToken) const
{
    const auto provider = getTokenProvider();
    if (!provider)
        return std::string();
    const std::string token = forceRefresh ? provider->refreshAccessToken(rejectedToken) : provider->getAccessToken();
    const auto begin = token.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
    {
        if (token.empty())
            return std::string();
        throw std::invalid_argument("TokenProvider returned an invalid access token");
    }
    return token.substr(begin, token.find_last_not_of(" \t\r\n") - begin + 1);
}

nlohmann::json AppMeshClient::getAuthConfig() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/auth/config");
    return nlohmann::json::parse(response->text);
}

// Application View
nlohmann::json AppMeshClient::getApp(const std::string &app) const
{
    const std::string restPath = "/appmesh/app/" + app;
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, restPath);
    return nlohmann::json::parse(response->text);
}

nlohmann::json AppMeshClient::listApps() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/applications");
    return nlohmann::json::parse(response->text);
}

AppOutput AppMeshClient::getAppOutput(const std::string &app, int64_t outputPosition,
                                      int stdoutIndex, int stdoutMaxsize,
                                      const std::string &processUuid, int timeout) const
{
    const std::string restPath = "/appmesh/app/" + app + "/output";

    std::map<std::string, std::string> query;
    if (stdoutIndex)
        query[HTTP_QUERY_KEY_stdout_index] = std::to_string(stdoutIndex);
    if (outputPosition)
        query[HTTP_QUERY_KEY_stdout_position] = std::to_string(outputPosition);
    if (stdoutMaxsize)
        query[HTTP_QUERY_KEY_stdout_maxsize] = std::to_string(stdoutMaxsize);
    if (!processUuid.empty())
        query[HTTP_QUERY_KEY_process_uuid] = processUuid;
    if (timeout)
        query[HTTP_QUERY_KEY_stdout_timeout] = std::to_string(timeout);

    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, restPath, nullptr, {}, query);

    AppOutput output;
    output.statusCode = response->status_code;
    output.output = response->text;

    if (response->header.count(HTTP_HEADER_KEY_output_pos))
        output.outputPosition = std::strtoll(response->header.get(HTTP_HEADER_KEY_output_pos).c_str(), nullptr, 10);

    if (response->header.count(HTTP_HEADER_KEY_exit_code))
        output.exitCode = std::make_shared<int>(std::atoi(response->header.get(HTTP_HEADER_KEY_exit_code).c_str()));

    return output;
}

bool AppMeshClient::checkAppHealth(const std::string &app) const
{
    const std::string restPath = "/appmesh/app/" + app + "/health";
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, restPath);
    try
    {
        return std::stoi(response->text) == 0;
    }
    catch (const std::exception &)
    {
        // Non-numeric health body: report it as an HTTP-level SDK error
        // instead of a raw stoi exception.
        throw AppMeshHttpError(response->status_code, response->text);
    }
}

// Application Manage
nlohmann::json AppMeshClient::addApp(const nlohmann::json &app)
{
    const std::string restPath = "/appmesh/app/" + GET_JSON_STR_VALUE(app, JSON_KEY_APP_name);
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::PUT, restPath, &app);
    return nlohmann::json::parse(response->text);
}

bool AppMeshClient::deleteApp(const std::string &app)
{
    const std::string restPath = "/appmesh/app/" + app;
    auto response = requestHttp(ErrorPolicy::Return, web::http::methods::DEL, restPath);
    if (response->status_code == web::http::status_codes::OK)
        return true;
    if (response->status_code == web::http::status_codes::NotFound)
        return false;
    // Other errors (permission denied, server error, etc.)
    throw AppMeshHttpError(response->status_code, response->text);
}

void AppMeshClient::enableApp(const std::string &app)
{
    const std::string restPath = "/appmesh/app/" + app + "/enable";
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath);
}

void AppMeshClient::disableApp(const std::string &app)
{
    const std::string restPath = "/appmesh/app/" + app + "/disable";
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath);
}

// Run Application Operations
std::tuple<std::shared_ptr<int>, std::string> AppMeshClient::runAppSync(const nlohmann::json &app,
                                                                     int maxTime,
                                                                     int lifecycle)
{
    std::map<std::string, std::string> query = {
        {HTTP_QUERY_KEY_timeout, std::to_string(maxTime)},
        {HTTP_QUERY_KEY_lifecycle, std::to_string(lifecycle)}};

    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::POST, "/appmesh/app/syncrun", &app, {}, query);

    std::shared_ptr<int> returnCode;
    if (response->header.count(HTTP_HEADER_KEY_exit_code))
        returnCode = std::make_shared<int>(std::atoi(response->header.get(HTTP_HEADER_KEY_exit_code).c_str()));

    return std::make_tuple(returnCode, response->text);
}

AppRun AppMeshClient::runAppAsync(const nlohmann::json &app, int maxTime, int lifecycle)
{
    std::map<std::string, std::string> query = {
        {HTTP_QUERY_KEY_timeout, std::to_string(maxTime)},
        {HTTP_QUERY_KEY_lifecycle, std::to_string(lifecycle)}};

    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::POST, "/appmesh/app/run", &app, {}, query);
    auto result = nlohmann::json::parse(response->text);

    auto appName = result.at(JSON_KEY_APP_name).get<std::string>();
    auto procUid = result.at(HTTP_QUERY_KEY_process_uuid).get<std::string>();

    return AppRun(this, appName, procUid);
}

std::shared_ptr<int> AppMeshClient::waitForAsyncRun(AppRun *run, OutputHandler stdoutHandler, int timeout)
{
    if (run == nullptr)
        throw std::invalid_argument("run must not be null");

    int64_t lastOutputPosition = 0;
    const time_t startTime = ACE_OS::time();
    // Server-side long-poll cadence per request, as in the Python SDK's
    // _POLL_INTERVAL: each request waits server-side instead of returning
    // at once and flooding the daemon.
    constexpr int pollIntervalSeconds = 1;

    while (true)
    {
        auto response = this->getAppOutput(run->appName(), lastOutputPosition, 0, 10240,
                                           run->procUid(), pollIntervalSeconds);

        if (stdoutHandler && !response.output.empty())
            stdoutHandler(response.output, lastOutputPosition);
        lastOutputPosition = response.outputPosition;

        // Real completion: clean up the temp run app (best-effort).
        if (response.exitCode)
        {
            try { this->deleteApp(run->appName()); } catch (...) {}
            return response.exitCode;
        }

        // Timeout: the app may still be running, so do not delete it.
        // (HTTP/transport errors throw from getAppOutput and never reach here.)
        if (timeout > 0 && ACE_OS::time() - startTime >= timeout)
            return nullptr;
    }
}

std::string AppMeshClient::runTask(const std::string &app, const nlohmann::json &data, int timeout)
{
    if (timeout <= 0)
        timeout = 300;
    const std::string restPath = "/appmesh/app/" + app + "/task";
    std::map<std::string, std::string> query = {{HTTP_QUERY_KEY_timeout, std::to_string(timeout)}};

    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath, &data, {}, query);
    return response->text;
}

bool AppMeshClient::cancelTask(const std::string &app)
{
    const std::string restPath = "/appmesh/app/" + app + "/task";
    auto response = requestHttp(ErrorPolicy::Return, web::http::methods::DEL, restPath);
    if (response->status_code == web::http::status_codes::OK)
        return true;
    if (response->status_code == web::http::status_codes::NotFound)
        return false;
    // Other errors (permission denied, server error, etc.)
    throw AppMeshHttpError(response->status_code, response->text);
}

// File Management
void AppMeshClient::downloadFile(const std::string &remoteFile, const std::string &localFile, bool preservePermissions)
{
    // Default to the basename when no local/remote name is given.
    const std::string localName = localFile.empty() ? remoteFile.substr(remoteFile.find_last_of("/\\") + 1) : localFile;

    // header
    std::map<std::string, std::string> header;
    this->addCommonHeaders(header);
    header[HTTP_HEADER_KEY_file_path] = Utility::encodeURIComponent(remoteFile);

    auto response = RestClient::download(m_url, REST_PATH_DOWNLOAD, remoteFile, localName, header);

    if (response->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(response->status_code, response->text);
    }

    if (preservePermissions)
    {
        Utility::applyFilePermission(localName, response->header);
    }
}

void AppMeshClient::uploadFile(const std::string &localFile, const std::string &remoteFile, bool preservePermissions)
{
    // Default to the basename when no remote name is given.
    const std::string remoteName = remoteFile.empty() ? localFile.substr(localFile.find_last_of("/\\") + 1) : remoteFile;

    // header
    std::map<std::string, std::string> header;
    this->addCommonHeaders(header);
    header[HTTP_HEADER_KEY_file_path] = Utility::encodeURIComponent(remoteName);
    if (preservePermissions)
    {
        auto fileInfo = os::fileStat(localFile);
        int mode = std::get<0>(fileInfo);
        auto uname = std::get<1>(fileInfo);
        auto gname = std::get<2>(fileInfo);

        if (mode >= 0)
        {
            header[HTTP_HEADER_KEY_file_mode] = std::to_string(mode);
        }
        if (!uname.empty() && !gname.empty())
        {
            header[HTTP_HEADER_KEY_file_user] = uname;
            header[HTTP_HEADER_KEY_file_group] = gname;
        }
    }

    auto response = RestClient::upload(m_url, REST_PATH_UPLOAD, localFile, header);

    if (response->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(response->status_code, response->text);
    }
}

// System Management
nlohmann::json AppMeshClient::getHostResources() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/resources");
    return nlohmann::json::parse(response->text);
}

nlohmann::json AppMeshClient::getConfig() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/config");
    return nlohmann::json::parse(response->text);
}

nlohmann::json AppMeshClient::setConfig(const nlohmann::json &config)
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::POST, "/appmesh/config", &config);
    return nlohmann::json::parse(response->text);
}

std::string AppMeshClient::setLogLevel(const std::string &level)
{
    nlohmann::json jsonObj = {{JSON_KEY_BaseConfig, {{JSON_KEY_LogLevel, level}}}};
    auto response = this->setConfig(jsonObj);
    return response.at(JSON_KEY_BaseConfig).at(JSON_KEY_LogLevel).get<std::string>();
}

std::string AppMeshClient::getMetrics() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/metrics");
    return response->text;
}

// Label Management
nlohmann::json AppMeshClient::listLabels() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/labels");
    return nlohmann::json::parse(response->text);
}

void AppMeshClient::addLabel(const std::string &label, const std::string &value)
{
    const std::string restPath = "/appmesh/label/" + label;
    std::map<std::string, std::string> query = {{HTTP_QUERY_KEY_label_value, value}};
    requestHttp(ErrorPolicy::Throw, web::http::methods::PUT, restPath, nullptr, {}, query);
}

void AppMeshClient::deleteLabel(const std::string &label)
{
    const std::string restPath = "/appmesh/label/" + label;
    requestHttp(ErrorPolicy::Throw, web::http::methods::DEL, restPath);
}

nlohmann::json AppMeshClient::getCurrentPrincipal() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/principal/self");
    return nlohmann::json::parse(response->text);
}

nlohmann::json AppMeshClient::listPrincipals() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/principals");
    return nlohmann::json::parse(response->text);
}

void AppMeshClient::updatePrincipal(const std::string &principal, const nlohmann::json &value)
{
    const std::string restPath = "/appmesh/principal/" + Utility::encodeURIComponent(principal);
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath, &value);
}

void AppMeshClient::deletePrincipal(const std::string &principal)
{
    const std::string restPath = "/appmesh/principal/" + Utility::encodeURIComponent(principal);
    requestHttp(ErrorPolicy::Throw, web::http::methods::DEL, restPath);
}

std::set<std::string> AppMeshClient::getPrincipalPermissions() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/principal/self/permissions");
    auto result = nlohmann::json::parse(response->text);
    std::set<std::string> permissions;
    for (const auto &perm : result)
    {
        permissions.insert(perm.get<std::string>());
    }
    return permissions;
}

nlohmann::json AppMeshClient::getCurrentUser() const
{
    return getCurrentPrincipal();
}

std::set<std::string> AppMeshClient::getUserPermissions() const
{
    return getPrincipalPermissions();
}

std::set<std::string> AppMeshClient::listPermissions() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/permissions");
    auto result = nlohmann::json::parse(response->text);
    std::set<std::string> permissions;
    for (const auto &perm : result)
    {
        permissions.insert(perm.get<std::string>());
    }
    return permissions;
}

std::map<std::string, std::set<std::string>> AppMeshClient::listRoles() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/roles");
    auto result = nlohmann::json::parse(response->text);
    std::map<std::string, std::set<std::string>> roles;
    for (const auto &item : result.items())
    {
        std::set<std::string> permissions;
        for (const auto &perm : item.value())
        {
            permissions.insert(perm.get<std::string>());
        }
        roles[item.key()] = permissions;
    }
    return roles;
}

void AppMeshClient::updateRole(const std::string &role, const std::set<std::string> &rolePermissions)
{
    nlohmann::json jsonObj = nlohmann::json::array();
    for (const auto &perm : rolePermissions)
    {
        jsonObj.push_back(perm);
    }
    const std::string restPath = "/appmesh/role/" + role;
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath, &jsonObj);
}

void AppMeshClient::deleteRole(const std::string &role)
{
    const std::string restPath = "/appmesh/role/" + role;
    requestHttp(ErrorPolicy::Throw, web::http::methods::DEL, restPath);
}

// Protected members
std::shared_ptr<CurlResponse> AppMeshClient::requestHttp(ErrorPolicy errorPolicy,
                                                         const std::string &method,
                                                         const std::string &path,
                                                         const nlohmann::json *body,
                                                         std::map<std::string, std::string> header,
                                                         std::map<std::string, std::string> query) const
{
    // header
    this->addCommonHeaders(header);

    // body
    const std::string bodyContent = body ? body->dump() : std::string();

    // request (the body is an in-memory string here, so every request through
    // requestHttp is replayable; streaming file transfer does not use this path)
    auto resp = RestClient::request(m_url, method, path, bodyContent, header, query);

    // One-shot token refresh on HTTP 401 (mirrors the Python SDK): ask the
    // provider to replace the rejected token and retry exactly once; a second
    // 401 falls through to the error policy below.
    if (resp->status_code == web::http::status_codes::Unauthorized)
    {
        const auto provider = getTokenProvider();
        if (provider && provider->canRefresh())
        {
            // The rejected token is the one just sent, not a fresh read: a racing
            // thread (or the proactive refresh) may already have replaced the
            // stored token, and re-reading here would defeat the coalescing in
            // refreshAccessToken() and issue a duplicate grant.
            std::string rejectedToken;
            const std::string bearerPrefix = HTTP_HEADER_JWT_BearerSpace;
            const auto sentAuth = header.find(HTTP_HEADER_JWT_Authorization);
            if (sentAuth != header.end() && sentAuth->second.compare(0, bearerPrefix.size(), bearerPrefix) == 0)
                rejectedToken = sentAuth->second.substr(bearerPrefix.size());
            const std::string newToken = getBearerToken(true, rejectedToken);
            if (newToken.empty())
                header.erase(HTTP_HEADER_JWT_Authorization);
            else
                header[HTTP_HEADER_JWT_Authorization] = JwtHelper::buildBearerAuthorization(newToken);
            resp = RestClient::request(m_url, method, path, bodyContent, header, query);
        }
    }

    // check return
    if (errorPolicy == ErrorPolicy::Throw && resp->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(resp->status_code, resp->text);
    }

    return resp;
}

void AppMeshClient::addCommonHeaders(std::map<std::string, std::string> &header) const
{
    const auto token = getBearerToken(false, "");
    if (!token.empty() && header.count(HTTP_HEADER_JWT_Authorization) == 0)
        header[HTTP_HEADER_JWT_Authorization] = JwtHelper::buildBearerAuthorization(token);

    if (!m_forwardTo.empty())
    {
        if (m_forwardTo.find(':') == std::string::npos)
            header[HTTP_HEADER_KEY_Forwarding_Host] = m_forwardTo + ":" + std::to_string(Uri::parse(m_url).port);
        else
            header[HTTP_HEADER_KEY_Forwarding_Host] = m_forwardTo;
    }
}

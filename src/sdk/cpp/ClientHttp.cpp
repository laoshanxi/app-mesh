// src/sdk/cpp/ClientHttp.cpp
#include "ClientHttp.h"

#include <cstdlib>
#include <map>
#include <string>

#include <ace/OS_NS_time.h>
#include <nlohmann/json.hpp>

#include "../../common/JwtHelper.h"
#include "../../common/RestClient.h"
#include "../../common/UriParser.hpp"
#include "../../common/Utility.h"
#include "../../common/os/filesystem.h"

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

AppMeshClient::AppMeshClient(const ClientHttpConfig &config)
{
    applyConfig(config);
}

void AppMeshClient::applyConfig(const ClientHttpConfig &config)
{
    m_url = config.url;

    if (config.cookieFile.empty())
        RestClient::setSessionConfiguration(SessionConfig::MemorySession());
    else
        RestClient::setSessionConfiguration(SessionConfig::FileSession(config.cookieFile));

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

// Authentication Management
std::string AppMeshClient::login(const std::string &username, const std::string &password,
                              const std::string &totp, int tokenExpire, const std::string &audience)
{
    RestClient::clearSession();

    std::map<std::string, std::string> header;
    header[HTTP_HEADER_JWT_Authorization] = std::string(HTTP_HEADER_Auth_BasicSpace) +
                                            Utility::encode64(username + ":" + password);
    header[HTTP_HEADER_KEY_X_SET_COOKIE] = "true";

    if (tokenExpire > 0)
        header[HTTP_HEADER_JWT_expire_seconds] = std::to_string(tokenExpire);
    if (!audience.empty())
        header[HTTP_HEADER_JWT_audience] = audience;
    if (!totp.empty())
        header[HTTP_HEADER_JWT_totp] = totp;

    auto response = this->requestHttp(ErrorPolicy::Return, web::http::methods::POST, "/appmesh/login", nullptr, header);

    if (response->status_code == web::http::status_codes::PreconditionRequired)
    {
        // TOTP required (HTTP 428)
        auto jsonResponse = nlohmann::json::parse(response->text);
        if (jsonResponse.contains(REST_TEXT_TOTP_CHALLENGE_JSON_KEY))
        {
            auto totpChallenge = jsonResponse.at(REST_TEXT_TOTP_CHALLENGE_JSON_KEY).get<std::string>();
            if (totp.empty())
                return totpChallenge;
            this->validateTotp(username, totpChallenge, totp, tokenExpire);
        }
    }
    else if (response->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(response->status_code, response->text);
    }

    return std::string();
}

void AppMeshClient::validateTotp(const std::string &username, const std::string &challenge,
                              const std::string &totp, int tokenExpire)
{
    std::map<std::string, std::string> header = {{HTTP_HEADER_KEY_X_SET_COOKIE, "true"}};

    nlohmann::json body = {
        {HTTP_BODY_KEY_JWT_username, username},
        {HTTP_BODY_KEY_JWT_totp, totp},
        {HTTP_BODY_KEY_JWT_totp_challenge, challenge},
        {HTTP_BODY_KEY_JWT_expire_seconds, tokenExpire}};

    this->requestHttp(ErrorPolicy::Throw, web::http::methods::POST, "/appmesh/totp/validate", &body, header);
}

std::tuple<bool, std::string> AppMeshClient::authenticate(const std::string &token,
                                                       const std::string &permission,
                                                       const std::string &audience, bool updateSession)
{
    std::map<std::string, std::string> header = {
        {HTTP_HEADER_JWT_Authorization, JwtHelper::buildBearerAuthorization(token)}};

    if (!permission.empty())
        header[HTTP_HEADER_JWT_auth_permission] = permission;
    if (!audience.empty())
        header[HTTP_HEADER_JWT_audience] = audience;
    if (updateSession)
        header[HTTP_HEADER_KEY_X_SET_COOKIE] = "true";

    auto resp = this->requestHttp(ErrorPolicy::Return, web::http::methods::POST, "/appmesh/auth", nullptr, header);
    return std::make_tuple(resp->status_code == web::http::status_codes::OK, resp->text);
}

void AppMeshClient::logout()
{
    this->requestHttp(ErrorPolicy::Throw, web::http::methods::POST, "/appmesh/self/logoff");
    RestClient::clearSession();
}

void AppMeshClient::renewToken(int tokenExpire)
{
    std::map<std::string, std::string> header;
    if (tokenExpire > 0)
        header[HTTP_HEADER_JWT_expire_seconds] = std::to_string(tokenExpire);

    this->requestHttp(ErrorPolicy::Throw, web::http::methods::POST, "/appmesh/token/renew", nullptr, header);
}

std::string AppMeshClient::getAuthToken() const
{
    return RestClient::getCookie(COOKIE_TOKEN);
}

std::string AppMeshClient::getTotpUri()
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::POST, "/appmesh/totp/secret");
    auto result = nlohmann::json::parse(response->text);
    return Utility::decode64(result.at(HTTP_BODY_KEY_MFA_URI).get<std::string>());
}

void AppMeshClient::enableTotp(const std::string &totp)
{
    std::map<std::string, std::string> header = {{HTTP_HEADER_JWT_totp, totp}};
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, "/appmesh/totp/setup", nullptr, header);
}

void AppMeshClient::disableTotp(const std::string &user)
{
    const std::string restPath = "/appmesh/totp/" + user + "/disable";
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath);
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
    return std::stoi(response->text) == 0;
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

    while (true)
    {
        auto response = this->getAppOutput(run->appName(), lastOutputPosition, 0, 10240,
                                           run->procUid(), timeout);

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
    std::map<std::string, std::string> query = {{"timeout", std::to_string(timeout)}};

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
    // header
    std::map<std::string, std::string> header;
    this->addCommonHeaders(header);
    header[HTTP_HEADER_KEY_file_path] = Utility::encodeURIComponent(remoteFile);

    auto response = RestClient::download(m_url, REST_PATH_DOWNLOAD, remoteFile, localFile, header);

    if (response->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(response->status_code, response->text);
    }

    if (preservePermissions)
    {
        Utility::applyFilePermission(localFile, response->header);
    }
}

void AppMeshClient::uploadFile(const std::string &localFile, const std::string &remoteFile, bool preservePermissions)
{
    // header
    std::map<std::string, std::string> header;
    this->addCommonHeaders(header);
    header[HTTP_HEADER_KEY_file_path] = Utility::encodeURIComponent(remoteFile);
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
    std::map<std::string, std::string> query = {{"value", value}};
    requestHttp(ErrorPolicy::Throw, web::http::methods::PUT, restPath, nullptr, {}, query);
}

void AppMeshClient::deleteLabel(const std::string &label)
{
    const std::string restPath = "/appmesh/label/" + label;
    requestHttp(ErrorPolicy::Throw, web::http::methods::DEL, restPath);
}

// User Management
void AppMeshClient::updatePassword(const std::string &oldPwd, const std::string &newPwd, const std::string &user)
{
    nlohmann::json jsonObj = {
        {HTTP_BODY_KEY_OLD_PASSWORD, Utility::encode64(oldPwd)},
        {HTTP_BODY_KEY_NEW_PASSWORD, Utility::encode64(newPwd)}};

    const std::string restPath = "/appmesh/user/" + user + "/passwd";
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath, &jsonObj);
}

nlohmann::json AppMeshClient::getCurrentUser() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/user/self");
    return nlohmann::json::parse(response->text);
}

nlohmann::json AppMeshClient::listUsers() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/users");
    return nlohmann::json::parse(response->text);
}

void AppMeshClient::addUser(const std::string &username, const nlohmann::json &user)
{
    const std::string restPath = "/appmesh/user/" + username;
    requestHttp(ErrorPolicy::Throw, web::http::methods::PUT, restPath, &user);
}

void AppMeshClient::deleteUser(const std::string &user)
{
    const std::string restPath = "/appmesh/user/" + user;
    requestHttp(ErrorPolicy::Throw, web::http::methods::DEL, restPath);
}

void AppMeshClient::lockUser(const std::string &user)
{
    const std::string restPath = "/appmesh/user/" + user + "/lock";
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath);
}

void AppMeshClient::unlockUser(const std::string &user)
{
    const std::string restPath = "/appmesh/user/" + user + "/unlock";
    requestHttp(ErrorPolicy::Throw, web::http::methods::POST, restPath);
}

std::set<std::string> AppMeshClient::getUserPermissions() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/user/permissions");
    auto result = nlohmann::json::parse(response->text);
    std::set<std::string> permissions;
    for (const auto &perm : result)
    {
        permissions.insert(perm.get<std::string>());
    }
    return permissions;
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

std::set<std::string> AppMeshClient::listGroups() const
{
    auto response = requestHttp(ErrorPolicy::Throw, web::http::methods::GET, "/appmesh/user/groups");
    auto result = nlohmann::json::parse(response->text);
    std::set<std::string> groups;
    for (const auto &group : result)
    {
        groups.insert(group.get<std::string>());
    }
    return groups;
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

    // request
    auto resp = RestClient::request(m_url, method, path, bodyContent, header, query);

    // check return
    if (errorPolicy == ErrorPolicy::Throw && resp->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(resp->status_code, resp->text);
    }

    if (resp->status_code == web::http::status_codes::OK &&
        resp->header.count(web::http::header_names::content_type) &&
        resp->header.get(web::http::header_names::content_type) == web::http::mime_types::text_plain_utf8)
    {
        resp->text = Utility::utf8ToLocalEncoding(resp->text);
    }

    return resp;
}

void AppMeshClient::addCommonHeaders(std::map<std::string, std::string> &header) const
{
    if (!m_forwardTo.empty())
    {
        if (m_forwardTo.find(':') == std::string::npos)
            header[HTTP_HEADER_KEY_Forwarding_Host] = m_forwardTo + ":" + std::to_string(Uri::parse(m_url).port);
        else
            header[HTTP_HEADER_KEY_Forwarding_Host] = m_forwardTo;
    }

    const auto token = RestClient::getCookie(COOKIE_CSRF_TOKEN);
    if (!token.empty())
        header[HTTP_HEADER_KEY_X_CSRF_TOKEN] = token;
}

// src/sdk/cpp/ClientHttp.cpp
#include "ClientHttp.h"

#include <iostream>
#include <map>
#include <string>

#include <ace/OS_NS_time.h>
#include <nlohmann/json.hpp>

#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.h"
#include "../../common/UriParser.hpp"

namespace
{
    const std::string HTTP_HEADER_JWT_set_cookie = "X-Set-Cookie";
    const std::string HTTP_HEADER_NAME_CSRF_TOKEN = "X-CSRF-Token";
    const std::string COOKIE_CSRF_TOKEN = "appmesh_csrf_token";
}

// === AppRun implementation ===

AppRun::AppRun(ClientHttp *client, const std::string &appName, const std::string &procUid)
    : m_client(client), m_appName(appName), m_procUid(procUid)
{
}

std::shared_ptr<int> AppRun::wait(int timeout, bool printToSTD)
{
    return this->m_client->waitForAsyncRun(this, timeout, printToSTD);
}

// === ClientHttp implementation ===

void ClientHttp::init(const std::string url, const std::string ssl_verify,
                      const std::string ssl_client_cert, const std::string ssl_client_certkey,
                      const std::string cookieFile)
{
    m_url = url;

    if (cookieFile.empty())
        RestClient::setSessionConfiguration(SessionConfig::MemorySession());
    else
        RestClient::setSessionConfiguration(SessionConfig::FileSession(cookieFile));

    ClientSSLConfig config;
    config.m_verify_server = !ssl_verify.empty();
    config.m_ca_location = ssl_verify;
    config.m_verify_client = !ssl_client_cert.empty() && !ssl_client_certkey.empty();
    config.m_certificate = ssl_client_cert;
    config.m_private_key = ssl_client_certkey;

    RestClient::defaultSslConfiguration(config);
}

void ClientHttp::forwardTo(const std::string url)
{
    m_forwardTo = url;
}

// Authentication Management
std::string ClientHttp::login(const std::string &user, const std::string &passwd,
                              const std::string totp, int timeoutSeconds, std::string audience)
{
    RestClient::clearSession();

    std::map<std::string, std::string> header;
    header[HTTP_HEADER_JWT_Authorization] = std::string(HTTP_HEADER_Auth_BasicSpace) +
                                            Utility::encode64(user + ":" + passwd);
    header[HTTP_HEADER_JWT_set_cookie] = "true";

    if (timeoutSeconds > 0)
        header[HTTP_HEADER_JWT_expire_seconds] = std::to_string(timeoutSeconds);
    if (!audience.empty())
        header[HTTP_HEADER_JWT_audience] = std::move(audience);
    if (!totp.empty())
        header[HTTP_HEADER_JWT_totp] = totp;

    auto response = this->requestHttp(false, web::http::methods::POST, "/appmesh/login", nullptr, header);

    if (response->status_code == web::http::status_codes::PreconditionRequired)
    {
        // TOTP required (HTTP 428)
        auto jsonResponse = nlohmann::json::parse(response->text);
        if (jsonResponse.contains(REST_TEXT_TOTP_CHALLENGE_JSON_KEY))
        {
            auto totpChallenge = jsonResponse.at(REST_TEXT_TOTP_CHALLENGE_JSON_KEY).get<std::string>();
            if (totp.empty())
                return totpChallenge;
            this->validateTotp(user, totpChallenge, totp, timeoutSeconds);
        }
    }
    else if (response->status_code != web::http::status_codes::OK)
    {
        throw std::invalid_argument(response->text);
    }

    return std::string();
}

void ClientHttp::validateTotp(const std::string &user, const std::string &challenge,
                              const std::string totp, int timeoutSeconds)
{
    std::map<std::string, std::string> header = {{HTTP_HEADER_JWT_set_cookie, "true"}};

    nlohmann::json body = {
        {HTTP_BODY_KEY_JWT_username, user},
        {HTTP_BODY_KEY_JWT_totp, totp},
        {HTTP_BODY_KEY_JWT_totp_challenge, challenge},
        {HTTP_BODY_KEY_JWT_expire_seconds, timeoutSeconds}};

    this->requestHttp(true, web::http::methods::POST, "/appmesh/totp/validate", &body, header);
}

std::tuple<bool, std::string> ClientHttp::authenticate(const std::string &token,
                                                       const std::string permission,
                                                       const std::string audience, bool apply)
{
    std::map<std::string, std::string> header = {
        {HTTP_HEADER_JWT_Authorization, std::string(HTTP_HEADER_JWT_BearerSpace) + token}};

    if (!permission.empty())
        header[HTTP_HEADER_JWT_auth_permission] = permission;
    if (!audience.empty())
        header[HTTP_HEADER_JWT_audience] = audience;
    if (apply)
        header[HTTP_HEADER_JWT_set_cookie] = "true";

    auto resp = this->requestHttp(false, web::http::methods::POST, "/appmesh/auth", nullptr, header);
    return std::make_tuple(resp->status_code == web::http::status_codes::OK, resp->text);
}

void ClientHttp::logout()
{
    this->requestHttp(true, web::http::methods::POST, "/appmesh/self/logoff");
    RestClient::clearSession();
}

void ClientHttp::renewToken(int timeoutSeconds)
{
    std::map<std::string, std::string> header;
    if (timeoutSeconds > 0)
        header[HTTP_HEADER_JWT_expire_seconds] = std::to_string(timeoutSeconds);

    this->requestHttp(true, web::http::methods::POST, "/appmesh/token/renew", nullptr, header);
}

std::string ClientHttp::getTotpSecret()
{
    auto response = requestHttp(true, web::http::methods::POST, "/appmesh/totp/secret");
    auto result = nlohmann::json::parse(response->text);
    return Utility::decode64(result.at(HTTP_BODY_KEY_MFA_URI).get<std::string>());
}

void ClientHttp::enableTotp(const std::string totp)
{
    std::map<std::string, std::string> header = {{HTTP_HEADER_JWT_totp, totp}};
    requestHttp(true, web::http::methods::POST, "/appmesh/totp/setup", nullptr, header);
}

void ClientHttp::disableTotp(const std::string user)
{
    const std::string restPath = "/appmesh/totp/" + user + "/disable";
    requestHttp(true, web::http::methods::POST, restPath);
}

// Application View
nlohmann::json ClientHttp::getApp(const std::string &app) const
{
    const std::string restPath = "/appmesh/app/" + app;
    auto response = requestHttp(true, web::http::methods::GET, restPath);
    return nlohmann::json::parse(response->text);
}

nlohmann::json ClientHttp::listApps() const
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/applications");
    return nlohmann::json::parse(response->text);
}

AppOutput ClientHttp::getAppOutput(const std::string &app, int outputPosition,
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

    auto response = requestHttp(true, web::http::methods::GET, restPath, nullptr, {}, query);

    AppOutput output;
    output.statusCode = response->status_code;
    output.output = response->text;

    if (response->header.count(HTTP_HEADER_KEY_output_pos))
        output.outputPosition = std::atol(response->header.at(HTTP_HEADER_KEY_output_pos).c_str());

    if (response->header.count(HTTP_HEADER_KEY_exit_code))
        output.exitCode = std::make_shared<int>(std::atoi(response->header.at(HTTP_HEADER_KEY_exit_code).c_str()));

    return output;
}

bool ClientHttp::checkAppHealth(const std::string &app) const
{
    const std::string restPath = "/appmesh/app/" + app + "/health";
    auto response = requestHttp(true, web::http::methods::GET, restPath);
    return std::stoi(response->text) == 0;
}

// Application Manage
nlohmann::json ClientHttp::addApp(const nlohmann::json &app)
{
    const std::string restPath = "/appmesh/app/" + GET_JSON_STR_VALUE(app, JSON_KEY_APP_name);
    auto response = requestHttp(true, web::http::methods::PUT, restPath, &app);
    return nlohmann::json::parse(response->text);
}

void ClientHttp::deleteApp(const std::string &app)
{
    const std::string restPath = "/appmesh/app/" + app;
    requestHttp(true, web::http::methods::DEL, restPath);
}

void ClientHttp::enableApp(const std::string &app)
{
    const std::string restPath = "/appmesh/app/" + app + "/enable";
    requestHttp(true, web::http::methods::POST, restPath);
}

void ClientHttp::disableApp(const std::string &app)
{
    const std::string restPath = "/appmesh/app/" + app + "/disable";
    requestHttp(true, web::http::methods::POST, restPath);
}

// Run Application Operations
std::tuple<std::shared_ptr<int>, std::string> ClientHttp::runAppSync(const nlohmann::json &app,
                                                                     int maxTimeout,
                                                                     int lifeCycleSeconds)
{
    std::map<std::string, std::string> query = {
        {HTTP_QUERY_KEY_timeout, std::to_string(std::abs(maxTimeout))},
        {HTTP_QUERY_KEY_lifecycle, std::to_string(std::abs(lifeCycleSeconds))}};

    auto response = requestHttp(true, web::http::methods::POST, "/appmesh/app/syncrun", &app, {}, query);

    std::shared_ptr<int> returnCode;
    if (response->header.count(HTTP_HEADER_KEY_exit_code))
        returnCode = std::make_shared<int>(std::atoi(response->header.at(HTTP_HEADER_KEY_exit_code).c_str()));

    return std::make_tuple(returnCode, response->text);
}

AppRun ClientHttp::runAppAsync(const nlohmann::json &app, int maxTimeout, int lifeCycleSeconds)
{
    std::map<std::string, std::string> query = {
        {HTTP_QUERY_KEY_timeout, std::to_string(maxTimeout)},
        {HTTP_QUERY_KEY_lifecycle, std::to_string(lifeCycleSeconds)}};

    auto response = requestHttp(true, web::http::methods::POST, "/appmesh/app/run", &app, {}, query);
    auto result = nlohmann::json::parse(response->text);

    auto appName = result.at(JSON_KEY_APP_name).get<std::string>();
    auto procUid = result.at(HTTP_QUERY_KEY_process_uuid).get<std::string>();

    return AppRun(this, appName, procUid);
}

std::shared_ptr<int> ClientHttp::waitForAsyncRun(AppRun *run, int timeout, bool printToSTD)
{
    int lastOutputPosition = 0;
    const int startTime = ACE_OS::time();

    while (true)
    {
        auto response = this->getAppOutput(run->m_appName, lastOutputPosition, 0, 10240,
                                           run->m_procUid, timeout);

        lastOutputPosition = response.outputPosition;
        if (printToSTD && !response.output.empty())
            std::cout << response.output << std::flush;

        if (response.exitCode ||
            response.statusCode != web::http::status_codes::OK ||
            (timeout > 0 && ACE_OS::time() - startTime >= timeout))
        {
            return response.exitCode;
        }
    }
}

std::string ClientHttp::runTask(const std::string &app, const nlohmann::json &data, int timeout)
{
    const std::string restPath = "/appmesh/app/" + app + "/task";
    std::map<std::string, std::string> query = {{"timeout", std::to_string(timeout)}};

    auto response = requestHttp(true, web::http::methods::POST, restPath, &data, {}, query);
    return response->text;
}

bool ClientHttp::cancelTask(const std::string &app)
{
    const std::string restPath = "/appmesh/app/" + app + "/task";
    auto response = requestHttp(false, web::http::methods::DEL, restPath);
    return response->status_code == web::http::status_codes::OK;
}

// File Management
void ClientHttp::downloadFile(const std::string &remoteFile, const std::string &localFile, bool preservePermissions)
{
    // header
    std::map<std::string, std::string> header;
    this->addCommonHeaders(header);
    header[HTTP_HEADER_KEY_file_path] = Utility::encodeURIComponent(remoteFile);

    auto response = RestClient::download(m_url, REST_PATH_DOWNLOAD, remoteFile, localFile, header);

    if (response->status_code != web::http::status_codes::OK)
    {
        throw std::invalid_argument(response->text);
    }

    if (preservePermissions)
    {
        Utility::applyFilePermission(localFile, HttpHeaderMap(response->header));
    }
}

void ClientHttp::uploadFile(const std::string &localFile, const std::string &remoteFile, bool preservePermissions)
{
    // header
    std::map<std::string, std::string> header;
    this->addCommonHeaders(header);
    header[HTTP_HEADER_KEY_file_path] = Utility::encodeURIComponent(remoteFile);
    if (preservePermissions)
    {
        auto fileInfo = os::fileStat(localFile);
        header[HTTP_HEADER_KEY_file_mode] = std::to_string(std::get<0>(fileInfo));
        header[HTTP_HEADER_KEY_file_user] = std::to_string(std::get<1>(fileInfo));
        header[HTTP_HEADER_KEY_file_group] = std::to_string(std::get<2>(fileInfo));
    }

    auto response = RestClient::upload(m_url, REST_PATH_UPLOAD, localFile, header);

    if (response->status_code != web::http::status_codes::OK)
    {
        throw std::invalid_argument(response->text);
    }
}

// System Management
nlohmann::json ClientHttp::getHostResources() const
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/resources");
    return nlohmann::json::parse(response->text);
}

nlohmann::json ClientHttp::getConfig() const
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/config");
    return nlohmann::json::parse(response->text);
}

nlohmann::json ClientHttp::setConfig(const nlohmann::json &config)
{
    auto response = requestHttp(true, web::http::methods::POST, "/appmesh/config", &config);
    return nlohmann::json::parse(response->text);
}

std::string ClientHttp::setLogLevel(const std::string &level)
{
    nlohmann::json jsonObj = {{JSON_KEY_BaseConfig, {{JSON_KEY_LogLevel, level}}}};
    auto response = this->setConfig(jsonObj);
    return response.at(JSON_KEY_BaseConfig).at(JSON_KEY_LogLevel).get<std::string>();
}

std::string ClientHttp::getMetrics()
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/metrics");
    return response->text;
}

// Tag Management
nlohmann::json ClientHttp::getTags() const
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/labels");
    return nlohmann::json::parse(response->text);
}

void ClientHttp::addTag(const std::string &tag, const std::string &value)
{
    const std::string restPath = "/appmesh/label/" + tag;
    std::map<std::string, std::string> query = {{"value", value}};
    requestHttp(true, web::http::methods::PUT, restPath, nullptr, {}, query);
}

void ClientHttp::deleteTag(const std::string &tag)
{
    const std::string restPath = "/appmesh/label/" + tag;
    requestHttp(true, web::http::methods::DEL, restPath);
}

// User Management
void ClientHttp::updatePassword(const std::string oldPwd, const std::string newPwd, const std::string user)
{
    nlohmann::json jsonObj = {
        {HTTP_BODY_KEY_OLD_PASSWORD, Utility::encode64(oldPwd)},
        {HTTP_BODY_KEY_NEW_PASSWORD, Utility::encode64(newPwd)}};

    const std::string restPath = "/appmesh/user/" + user + "/passwd";
    requestHttp(true, web::http::methods::POST, restPath, &jsonObj);
}

nlohmann::json ClientHttp::getCurrentUser() const
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/user/self");
    return nlohmann::json::parse(response->text);
}

nlohmann::json ClientHttp::listUsers() const
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/users");
    return nlohmann::json::parse(response->text);
}

void ClientHttp::addUser(const nlohmann::json &user)
{
    const std::string userName = user.at(JSON_KEY_USER_readonly_name).get<std::string>();
    const std::string restPath = "/appmesh/user/" + userName;
    requestHttp(true, web::http::methods::PUT, restPath, &user);
}

void ClientHttp::deleteUser(const std::string &user)
{
    const std::string restPath = "/appmesh/user/" + user;
    requestHttp(true, web::http::methods::DEL, restPath);
}

void ClientHttp::lockUser(const std::string user)
{
    const std::string restPath = "/appmesh/user/" + user + "/lock";
    requestHttp(true, web::http::methods::POST, restPath);
}

void ClientHttp::unlockUser(const std::string user)
{
    const std::string restPath = "/appmesh/user/" + user + "/unlock";
    requestHttp(true, web::http::methods::POST, restPath);
}

std::set<std::string> ClientHttp::getUserPermissions()
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/user/permissions");
    auto result = nlohmann::json::parse(response->text);
    std::set<std::string> permissions;
    for (const auto &perm : result)
    {
        permissions.insert(perm.get<std::string>());
    }
    return permissions;
}

std::set<std::string> ClientHttp::listPermissions()
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/permissions");
    auto result = nlohmann::json::parse(response->text);
    std::set<std::string> permissions;
    for (const auto &perm : result)
    {
        permissions.insert(perm.get<std::string>());
    }
    return permissions;
}

std::map<std::string, std::set<std::string>> ClientHttp::listRoles()
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/roles");
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

std::set<std::string> ClientHttp::listGroups()
{
    auto response = requestHttp(true, web::http::methods::GET, "/appmesh/user/groups");
    auto result = nlohmann::json::parse(response->text);
    std::set<std::string> groups;
    for (const auto &group : result)
    {
        groups.insert(group.get<std::string>());
    }
    return groups;
}

void ClientHttp::updateRole(const std::string &role, std::set<std::string> rolePermissions)
{
    nlohmann::json jsonObj = nlohmann::json::array();
    for (const auto &perm : rolePermissions)
    {
        jsonObj.push_back(perm);
    }
    const std::string restPath = "/appmesh/role/" + role;
    requestHttp(true, web::http::methods::POST, restPath, &jsonObj);
}

void ClientHttp::deleteRole(const std::string &role)
{
    const std::string restPath = "/appmesh/role/" + role;
    requestHttp(true, web::http::methods::DEL, restPath);
}

// Protected members
std::shared_ptr<CurlResponse> ClientHttp::requestHttp(bool throwOnFail,
                                                      const web::http::method &mtd,
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
    auto resp = RestClient::request(m_url, mtd, path, bodyContent, header, query);

    // check return
    if (throwOnFail && resp->status_code != web::http::status_codes::OK)
    {
        throw std::invalid_argument(resp->text);
    }

    if (resp->status_code == web::http::status_codes::OK &&
        resp->header.count(web::http::header_names::content_type) &&
        resp->header.at(web::http::header_names::content_type) == web::http::mime_types::text_plain_utf8)
    {
        resp->text = Utility::utf8ToLocalEncoding(resp->text);
    }

    return resp;
}

void ClientHttp::addCommonHeaders(std::map<std::string, std::string> &header) const
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
        header[HTTP_HEADER_NAME_CSRF_TOKEN] = token;
}

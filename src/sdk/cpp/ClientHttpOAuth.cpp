// src/sdk/cpp/ClientHttpOAuth.cpp
#include "ClientHttpOAuth.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <map>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "../../common/JwtHelper.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"

AppMeshClientOAuth::AppMeshClientOAuth(const ClientOAuthConfig &oauth, const ClientHttpConfig &config)
    : AppMeshClient(config), m_oauth(oauth)
{
}

void AppMeshClientOAuth::login(const std::string &username, const std::string &password, const std::string &totpCode)
{
    std::map<std::string, std::string> form;
    form["grant_type"] = "password";
    form["username"] = username;
    form["password"] = password;
    // Request identity claims so userinfo returns preferred_username/email.
    form["scope"] = "openid profile email";
    // Pass TOTP as-is: a numeric conversion would strip leading zeros (e.g. "012345" -> 12345).
    if (!totpCode.empty())
        form["totp"] = totpCode;

    auto response = this->requestOauth("token", form);
    if (response->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(response->status_code, response->text);
    }
    m_token = nlohmann::json::parse(response->text);
}

void AppMeshClientOAuth::loginDeviceFlow(DeviceAuthPromptHandler onPrompt, const std::string &scope)
{
    std::map<std::string, std::string> form;
    form["scope"] = scope;
    auto response = this->requestOauth("auth/device", form);
    if (response->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(response->status_code, response->text);
    }
    const auto device = nlohmann::json::parse(response->text);

    if (onPrompt)
    {
        onPrompt(device);
    }
    else
    {
        // User-facing sign-in instructions (interaction, not logging), matching the Python SDK default.
        std::string uri = device.value("verification_uri_complete", "");
        if (uri.empty())
            uri = device.value("verification_uri", "");
        std::cout << "To sign in, open " << uri << " and enter code: " << device.value("user_code", "") << std::endl;
    }

    // RFC 8628 §3.5: poll no faster than "interval", stop once the device code expires.
    long long interval = device.value("interval", 5);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(device.value("expires_in", 600));

    while (true)
    {
        const long long remaining = std::chrono::duration_cast<std::chrono::seconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0)
            throw AppMeshAuthError("Device authorization expired before the user approved the request");
        std::this_thread::sleep_for(std::chrono::seconds(std::min(interval, remaining)));

        std::map<std::string, std::string> tokenForm;
        tokenForm["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code";
        tokenForm["device_code"] = device.at("device_code").get<std::string>();
        auto tokenResponse = this->requestOauth("token", tokenForm);
        if (tokenResponse->status_code == web::http::status_codes::OK)
        {
            m_token = nlohmann::json::parse(tokenResponse->text);
            return;
        }

        const std::string error = oauthErrorCode(tokenResponse->text);
        if (error == "authorization_pending")
            continue;
        if (error == "slow_down")
        {
            interval += 5; // RFC 8628 §3.5: back off by 5 seconds
            continue;
        }
        throw AppMeshAuthError("Device authorization failed: " + (error.empty() ? tokenResponse->text : error));
    }
}

void AppMeshClientOAuth::logout()
{
    // Best-effort Keycloak session logout with the refresh token (failures ignored, as in the Python SDK).
    const std::string refreshToken = this->tokenField("refresh_token");
    if (!refreshToken.empty())
    {
        std::map<std::string, std::string> form;
        form["refresh_token"] = refreshToken;
        this->requestOauth("logout", form);
    }

    // Daemon logoff BEFORE clearing the token so the request still carries the Bearer authorization.
    AppMeshClient::logout();
    m_token = nlohmann::json();
}

void AppMeshClientOAuth::renewToken()
{
    const std::string refreshToken = this->tokenField("refresh_token");
    if (refreshToken.empty())
        throw AppMeshAuthError("No Keycloak refresh token available to renew");

    std::map<std::string, std::string> form;
    form["grant_type"] = "refresh_token";
    form["refresh_token"] = refreshToken;

    auto response = this->requestOauth("token", form);
    if (response->status_code != web::http::status_codes::OK)
    {
        throw AppMeshAuthError("Keycloak token renewal failed: " + response->text);
    }
    // Keycloak rotates refresh tokens: store the complete new response.
    m_token = nlohmann::json::parse(response->text);
}

nlohmann::json AppMeshClientOAuth::getOauthUserinfo() const
{
    std::map<std::string, std::string> header = {
        {HTTP_HEADER_JWT_Authorization, JwtHelper::buildBearerAuthorization(this->tokenField("access_token"))}};

    auto response = RestClient::request(m_oauth.authServerUrl, web::http::methods::GET,
                                        this->oauthEndpoint("userinfo"), "", header, {});
    if (response->status_code != web::http::status_codes::OK)
    {
        throw AppMeshHttpError(response->status_code, response->text);
    }
    return nlohmann::json::parse(response->text);
}

// Protected members
void AppMeshClientOAuth::addCommonHeaders(std::map<std::string, std::string> &header) const
{
    AppMeshClient::addCommonHeaders(header);

    const std::string accessToken = this->tokenField("access_token");
    if (!accessToken.empty() && header.count(HTTP_HEADER_JWT_Authorization) == 0)
    {
        header[HTTP_HEADER_JWT_Authorization] = JwtHelper::buildBearerAuthorization(accessToken);
    }
}

// Private members
std::string AppMeshClientOAuth::oauthEndpoint(const std::string &name) const
{
    return "/realms/" + m_oauth.realm + "/protocol/openid-connect/" + name;
}

std::shared_ptr<CurlResponse> AppMeshClientOAuth::requestOauth(const std::string &endpoint, std::map<std::string, std::string> formData) const
{
    formData["client_id"] = m_oauth.clientId;
    if (!m_oauth.clientSecret.empty())
        formData["client_secret"] = m_oauth.clientSecret;

    return RestClient::request(m_oauth.authServerUrl, web::http::methods::POST,
                               this->oauthEndpoint(endpoint), "", {}, {}, formData);
}

std::string AppMeshClientOAuth::tokenField(const std::string &key) const
{
    return (m_token.is_object() && m_token.contains(key) && m_token.at(key).is_string())
               ? m_token.at(key).get<std::string>()
               : std::string();
}

std::string AppMeshClientOAuth::oauthErrorCode(const std::string &responseBody)
{
    try
    {
        return nlohmann::json::parse(responseBody).value("error", "");
    }
    catch (...)
    {
        return std::string();
    }
}

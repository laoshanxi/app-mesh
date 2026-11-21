#include "VaultClient.h"

#include <fstream>
#include <sstream>
#include <thread>

#include "../../common/RestClient.h"
#include "../../common/StreamLogger.h"
#include "../../common/Utility.h"
#include "../../common/json.h"

namespace
{
	constexpr int REQUEST_TIMEOUT_SECONDS = 5;
	// A Vault outage must not take the pull loop's thread for a long ride;
	// one short retry smooths a leader election blip.
	constexpr int READ_ATTEMPTS = 2;
	const char *ENV_VAULT_CACERT = "APPMESH_VAULT_CACERT";
	const char *ENV_VAULT_TLS_SKIP_VERIFY = "APPMESH_VAULT_TLS_SKIP_VERIFY";

	/// Vault HTTP failure with the status attached, so a caller can tell one
	/// revoked entry (404) from an outage.
	struct VaultRequestError : std::runtime_error
	{
		VaultRequestError(const std::string &message, int status) : std::runtime_error(message), status(status) {}
		const int status;
	};

	/// https verifies by default (APPMESH_VAULT_CACERT or the system store);
	/// only APPMESH_VAULT_TLS_SKIP_VERIFY opts out. Inert for http addresses.
	ClientSSLConfig vaultTlsConfig(const VaultClient::Config &config)
	{
		ClientSSLConfig ssl;
		ssl.m_verify_server = config.verifyServer;
		const auto skip = Utility::getenvTrimmed(ENV_VAULT_TLS_SKIP_VERIFY);
		if (skip == "1" || skip == "true")
			ssl.m_verify_server = false;
		ssl.m_ca_location = !config.caPath.empty() ? config.caPath
												   : Utility::getenvTrimmed(ENV_VAULT_CACERT);
		return ssl;
	}

	/// Resolves the credential file into a Vault access token: one line is a
	/// static service token, two lines are an AppRole machine identity that
	/// logs in for a fresh client token on every use.
	std::string resolveAccessToken(const VaultClient::Config &config)
	{
		std::ifstream in(config.tokenFile, std::ios::binary);
		if (!in)
			throw std::runtime_error("Vault token file <" + config.tokenFile + "> is not readable");
		std::string first, second;
		std::getline(in, first);
		std::getline(in, second);
		first = Utility::stdStringTrim(first);
		second = Utility::stdStringTrim(second);
		if (first.empty())
			throw std::runtime_error("Vault token file <" + config.tokenFile + "> is empty");
		return second.empty() ? first : VaultClient::loginAppRole(config, first, second);
	}

	std::shared_ptr<HttpResponse> vaultRequest(const VaultClient::Config &config, const std::string &path,
												   const std::string &method = web::http::methods::GET)
	{
		const auto token = resolveAccessToken(config);
		std::map<std::string, std::string> headers{{"X-Vault-Token", token}};
		const auto ssl = vaultTlsConfig(config);
		std::string lastError;
		int lastStatus = 0;
		for (int attempt = 0; attempt < READ_ATTEMPTS; ++attempt)
		{
			const auto response =
				RestClient::request(config.address, method, path, "", headers, {}, REQUEST_TIMEOUT_SECONDS, &ssl);
			if (response && response->statusCode >= 200 && response->statusCode < 300)
				return response;
			lastStatus = response ? response->statusCode : 0;
			lastError = response ? "HTTP " + std::to_string(response->statusCode)
								 : std::string("transport failure");
			if (response && response->statusCode == 403)
				break; // a wrong token will not fix itself on retry
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		throw VaultRequestError("Vault request <" + path + "> failed: " + lastError, lastStatus);
	}

	/// The KV path honors the same override the operator tooling uses
	/// (APPMESH_REPLICATION_VAULT_KV_PATH), so a custom prefix deploys
	/// consistently on both sides: the engine reads what the tooling writes.
	std::string kvPath()
	{
		const auto custom = Utility::getenvTrimmed("APPMESH_REPLICATION_VAULT_KV_PATH");
		return custom.empty() ? std::string(VaultClient::KV_PATH) : custom;
	}
} // namespace

std::vector<AuthReplication::AcceptedToken> VaultClient::listReplicationTokens(const Config &config)
{
	std::shared_ptr<HttpResponse> response;
	try
	{
		response = vaultRequest(config, std::string("/v1/") + KV_MOUNT + "/metadata/" + kvPath() + "?list=true");
	}
	catch (const VaultRequestError &e)
	{
		// An empty KV store lists as 404: that is "no entries", not an outage.
		if (e.status == 404)
			return {};
		throw;
	}
	const auto root = JSON::parse(response->text);
	const auto &keys = root["data"]["keys"];
	if (!keys.isArray())
		throw std::runtime_error("Vault list response has no key array");
	std::vector<AuthReplication::AcceptedToken> tokens;
	for (const auto &key : keys)
	{
		if (!key.isString() || key.asString().empty())
			continue;
		const auto label = Utility::stdStringTrim(key.asString(), "/");
		std::string entry;
		try
		{
			entry = readReplicationToken(config, label);
		}
		catch (const VaultRequestError &e)
		{
			// Revocation deletes the data while the metadata still lists the
			// key: one revoked follower must not fail every other follower's
			// pull. Anything else is a real outage and fails closed.
			if (e.status == 404)
				continue;
			throw;
		}
		if (!entry.empty())
			tokens.push_back({entry, label});
	}
	return tokens;
}

std::string VaultClient::loginAppRole(const Config &config, const std::string &roleId, const std::string &secretId)
{
	Json::Value body(Json::objectValue);
	body["role_id"] = roleId;
	body["secret_id"] = secretId;
	// AppRole login takes no X-Vault-Token: issue it directly.
	const auto ssl = vaultTlsConfig(config);
	const auto response = RestClient::request(config.address, web::http::methods::POST, "/v1/auth/approle/login",
											  JSON::dump(body), {}, {}, REQUEST_TIMEOUT_SECONDS, &ssl);
	std::string lastError =
		response ? "HTTP " + std::to_string(response->statusCode) : std::string("transport failure");
	if (response && response->statusCode == 200)
	{
		const auto token = JSON::parse(response->text)["auth"]["client_token"].asString();
		if (!token.empty())
			return token;
		lastError = "login response carries no client token";
	}
	throw std::runtime_error("Vault AppRole login failed: " + lastError);
}

std::string VaultClient::readReplicationToken(const Config &config, const std::string &label)
{
	const auto response =
		vaultRequest(config, std::string("/v1/") + KV_MOUNT + "/data/" + kvPath() + "/" + label);
	const auto root = JSON::parse(response->text);
	// KV v2 wraps values: {"data": {"data": {"token": ...}, ...}}
	return root["data"]["data"]["token"].asString();
}

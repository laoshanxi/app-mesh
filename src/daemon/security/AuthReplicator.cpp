#include "AuthReplicator.h"

#include "AuthReplicationTokens.h"
#include "VaultClient.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>

#include "../../common/QuitHandler.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/json.h"
#include "../../common/os/filesystem.h"
#include "Security.h"

namespace
{
	constexpr int DEFAULT_INTERVAL_SECONDS = 30;
	constexpr int MIN_INTERVAL_SECONDS = 5;
	constexpr int MAX_INTERVAL_SECONDS = 3600;
	constexpr int PULL_TIMEOUT_SECONDS = 5;
	const char *REPLICATION_POLICY_PATH = "/appmesh/auth/replication/policy";

	std::string readTokenFile(const std::string &path)
	{
		std::ifstream in(path, std::ios::binary);
		if (!in)
			return {};
		std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		// The file may hold per-follower tokens, one per line with labels. This
		// node presents the FIRST one: in the shared-file topology (compose)
		// that line is the cluster's shared token; a real deployment gives each
		// follower its own single-token file anyway.
		const auto tokens = AuthReplication::parseTokenFile(content);
		return tokens.empty() ? std::string() : tokens.front().token;
	}

	/// Vault-sourced token: read fresh on every pull, so a rotation done in
	/// Vault propagates within one pull cycle (no restart, no materialized
	/// copy). A missing KV entry returns an empty token and fails the pull
	/// closed; a Vault outage throws and the pull retries next cycle.
	std::string readVaultToken(const std::string &label)
	{
		VaultClient::Config config;
		config.address = Utility::getenvTrimmed(AuthReplication::ENV_VAULT_ADDR);
		config.tokenFile = Utility::getenvTrimmed(AuthReplication::ENV_VAULT_TOKEN_FILE);
		return VaultClient::readReplicationToken(config, label);
	}
}

AuthReplicator &AuthReplicator::instance()
{
	static AuthReplicator replicator;
	return replicator;
}

void AuthReplicator::start()
{
	if (m_worker.joinable())
		return;
	const auto vaultAddress = Utility::getenvTrimmed(AuthReplication::ENV_VAULT_ADDR);
	const bool vaultSource =
		Utility::getenvTrimmed(AuthReplication::ENV_TOKEN_SOURCE) == "vault" && !vaultAddress.empty();
	m_tokenFile = Utility::getenvTrimmed(AuthReplication::ENV_TOKEN_FILE);
	// The Vault source reads its credential from Vault, not from the accept
	// file: requiring the file here would leave the documented vault-only
	// configuration without any replication at all.
	if (m_tokenFile.empty() && !vaultSource)
		return;
	m_source = Utility::getenvTrimmed(AuthReplication::ENV_FROM);
	if (m_source.empty())
	{
		// Owner side: only the token file is configured. Publish a random token
		// for the followers' read-only volume; no pull runs here. The Vault
		// source never reads it, so no unused credential is left on disk.
		if (!vaultSource)
			ensureOwnerTokenFile();
		return;
	}
	const auto interval = Utility::getenv(AuthReplication::ENV_INTERVAL);
	if (!interval.empty())
	{
		try
		{
			m_intervalSeconds = std::clamp(std::stoi(interval), MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS);
		}
		catch (const std::exception &)
		{
			m_intervalSeconds = DEFAULT_INTERVAL_SECONDS;
		}
	}
	m_caPath = Utility::getenvTrimmed(AuthReplication::ENV_CA);
	if (vaultSource)
		LOG_INF << "authorization replication enabled: from <" << m_source << "> every <" << m_intervalSeconds
				<< ">s, Vault token source <" << vaultAddress << ">";
	else
		LOG_INF << "authorization replication enabled: from <" << m_source << "> every <" << m_intervalSeconds
				<< ">s, token file <" << m_tokenFile << ">";
	m_worker = std::thread(&AuthReplicator::run, this);
}

AuthReplicator::~AuthReplicator()
{
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		m_stopped = true;
	}
	m_wakeup.notify_all();
	if (m_worker.joinable())
		m_worker.join();
}

void AuthReplicator::ensureOwnerTokenFile()
{
	const static char fname[] = "AuthReplicator::ensureOwnerTokenFile() ";
	const auto path = fs::path(m_tokenFile);
	std::error_code ec;
	fs::create_directories(path.parent_path(), ec);
	if (!ec && !Utility::isFileExist(m_tokenFile))
	{
		// 256-bit shared secret; readable by the follower identities that mount
		// the directory read-only inside the cluster network. Owner-only mode,
		// like the policy file the token authorizes reading.
		std::random_device device;
		std::ostringstream hex;
		hex << std::hex;
		for (int i = 0; i < 8; ++i)
			hex << std::setw(8) << std::setfill('0') << device();
		const auto tmp = os::createTmpFile(m_tokenFile, hex.str() + "\n", 0600);
		std::error_code renameError;
		if (!tmp.empty())
			fs::rename(tmp, m_tokenFile, renameError);
		if (tmp.empty() || renameError)
		{
			if (!tmp.empty())
				Utility::removeFile(tmp);
			LOG_WAR << fname << "could not write the replication token to <" << m_tokenFile << ">";
			return;
		}
		LOG_INF << fname << "generated the cluster replication token in <" << m_tokenFile << ">";
	}
	// Tighten a token left group/world-readable by an older build (best effort).
	fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, ec);
}

void AuthReplicator::notifyPolicyMiss()
{
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		m_missPending = true;
	}
	m_wakeup.notify_all();
}

void AuthReplicator::run()
{
	const static char fname[] = "AuthReplicator::run() ";
	LOG_INF << fname << "authorization replication worker started";
	bool firstRound = true;
	while (true)
	{
		if (!firstRound)
		{
			std::unique_lock<std::mutex> lock(m_mutex);
			// An interval tick and a policy miss both end this wait early; misses
			// arriving during a pull coalesce into the next round.
			m_wakeup.wait_for(lock, std::chrono::seconds(m_intervalSeconds), [this] { return m_stopped || m_missPending; });
			if (m_stopped)
				break;
			m_missPending = false;
		}
		firstRound = false;
		if (QuitHandler::instance()->shouldExit())
			break;
		pullOnce();
	}
	LOG_INF << fname << "authorization replication worker exited";
}

void AuthReplicator::pullOnce()
{
	const static char fname[] = "AuthReplicator::pullOnce() ";
	try
	{
		std::string token;
		const auto source = Utility::getenvTrimmed(AuthReplication::ENV_TOKEN_SOURCE);
		const auto vaultAddress =
			source == "vault" ? Utility::getenvTrimmed(AuthReplication::ENV_VAULT_ADDR) : std::string();
		if (!vaultAddress.empty())
		{
			const auto label = Utility::getenvTrimmed(AuthReplication::ENV_LABEL);
			if (label.empty() || !AuthReplication::isValidLabel(label))
			{
				LOG_WAR << fname
						<< "APPMESH_AUTH_REPLICATION_LABEL is required with the Vault token source and may only use"
						   " letters, digits, '.', '_' or '-'";
				return;
			}
			token = readVaultToken(label);
		}
		else
			token = readTokenFile(m_tokenFile);
		if (token.empty())
		{
			LOG_WAR << fname << "replication token is missing or empty";
			return;
		}

		ClientSSLConfig ssl;
		const ClientSSLConfig *sslConfig = nullptr;
		if (m_source.rfind("https://", 0) == 0)
		{
			ssl.m_verify_server = true;
			ssl.m_ca_location = m_caPath;
			sslConfig = &ssl;
		}
		else if (m_source.rfind("http://", 0) != 0)
		{
			LOG_WAR << fname << "replication source <" << m_source << "> must start with http:// or https://";
			return;
		}
		std::map<std::string, std::string> headers;
		headers[HTTP_HEADER_JWT_Authorization] = HTTP_HEADER_JWT_BearerSpace + token;
		const auto response = RestClient::request(m_source, web::http::methods::GET, REPLICATION_POLICY_PATH, "", headers,
												  {}, PULL_TIMEOUT_SECONDS, sslConfig);
		if (response->statusCode != web::http::status_codes::OK)
		{
			LOG_WAR << fname << "replication pull failed: HTTP <" << response->statusCode << ">";
			return;
		}
		std::string parseError;
		const auto root = JSON::parse(response->text, &parseError);
		if (!parseError.empty())
		{
			LOG_WAR << fname << "replication response was not valid JSON (HTTP " << response->statusCode
					<< "): " << Utility::stdStringTrim(response->text).substr(0, 160);
			return;
		}
		if (Security::instance()->applyReplicatedPolicy(root))
			LOG_INF << fname << "authorization policy synced from <" << m_source << ">";
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "replication pull failed: " << e.what();
	}
}

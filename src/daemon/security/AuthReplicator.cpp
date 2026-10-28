#include "AuthReplicator.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>

#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/json.h"
#include "Security.h"

namespace
{
	const char *ENV_FROM = "APPMESH_AUTH_REPLICATION_FROM";
	const char *ENV_TOKEN_FILE = "APPMESH_AUTH_REPLICATION_TOKEN_FILE";
	const char *ENV_CA = "APPMESH_AUTH_REPLICATION_CA";
	const char *ENV_INTERVAL = "APPMESH_AUTH_REPLICATION_INTERVAL";
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
		return Utility::stdStringTrim(content);
	}
}

AuthReplicator &AuthReplicator::instance()
{
	static AuthReplicator replicator;
	return replicator;
}

void AuthReplicator::start()
{
	if (m_enabled.load())
		return;
	m_tokenFile = Utility::stdStringTrim(Utility::getenv(ENV_TOKEN_FILE));
	if (m_tokenFile.empty())
		return;
	m_source = Utility::stdStringTrim(Utility::getenv(ENV_FROM));
	if (m_source.empty())
	{
		// Owner side: only the token file is configured. Publish a random token
		// for the followers' read-only volume; no pull runs here.
		ensureOwnerTokenFile();
		return;
	}
	const auto interval = Utility::getenv(ENV_INTERVAL);
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
	m_caPath = Utility::stdStringTrim(Utility::getenv(ENV_CA));
	m_elapsedSeconds = m_intervalSeconds; // pull on the first schedule tick
	m_enabled.store(true);
	LOG_INF << "authorization replication enabled: from <" << m_source << "> every <" << m_intervalSeconds
			<< ">s, token file <" << m_tokenFile << ">";
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
		// the directory read-only inside the cluster network.
		std::random_device device;
		std::ostringstream hex;
		hex << std::hex;
		for (int i = 0; i < 8; ++i)
			hex << std::setw(8) << std::setfill('0') << device();
		std::ofstream out(m_tokenFile, std::ios::binary | std::ios::trunc);
		out << hex.str() << std::endl;
		if (out.good())
			LOG_INF << fname << "generated the cluster replication token in <" << m_tokenFile << ">";
		else
			LOG_WAR << fname << "could not write the replication token to <" << m_tokenFile << ">";
	}
}

void AuthReplicator::notifyPolicyMiss()
{
	if (m_enabled.load())
		m_missPending.store(true);
}

void AuthReplicator::onScheduleTick(int stepSeconds)
{
	if (!m_enabled.load())
		return;
	m_elapsedSeconds += stepSeconds;
	const bool missed = m_missPending.exchange(false);
	if (!missed && m_elapsedSeconds < m_intervalSeconds)
		return;
	m_elapsedSeconds = 0;
	pullOnce();
}

void AuthReplicator::pullOnce()
{
	const static char fname[] = "AuthReplicator::pullOnce() ";
	try
	{
		const auto token = readTokenFile(m_tokenFile);
		if (token.empty())
		{
			LOG_WAR << fname << "replication token file <" << m_tokenFile << "> is missing or empty";
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
		headers[HTTP_HEADER_JWT_Authorization] = "Bearer " + token;
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

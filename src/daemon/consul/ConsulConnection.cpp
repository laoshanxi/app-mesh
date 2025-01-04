#include <algorithm>
#include <thread>

#include <nlohmann/json.hpp>

#include "../../common/DateTime.h"
#include "../../common/PerfLog.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.hpp"
#include "../Configuration.h"
#include "../ResourceCollection.h"
#include "../application/Application.h"
#include "../security/Security.h"
#include "ConsulConnection.h"

const auto SECURITY_CONSUL_PATH = fs::path("/v1/kv/") / "appmesh" / "security";

ConsulConnection::ConsulConnection()
{
}

ConsulConnection::~ConsulConnection()
{
}

std::shared_ptr<ConsulConnection> &ConsulConnection::instance()
{
	static auto singleton = std::make_shared<ConsulConnection>();
	return singleton;
}

std::shared_ptr<JsonConsul> ConsulConnection::getConfig()
{
	std::lock_guard<std::recursive_mutex> guard(m_consulMutex);
	return m_config;
}

long long ConsulConnection::getModifyIndex(const std::string &path, bool recurse)
{
	const static char fname[] = "ConsulConnection::getModifyIndex() ";

	std::map<std::string, std::string> query;
	if (recurse)
		query["recurse"] = "true";
	auto resp = requestConsul(web::http::methods::GET, path, query, {}, "");
	if (resp->header.count("x-consul-index"))
	{
		auto index = std::atoll(resp->header.find("x-consul-index")->second.c_str());
		LOG_DBG << fname << path << " index : " << index;
		return index;
	}
	else
	{
		LOG_WAR << fname << path << " failed with return code : " << resp->status_code;
		return 0;
	}
}

nlohmann::json ConsulConnection::fetchSecurityJson()
{
	const static char fname[] = "ConsulConnection::fetchSecurityJson() ";

	try
	{
		PerfLog perf(fname);

		std::string path = SECURITY_CONSUL_PATH.string();
		auto resp = requestConsul(web::http::methods::GET, path, {}, {}, "");
		if (resp->status_code == web::http::status_codes::OK)
		{
			auto respJson = nlohmann::json::parse(resp->text);
			if (!respJson.is_array() || respJson.empty())
			{
				LOG_WAR << fname << "response JSON is not an array or is empty";
				return EMPTY_STR_JSON;
			}
			auto securityJson = respJson.at(0);
			if (!HAS_JSON_FIELD(securityJson, "ModifyIndex") || !HAS_JSON_FIELD(securityJson, "Value"))
			{
				LOG_WAR << fname << "response JSON does not contain required fields: ModifyIndex or Value";
				return EMPTY_STR_JSON;
			}

			return Utility::yamlToJson(YAML::Load(Utility::decode64(GET_JSON_STR_VALUE(securityJson, "Value"))));
		}
		else
		{
			LOG_WAR << fname << "failed with return code : " << resp->status_code;
		}
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << "exception";
	}
	return EMPTY_STR_JSON;
}

void ConsulConnection::saveSecurity()
{
	const static char fname[] = "ConsulConnection::saveSecurity() ";

	// /appmesh/security
	std::string path = SECURITY_CONSUL_PATH.string();

	auto body = Utility::jsonToYaml(Security::instance()->AsJson());
	auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
	auto resp = requestConsul(web::http::methods::PUT, path, {{"flags", timestamp}}, {}, body);
	if (resp->status_code == web::http::status_codes::OK)
	{
		auto result = resp->text;
		if (resp->text != "true")
		{
			LOG_WAR << fname << "PUT " << path << " failed with response : " << result;
		}
	}
}

void ConsulConnection::init()
{
	const static char fname[] = "ConsulConnection::init() ";
	LOG_DBG << fname;

	auto file = (fs::path(Configuration::instance()->getWorkDir()) / "config" / APPMESH_CONSUL_API_CONFIG_FILE).string();
	if (!Utility::isFileExist(file))
	{
		file = (fs::path(Configuration::instance()->getWorkDir()).parent_path() / APPMESH_CONSUL_API_CONFIG_FILE).string();
	}

	{
		std::lock_guard<std::recursive_mutex> guard(m_consulMutex);
		assert(m_config == nullptr);
		m_config = JsonConsul::FromJson(Utility::yamlToJson(YAML::Load(Utility::readFile(file))));
	}

	{
		ClientSSLConfig config;
		config.m_verify_client = false;
		config.m_verify_server = !m_config->tls_insecure_skip_verify;
		config.m_certificate = m_config->tls_cert_file;
		config.m_private_key = m_config->tls_key_file;
		config.m_ca_location = m_config->tls_ca_file;
		RestClient::defaultSslConfiguration(config);
	}

	if (m_securityWatch == nullptr)
	{
		// security watch
		m_securityWatch = std::make_shared<std::thread>(std::bind(&ConsulConnection::watchSecurityThread, this));
		m_securityWatch->detach();
	}
}

std::shared_ptr<CurlResponse> ConsulConnection::requestConsul(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, const std::string &body, int timeoutSec)
{
	const static char fname[] = "ConsulConnection::requestConsul() ";

	auto response = std::make_shared<CurlResponse>();
	auto restURL = getConfig()->address;
	auto aclToken = getConfig()->token;
	try
	{
		if (!aclToken.empty())
		{
			header["X-Consul-Token"] = aclToken;
		}
		response = RestClient::request(restURL, mtd, path, body, header, query);
		// In case of REST server crash or block query timeout, will throw exception:
		// "Failed to read HTTP status line"
		LOG_DBG << fname << mtd << " " << path << " return " << response->status_code;
		return response;
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << path << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << path << " exception";
	}

	response->status_code = web::http::status_codes::ResetContent;
	response->text = std::string("failed access ").append(restURL);
	return response;
}

// https://www.consul.io/api-docs/kv
std::tuple<bool, long long> ConsulConnection::blockWatchKv(const std::string &kvPath, long long lastIndex, bool recurse)
{
	const static char fname[] = "ConsulConnection::blockWatchKv() ";

	int waitTimeout = 10; // should less than REST_REQUEST_TIMEOUT_SECONDS(60)
	std::map<std::string, std::string> query, header;
	query["index"] = std::to_string(lastIndex);
	query["wait"] = std::to_string(waitTimeout * 1000).append("ms");
	query["stale"] = "false";
	if (recurse)
	{
		query["recurse"] = "true";
	}

	auto response = requestConsul(web::http::methods::GET, kvPath, query, header, "");
	long long index = 0;
	if (response->header.count("x-consul-index"))
	{
		index = std::atoll(response->header.find("x-consul-index")->second.c_str());
	}
	bool success = (response->status_code == web::http::status_codes::OK);
	LOG_DBG << fname << "watch " << kvPath << " with timeout " << waitTimeout << ", last-index " << lastIndex << " index " << index << " success " << success;
	return std::make_tuple(success, index);
}

void ConsulConnection::watchSecurityThread()
{
	const static char fname[] = "ConsulConnection::watchSecurityThread() ";
	LOG_DBG << fname;

	std::string path = SECURITY_CONSUL_PATH.string();
	long long index = getModifyIndex(path);
	while (true)
	{
		auto result = blockWatchKv(path, index);
		if (std::get<0>(result) || (std::get<1>(result) != index && std::get<1>(result) > 0))
		{
			// watch success
			index = std::get<1>(result);

			auto securityObj = Security::FromJson(this->fetchSecurityJson());
			if (securityObj->getUsers().size())
			{
				Security::instance(securityObj);
				LOG_DBG << fname << "Security info updated from Consul successfully";
			}
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::seconds(3));
		}
	}
	LOG_DBG << fname << "exit";
}

JsonConsul::JsonConsul()
	: enable(false), tls_enable(false), tls_insecure_skip_verify(false)
{
}

std::shared_ptr<JsonConsul> JsonConsul::FromJson(const nlohmann::json &jsonObj)
{
	auto consul = std::make_shared<JsonConsul>();
	if (jsonObj.contains("consul"))
	{
		const auto &consulJson = jsonObj.at("consul");
		if (consulJson.contains("enable"))
			consul->enable = consulJson.at("enable").get<bool>();
		if (consulJson.contains("address"))
			consul->address = consulJson.at("address").get<std::string>();
		if (consulJson.contains("datacenter"))
			consul->datacenter = consulJson.at("datacenter").get<std::string>();
		if (consulJson.contains("scheme"))
			consul->scheme = consulJson.at("scheme").get<std::string>();
		if (consulJson.contains("token"))
			consul->token = consulJson.at("token").get<std::string>();
		if (consulJson.contains("tls"))
		{
			const auto &tlsJson = consulJson.at("tls");
			if (tlsJson.contains("enable"))
				consul->tls_enable = tlsJson.at("enable").get<bool>();
			if (tlsJson.contains("insecure_skip_verify"))
				consul->tls_insecure_skip_verify = tlsJson.at("insecure_skip_verify").get<bool>();
			if (tlsJson.contains("ca_file"))
				consul->tls_ca_file = tlsJson.at("ca_file").get<std::string>();
			if (tlsJson.contains("cert_file"))
				consul->tls_cert_file = tlsJson.at("cert_file").get<std::string>();
			if (tlsJson.contains("key_file"))
				consul->tls_key_file = tlsJson.at("key_file").get<std::string>();
		}
	}

	if (!Utility::startWith(consul->address, "http"))
	{
		consul->address = std::string("https://") + consul->address;
	}
	return consul;
}

nlohmann::json JsonConsul::AsJson() const
{
	nlohmann::json jsonObj;
	jsonObj["consul"]["enable"] = enable;
	jsonObj["consul"]["address"] = address;
	jsonObj["consul"]["datacenter"] = datacenter;
	jsonObj["consul"]["scheme"] = scheme;
	jsonObj["consul"]["token"] = token;
	jsonObj["consul"]["tls"]["enable"] = tls_enable;
	jsonObj["consul"]["tls"]["insecure_skip_verify"] = tls_insecure_skip_verify;
	jsonObj["consul"]["tls"]["ca_file"] = tls_ca_file;
	jsonObj["consul"]["tls"]["cert_file"] = tls_cert_file;
	jsonObj["consul"]["tls"]["key_file"] = tls_key_file;
	return jsonObj;
}
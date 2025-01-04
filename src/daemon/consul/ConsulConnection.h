#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../Label.h"

struct CurlResponse;

struct JsonConsul
{
	JsonConsul();
	static std::shared_ptr<JsonConsul> FromJson(const nlohmann::json &jsonObj);
	nlohmann::json AsJson() const;

	bool enable;
	std::string address;
	std::string datacenter;
	std::string scheme;
	std::string token;
	bool tls_enable;
	bool tls_insecure_skip_verify;
	std::string tls_ca_file;
	std::string tls_cert_file;
	std::string tls_key_file;
};

/// <summary>
/// Connection to Consul service
/// </summary>
class ConsulConnection : public TimerHandler
{
public:
	ConsulConnection();
	virtual ~ConsulConnection();
	static std::shared_ptr<ConsulConnection> &instance();
	void init();
	void saveSecurity();

	nlohmann::json fetchSecurityJson();

private:
	std::shared_ptr<JsonConsul> getConfig();
	long long getModifyIndex(const std::string &path, bool recurse = false);

	std::shared_ptr<CurlResponse> requestConsul(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, const std::string &body, int timeoutSec = REST_REQUEST_TIMEOUT_SECONDS);

	std::tuple<bool, long long> blockWatchKv(const std::string &kvPath, long long lastIndex, bool recurse = false);
	void watchSecurityThread();

private:
	mutable std::recursive_mutex m_consulMutex;
	std::shared_ptr<JsonConsul> m_config;
	std::shared_ptr<std::thread> m_securityWatch;
};

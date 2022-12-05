#pragma once

#include <memory>

#include "Utility.h"

namespace cpr
{
	class Response;
	struct SslOptions;

};

class RestClient
{
public:
	static std::shared_ptr<cpr::Response> request(const std::string url, const web::http::method &mtd, const std::string &path, nlohmann::json *body, std::map<std::string, std::string> header, std::map<std::string, std::string> query);
	static std::shared_ptr<cpr::Response> upload(const std::string url, const std::string &path, const std::string file, std::map<std::string, std::string> header);
	static std::shared_ptr<cpr::Response> download(const std::string url, const std::string &path, const std::string remoteFile, const std::string localFile, std::map<std::string, std::string> header);
};

#pragma once

#include <string>
#include <iomanip>
#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <boost/program_options.hpp>

using namespace web;				  // Common features like URIs.
using namespace web::http;			  // Common HTTP functionality
using namespace web::http::client;	  // HTTP client features
using namespace concurrency::streams; // Asynchronous streams

namespace po = boost::program_options;

//////////////////////////////////////////////////////////////////////////
// Command Line arguments parse and request/print
//////////////////////////////////////////////////////////////////////////
class ArgumentParser
{
public:
	explicit ArgumentParser(int argc, const char *argv[], int listenPort, bool sslEnabled);
	virtual ~ArgumentParser() noexcept;

	void parse();

private:
	void printMainHelp();
	void processLogon();
	void processLogoff();
	void processLoginfo();
	void processReg();
	void processUnReg();
	void processView();
	void processResource();
	void processEnableDisable(bool start);
	void processRun();
	void processDownload();
	void processUpload();
	void processTags();
	void processLoglevel();
	void processConfigView();
	void processChangePwd();
	void processLockUser();
	void processEncryptUserPwd();

	http_response requestHttp(const method &mtd, const std::string &path);
	http_response requestHttp(const method &mtd, const std::string &path, web::json::value &body);
	http_response requestHttp(const method &mtd, const std::string &path, std::map<std::string, std::string> &query, web::json::value *body = nullptr, std::map<std::string, std::string> *header = nullptr);
	http_request createRequest(const method &mtd, const std::string &path, std::map<std::string, std::string> &query, std::map<std::string, std::string> *header);

	std::string getAuthenToken();
	std::string readAuthenToken();
	std::string requestToken(const std::string &user, const std::string &passwd);

private:
	bool isAppExist(const std::string &appName);
	std::map<std::string, bool> getAppList();
	void printApps(web::json::value json, bool reduce);
	void shiftCommandLineArgs(po::options_description &desc);
	std::string reduceStr(std::string source, int limit);
	void setStdinEcho(bool enable = true);
	bool confirmInput(const char *msg);
	size_t inputSecurePasswd(char **pw, size_t sz, int mask, FILE *fp);

private:
	po::variables_map m_commandLineVariables;
	std::vector<po::option> m_pasrsedOptions;
	int m_listenPort;
	bool m_sslEnabled;
	int m_tokenTimeoutSeconds;
	std::string m_hostname;
	std::string m_username;
	std::string m_userpwd;
};

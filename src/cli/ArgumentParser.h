#pragma once

#include <iomanip>
#include <string>

#include <boost/program_options.hpp>
#include <cpprest/http_client.h>
#include <cpprest/json.h>

using namespace web;				  // Common features like URIs.
using namespace web::http;			  // Common HTTP functionality
using namespace web::http::client;	  // HTTP client features
using namespace concurrency::streams; // Asynchronous streams

namespace po = boost::program_options;
class ACE_Sig_Action;

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
	void processViewCloud();
	void processResource();
	void processEnableDisable(bool start);
	void processRun();
	void processExec();
	void processDownload();
	void processUpload();
	void processTags();
	void processLoglevel();
	void processJoinConsulCluster();
	void processConfigView();
	void processChangePwd();
	void processLockUser();
	void processEncryptUserPwd();

public:
	http_response requestHttp(bool throwAble, const method &mtd, const std::string &path);
	http_response requestHttp(bool throwAble, const method &mtd, const std::string &path, web::json::value &body);
	http_response requestHttp(bool throwAble, const method &mtd, const std::string &path, std::map<std::string, std::string> &query, web::json::value *body = nullptr, std::map<std::string, std::string> *header = nullptr);
	http_request createRequest(const method &mtd, const std::string &path, std::map<std::string, std::string> &query, std::map<std::string, std::string> *header);

private:
	std::string getAuthenToken();
	std::string getAuthenUser();
	std::string getOsUser();
	std::string readAuthenToken();
	std::string requestToken(const std::string &user, const std::string &passwd);

private:
	bool isAppExist(const std::string &appName);
	std::map<std::string, bool> getAppList();
	void printApps(web::json::value json, bool reduce);
	void shiftCommandLineArgs(po::options_description &desc);
	std::string reduceStr(std::string source, int limit);
	bool confirmInput(const char *msg);
	size_t inputSecurePasswd(char **pw, size_t sz, int mask, FILE *fp);
	void regSignal();
	void unregSignal();

private:
	po::variables_map m_commandLineVariables;
	std::vector<po::option> m_parsedOptions;
	const int m_argc;
	const char **m_argv;
	int m_listenPort;
	bool m_sslEnabled;
	int m_tokenTimeoutSeconds;
	std::string m_hostname;
	std::string m_username;
	std::string m_userpwd;
	std::shared_ptr<ACE_Sig_Action> m_sigAction;
};

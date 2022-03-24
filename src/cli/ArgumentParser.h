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
	explicit ArgumentParser(int argc, const char *argv[]);
	virtual ~ArgumentParser();

	int parse();

private:
	void printMainHelp();
	void processLogon();
	void processLogoff();
	void processLoginfo();
	std::string getLoginUser();

	void processAppAdd();
	void processAppDel();
	void processAppView();
	void processAppControl(bool start);
	int processAppRun();
	int processExec();

	void processCloudAppView();
	void processCloudNodesView();
	void processCloudJoinMaster();

	void processFileDownload();
	void processFileUpload();

	void processLoglevel();
	void processResource();
	void processTags();
	void processConfigView();

	void processUserChangePwd();
	void processUserLock();
	void processUserPwdEncrypt();
	void processUserMfaActive();
	void initRadomPassword();

public:
	http_response requestHttp(bool throwAble, const method &mtd, const std::string &path);
	http_response requestHttp(bool throwAble, const method &mtd, const std::string &path, web::json::value &body);
	http_response requestHttp(bool throwAble, const method &mtd, const std::string &path, std::map<std::string, std::string> &query, web::json::value *body = nullptr, std::map<std::string, std::string> header = {});
	http_request createRequest(const method &mtd, const std::string &path, std::map<std::string, std::string> &query, std::map<std::string, std::string> &headers);

private:
	std::string getAuthenToken();
	std::string getAuthenUser();
	std::string readAuthToken();
	void persistAuthToken(const std::string &hostName, const std::string &token);
	std::string requestToken(const std::string &user, const std::string &passwd, const std::string &totp);

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
	std::string parseOutputMessage(http_response &resp);
	const std::string getAppMeshUrl();

private:
	po::variables_map m_commandLineVariables;
	std::vector<po::option> m_parsedOptions;
	const int m_argc;
	const char **m_argv;
	int m_tokenTimeoutSeconds;
	std::string m_defaultUrl;
	std::string m_url;
	std::string m_username;
	std::string m_userpwd;
	std::string m_totp;
	std::unique_ptr<ACE_Sig_Action> m_sigAction;
};

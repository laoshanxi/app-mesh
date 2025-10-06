#pragma once

#include <iomanip>
#include <memory>
#include <string>

#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>

#include "../common/Utility.h"

struct CurlResponse;
namespace po = boost::program_options;
class ACE_Sig_Action;

//////////////////////////////////////////////////////////////////////////
// Command Line arguments parse and request/print
//////////////////////////////////////////////////////////////////////////
class ArgumentParser
{
public:
	explicit ArgumentParser(int argc, char *argv[]);
	virtual ~ArgumentParser();

	int parse();

private:
	void initArgs();
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
	int processShell();

	void processFileDownload();
	void processFileUpload();

	void processLoglevel();
	void processResource();
	void processTags();
	void processConfigView();

	void processUserChangePwd();
	void processUserLock();
	void processUserManage();
	void processUserPwdEncrypt();
	void processUserMfa();
	void initRadomPassword();

public:
	std::shared_ptr<CurlResponse> requestHttp(bool shouldThrow, const web::http::method &mtd, const std::string &path, nlohmann::json *body = nullptr, std::map<std::string, std::string> header = {}, std::map<std::string, std::string> query = {});

	std::string acquireAuthToken();
	std::string getAuthenUser();
	std::string getAuthToken();
	std::string readPersistLastHost(const std::string &defaultAddress);
	void persistUserConfig(const std::string &hostName);
	std::string login(const std::string &user, const std::string &passwd, std::string targetHost, std::string audience);
	static std::string getAndCreateConfigDir();
	static std::string getAndCreateCookieDirectory(const std::string &host);

private:
	bool isAppExist(const std::string &appName);
	std::map<std::string, bool> getAppList();
	void printApps(const nlohmann::json &json, bool reduce);
	void shiftCommandLineArgs(po::options_description &desc, bool allowUnregistered = false);
	std::string reduceStr(std::string source, int limit);
	bool confirmInput(const char *msg);
	std::string inputPasswd(const std::string &userNameDesc);
	size_t inputSecurePasswd(char **pw, size_t sz, int mask, FILE *fp);
	void regSignal();
	void unregSignal();
	std::string parseOutputMessage(std::shared_ptr<CurlResponse> &resp);
	int runAsyncApp(nlohmann::json &jsonObj, int timeoutSeconds, int lifeCycleSeconds);
	const std::string getAppMeshUrl();
	const std::string getPosixTimezone();
	const std::string parseUrlHost(const std::string &url);
	const std::string parseUrlPort(const std::string &url);

private:
	po::variables_map m_commandLineVariables;
	std::vector<po::option> m_parsedOptions;
	int m_argc;
	char **m_argv;
	int m_tokenTimeoutSeconds;
	std::string m_audience;
	std::string m_defaultUrl;
	std::string m_currentUrl;
	std::string m_username;
	std::string m_userpwd;
	std::string m_forwardTo;
};

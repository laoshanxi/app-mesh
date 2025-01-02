#pragma once

#include <iomanip>
#include <memory>
#include <string>

#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>

#include "../../common/Utility.h"

struct CurlResponse;
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
	void saveUserCmdHistory(const char *input);

	void processFileDownload();
	void processFileUpload();

	void processLoglevel();
	void processResource();
	void processTags();
	void processConfigView();

	void processUserChangePwd();
	void processUserLock();
	void processUserView();
	void processUserPwdEncrypt();
	void processUserMfa();
	void initRadomPassword();

public:
	std::shared_ptr<CurlResponse> requestHttp(bool throwAble, const web::http::method &mtd, const std::string &path, nlohmann::json *body = nullptr, std::map<std::string, std::string> header = {}, std::map<std::string, std::string> query = {});

	std::string getAuthenToken();
	std::string getAuthenUser();
	std::string readPersistAuthToken(const std::string &hostName);
	std::string readPersistLastHost(const std::string &defaultAddress);
	void persistAuthToken(const std::string &hostName, const std::string &token);
	std::string login(const std::string &user, const std::string &passwd, std::string targetHost);

private:
	bool isAppExist(const std::string &appName);
	std::map<std::string, bool> getAppList();
	void printApps(nlohmann::json json, bool reduce);
	void shiftCommandLineArgs(po::options_description &desc, bool allowUnregistered = false);
	std::string reduceStr(std::string source, int limit);
	bool confirmInput(const char *msg);
	std::string inputPasswd();
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
	const int m_argc;
	const char **m_argv;
	int m_tokenTimeoutSeconds;
	std::string m_defaultUrl;
	std::string m_currentUrl;
	std::string m_username;
	std::string m_userpwd;
	std::unique_ptr<ACE_Sig_Action> m_sigAction;
	std::string m_jwtToken;
	std::string m_forwardTo;
};

#pragma once

#include <iomanip>
#include <memory>
#include <string>

#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>

#include "../common/Utility.h"
#include "../sdk/cpp/ClientHttp.h"

namespace po = boost::program_options;
class ACE_Sig_Action;

//////////////////////////////////////////////////////////////////////////
// Command Line arguments parse and request/print
//////////////////////////////////////////////////////////////////////////
class CommandDispatcher : public ClientHttp
{
public:
	explicit CommandDispatcher(int argc, char *argv[]);
	virtual ~CommandDispatcher();

	int execute();

private:
	void printMainHelp();
	void initCommandMap();
	void initArgs();

	int cmdLogin();
	int cmdLogoff();
	int cmdLoginUserInfo();

	int cmdAppAdd();
	int cmdAppDelete();
	int cmdAppView();
	int cmdAppControlState(bool start);
	int cmdAppRun();
	int cmdExecuteShell();

	int cmdDownloadFile();
	int cmdUploadFile();

	int cmdLogLevel();
	int cmdHostResources();
	int cmdLabelManage();
	int cmdConfigView();

	int cmdChangePwd();
	int cmdUserLock();
	int cmdUserManage();
	int cmdEncryptPassword();
	int cmdUserMFA();
	int cmdInitRandomPassword();

public:
	std::string getLoginUser();
	std::string acquireAuthToken();
	std::string getAuthenUser();
	std::string getAuthToken();
	std::string readPersistLastHost();
	void persistUserConfig(const std::string &hostName);
	static std::string getAndCreateConfigDir();
	static std::string getAndCreateCookieDirectory(const std::string &host);

private:
	bool isAppExist(const std::string &appName);
	std::map<std::string, bool> getAppList();
	void printApps(const nlohmann::json &json, bool reduce);
	void shiftCommandLineArgs(po::options_description &desc, bool allowUnregistered = false);
	std::string reduceStr(std::string source, size_t limit);
	bool confirmInput(const char *msg);
	std::string inputPasswd(const std::string &userNameDesc);
	int inputSecurePasswd(char **pw, size_t sz, int mask, FILE *fp);
	void setupInterruptHandler(const std::string &appName);
	void teardownInterruptHandler();
	std::string parseOutputMessage(std::shared_ptr<CurlResponse> &resp);
	std::shared_ptr<int> runAsyncApp(nlohmann::json &jsonObj, int timeoutSeconds, int lifeCycleSeconds);
	std::string getDefaultURL();
	void initClient(const std::string &url);
	const std::string getPosixTimezone();
	static std::string hostSafeDir(const std::string &host);

	void setCurrentUrl(const std::string &userSpecifyUrl);

private:
	using CommandHandler = std::function<int()>;
	std::map<std::string, CommandHandler> m_commandMap;
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
};

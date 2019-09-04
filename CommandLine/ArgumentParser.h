#ifndef ARGUMENT_PARSER_H
#define ARGUMENT_PARSER_H
#include <string>
#include <iomanip>
#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <boost/program_options.hpp>

using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams

namespace po = boost::program_options;

//////////////////////////////////////////////////////////////////////////
// Command Line arguments parse and request/print
//////////////////////////////////////////////////////////////////////////
class ArgumentParser
{
public:
	ArgumentParser(int argc, const char* argv[], int listenPort, bool sslEnabled, bool printDebug);
	virtual ~ArgumentParser();

	void parse();

private:
	void printMainHelp();
	void processReg(const char* appName = 0);
	void processUnReg();
	void processView();
	void processResource();
	void processStartStop(bool start);
	void processTest();
	void processShell();
	void processDownload();
	void processUpload();

	bool confirmInput(const char* msg);
	http_response requestHttp(const method & mtd, const std::string& path);
	http_response requestHttp(const method & mtd, const std::string& path, web::json::value& body);
	http_response requestHttp(const method& mtd, const std::string& path, std::map<std::string, std::string>& query, web::json::value* body = nullptr, std::map<std::string, std::string>* header = nullptr);
	http_request createRequest(const method& mtd, const std::string& path, std::map<std::string, std::string>& query, std::map<std::string, std::string>* header);
	
	void addAuthenToken(http_request& request);

private:
	bool isAppExist(const std::string& appName);
	std::map<std::string, bool> getAppList();
	void printApps(web::json::value json, bool reduce);
	void moveForwardCommandLineVariables(po::options_description& desc);
	std::string reduceStr(std::string source, int limit);

private:
	po::variables_map m_commandLineVariables;
	std::vector<po::option> m_pasrsedOptions;
	int m_listenPort;
	bool m_sslEnabled;
	std::string m_hostname;
	bool m_printDebug;
};
#endif


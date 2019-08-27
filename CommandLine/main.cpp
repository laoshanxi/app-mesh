
#include <stdio.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <pplx/threadpool.h>
#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <boost/program_options.hpp>
#include "ArgumentParser.h"
#include "../common/Utility.h"

namespace po = boost::program_options;
void getListenPort(int& port, bool& sslEnabled);

int main(int argc, const char * argv[])
{
	PRINT_VERSION();
	try
	{
		int port;
		bool ssl;
		crossplat::threadpool::initialize_with_threads(1);
		getListenPort(port, ssl);
		ArgumentParser parser(argc, argv, port, ssl, true);
		parser.parse();
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
	return 0;
}

void getListenPort(int& port, bool& sslEnabled)
{
	// Get listen port
	port = DEFAULT_REST_LISTEN_PORT;
	web::json::value jsonValue;
	auto configPath = Utility::getSelfFullPath();
	configPath[configPath.length() - 1] = '\0';
	auto pos = configPath.rfind("/");
	if (pos != std::string::npos)
	{
		configPath = configPath.substr(0, pos + 1);
	}
	else
	{
		assert(false);
	}
	auto file = Utility::readFileCpp(configPath + "appsvc.json");
	if (file.length() > 0)
	{
		jsonValue = web::json::value::parse(GET_STRING_T(file));
		auto p = GET_JSON_INT_VALUE(jsonValue.as_object(), "RestListenPort");
		if (p > 1000 && p < 65534)
		{
			port = p;
		}
		sslEnabled = GET_JSON_BOOL_VALUE(jsonValue.as_object(), "SSLEnabled");
	}
}

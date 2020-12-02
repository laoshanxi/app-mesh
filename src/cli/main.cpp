
#include <stdio.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <ace/OS.h>
#include <pplx/threadpool.h>
#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <boost/program_options.hpp>
#include "ArgumentParser.h"
#include "../common/Utility.h"

namespace po = boost::program_options;
void getListenPort(int &port, bool &sslEnabled);

int main(int argc, const char *argv[])
{
	PRINT_VERSION();
	try
	{
		int port = DEFAULT_REST_LISTEN_PORT;
		bool ssl = false;
		crossplat::threadpool::initialize_with_threads(1);
		getListenPort(port, ssl);
		ArgumentParser parser(argc, argv, port, ssl);
		parser.parse();
	}
	catch (const std::exception &e)
	{
		std::cout << e.what() << std::endl;
		return -1;
	}
	return 0;
}

void getListenPort(int &port, bool &sslEnabled)
{
	// Get listen port
	web::json::value jsonValue;
	auto configPath = Utility::getSelfFullPath();
	configPath[configPath.length() - 1] = '\0';
	auto pos = configPath.rfind(ACE_DIRECTORY_SEPARATOR_STR);
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
		if (HAS_JSON_FIELD(jsonValue, JSON_KEY_REST) &&
			HAS_JSON_FIELD(jsonValue.at(JSON_KEY_REST), JSON_KEY_RestListenPort))
		{
			auto rest = jsonValue.at(JSON_KEY_REST);
			port = GET_JSON_INT_VALUE(rest, JSON_KEY_RestListenPort);
			// SSL
			if (HAS_JSON_FIELD(rest, JSON_KEY_SSL) &&
				HAS_JSON_FIELD(rest.at(JSON_KEY_SSL), JSON_KEY_SSLEnabled))
			{
				sslEnabled = GET_JSON_BOOL_VALUE(rest.at(JSON_KEY_SSL), JSON_KEY_SSLEnabled);
			}
		}
	}
}

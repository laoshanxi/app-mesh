
#include <iomanip>
#include <iostream>
#include <stdio.h>
#include <string>

#include <ace/OS.h>
#include <boost/program_options.hpp>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <pplx/threadpool.h>

#include "../common/Utility.h"
#include "ArgumentParser.h"

namespace po = boost::program_options;
void getListenPort(int &port, bool &sslEnabled);

/// <summary>
/// Command line entrypoint
/// </summary>
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
	std::string jsonPath = Utility::getSelfDir() + ACE_DIRECTORY_SEPARATOR_STR + APPMESH_CONFIG_JSON_FILE;
	auto file = Utility::readFileCpp(jsonPath);
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

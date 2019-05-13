
#include <stdio.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <boost/program_options.hpp>
#include "ArgumentParser.h"
#include "../common/Utility.h"

namespace po = boost::program_options;
int getListenPort();

int main(int argc, char * argv[])
{
	PRINT_VERSION();
	try
	{
		int port = getListenPort();
		ArgumentParser parser(argc, argv, port);
		parser.parse();
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
	return 0;
}

int getListenPort()
{
	// Get listen port
	int port = DEFAULT_REST_LISTEN_PORT;
	web::json::value jsonValue;
	auto configPath = Utility::getSelfFullPath();
	configPath[configPath.length()] = '\0';
	auto file = Utility::readFileCpp(configPath + ".json");
	if (file.length() > 0)
	{
		jsonValue = web::json::value::parse(GET_STRING_T(file));
		auto p = GET_JSON_INT_VALUE(jsonValue.as_object(), "RestListenPort");
		if (p > 1000 && p < 65534)
		{
			port = p;
		}
	}
	return port;
}

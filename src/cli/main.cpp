#include <algorithm>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

#include "../common/Utility.h"
#include "CommandDispatcher.h"

std::string extractErrorMessage(const std::string &message);

int main(int argc, char *argv[])
{
	PRINT_VERSION();
	try
	{
		Utility::initLogging(std::string());
		CommandDispatcher arg(argc, argv);
		return arg.execute();
	}
	catch (const std::exception &e)
	{
		std::cerr << extractErrorMessage(e.what()) << std::endl;

		if (std::any_of(argv + 1, argv + argc,
						[](const char *arg)
						{ return std::string(arg) == "-f"; }))
		{
			return 0;
		}
		return -1;
	}
}

std::string extractErrorMessage(const std::string &message)
{
	if (message.empty())
		return {};

	try
	{
		auto respJson = nlohmann::json::parse(message, nullptr, false);
		if (!respJson.is_discarded())
		{
			if (respJson.contains(REST_TEXT_MESSAGE_JSON_KEY))
				return respJson.value(REST_TEXT_MESSAGE_JSON_KEY, "");
			return respJson.dump(2);
		}
	}
	catch (...)
	{
	}
	return message;
}

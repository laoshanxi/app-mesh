#include <string>

#include <boost/filesystem/operations.hpp>

#include "../common/Utility.h"
#include "CommandDispatcher.h"

/// <summary>
/// Command line entrypoint
/// </summary>
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
		std::cout << e.what() << std::endl;

		// do not return -1 in case of input '-f'
		for (int i = 1; i < argc; i++)
		{
			if (std::string("-f") == argv[i])
			{
				return 0;
			}
		}
		return -1;
	}
	return 0;
}

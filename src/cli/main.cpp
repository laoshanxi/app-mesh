#include <string>

#include "../common/Utility.h"
#include "client/ArgumentParser.h"

/// <summary>
/// Command line entrypoint
/// </summary>
int main(int argc, const char *argv[])
{
	PRINT_VERSION();
	try
	{
		ArgumentParser parser(argc, argv);
		return parser.parse();
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

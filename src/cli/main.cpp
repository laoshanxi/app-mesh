
#include "../common/Utility.h"
#include "ArgumentParser.h"

/// <summary>
/// Command line entrypoint
/// </summary>
int main(int argc, const char *argv[])
{
	PRINT_VERSION();
	try
	{
		Utility::initCpprestThreadPool(1);
		ArgumentParser parser(argc, argv, DEFAULT_REST_LISTEN_PORT, true);
		parser.parse();
	}
	catch (const std::exception &e)
	{
		std::cout << e.what() << std::endl;
		return -1;
	}
	return 0;
}

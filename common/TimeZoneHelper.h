#ifndef TIME_ZONE_HELPER_H
#define TIME_ZONE_HELPER_H
#include <string>
#include <chrono>

class TimeZoneHelper
{
public:
	TimeZoneHelper();
	virtual ~TimeZoneHelper();

	// Convert target zone time to current zone
	static std::chrono::system_clock::time_point convert2tzTime(std::chrono::system_clock::time_point& dst, std::string& posixTimezone);
};
#endif


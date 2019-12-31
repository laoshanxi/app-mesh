#pragma once

#include <string>
#include <chrono>

//////////////////////////////////////////////////////////////////////////
/// convert time_point with timtzone
//////////////////////////////////////////////////////////////////////////
class TimeZoneHelper
{
public:
	TimeZoneHelper();
	virtual ~TimeZoneHelper();

	// Convert target zone time to current zone
	static std::chrono::system_clock::time_point convert2tzTime(std::chrono::system_clock::time_point& dst, std::string& posixTimezone);
};

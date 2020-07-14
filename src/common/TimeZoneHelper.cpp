#include <boost/date_time/local_time/local_time.hpp>
#include "TimeZoneHelper.h"
#include "Utility.h"

TimeZoneHelper::TimeZoneHelper()
{
}

TimeZoneHelper::~TimeZoneHelper()
{
}


std::chrono::system_clock::time_point TimeZoneHelper::convert2tzTime(std::chrono::system_clock::time_point& origin_time, std::string& posixTimezone)
{
	const static char fname[] = "ApplicationShortRun::convert2tzTime() ";

	try
	{
		// https://www.boost.org/doc/libs/1_58_0/doc/html/date_time/examples.html#date_time.examples.simple_time_zone
		// 1. Get original time with target time zone
		//std::chrono::system_clock::time_point origin_time = std::chrono::system_clock::now();
		std::time_t origin_timet = std::chrono::system_clock::to_time_t(origin_time);
		struct tm origin_localtime;
		::localtime_r(&origin_timet, &origin_localtime);
		boost::gregorian::date origin_date(origin_localtime.tm_year + 1900, origin_localtime.tm_mon + 1, origin_localtime.tm_mday);
		boost::posix_time::time_duration origin_time_duration(origin_localtime.tm_hour, origin_localtime.tm_min, origin_localtime.tm_sec);
		// https://stackoverflow.com/questions/36411557/how-to-make-sure-that-posix-time-zone-constructor-wont-crash-when-invalid-strin
		boost::local_time::time_zone_ptr zone(new boost::local_time::posix_time_zone(posixTimezone));
		boost::local_time::local_date_time origin_local_time(origin_date, origin_time_duration, zone, boost::local_time::local_date_time::NOT_DATE_TIME_ON_ERROR);
		//std::cout << origin_local_time.to_string() << std::endl;

		// 2. Convert time to current time zone
		boost::local_time::time_zone_ptr dst_tz(new boost::local_time::posix_time_zone(Utility::getSystemPosixTimeZone()));
		auto target_local_time = origin_local_time.local_time_in(dst_tz);
		//std::cout << target_time.to_string() << std::endl;

		// 3. Convert local_date_time to time_point
		// https://stackoverflow.com/questions/4910373/interoperability-between-boostdate-time-and-stdchrono
		auto timepoint = std::chrono::system_clock::from_time_t(boost::posix_time::to_time_t(target_local_time.utc_time()));

		LOG_INF << fname << "time <" << Utility::convertTime2Str(origin_time) << "> with timezone <" << posixTimezone
			<< "> was convert system time <" << Utility::convertTime2Str(timepoint) << "> from timezone <" << Utility::getSystemPosixTimeZone() << ">.";
		return std::move(timepoint);
	}
	catch (...)
	{
		LOG_WAR << fname << "unknown exception : " << std::strerror(errno);
		return origin_time;
	}
}
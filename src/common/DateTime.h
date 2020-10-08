#pragma once

#include <chrono>
#include <string>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

// https://stackoverflow.com/questions/8746848/boost-get-the-current-local-date-time-with-current-time-zone-from-the-machine
class machine_time_zone : public boost::local_time::custom_time_zone
{
	typedef boost::local_time::custom_time_zone base_type;
	typedef base_type::time_duration_type time_duration_type;

public:
	machine_time_zone();
	// This method is not precise, real offset may be several seconds more or less.
	static const boost::posix_time::time_duration &get_utc_offset();
	// GMT
	static const std::string &get_std_zone_abbrev();
};

class DateTime
{
public:
	// +08:00:00
	static const std::string getLocalUtcOffset();
	// "2005-10-15 13:12:11-07:00"
	static std::chrono::system_clock::time_point parseISO8601DateTime(const std::string &strTime, const std::string &posixTimeZone);

	// output 2017-09-11T21:52:13+00:00 in local time with offset
	static std::string formatISO8601Time(const std::chrono::system_clock::time_point &time);
	static std::string formatLocalTime(const std::chrono::system_clock::time_point &time, const char *fmt);
	// output 2019-01-23T10:18:32.079Z in UTC
	static std::string formatRFC3339Time(const std::chrono::system_clock::time_point &time);

	// +08:00
	static std::string getISO8601TimeZone(const std::string &strTime);

	static boost::posix_time::time_duration getDayTimeDuration(const std::chrono::system_clock::time_point &time);
	static boost::posix_time::time_duration parseDayTimeDuration(const std::string &strTime, const std::string &posixTimezone);

	// +08:00:00 -> +08
	static std::string reducePosixZone(const std::string &timeStr);
};

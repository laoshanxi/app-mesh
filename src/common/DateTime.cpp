#include <chrono>
#include <ctime>
#include <iostream>

#include <ace/OS.h>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "DateTime.h"
#include "Utility.h"

static const boost::local_time::time_zone_ptr LOCAL_POSIX_ZONE = boost::local_time::time_zone_ptr(new machine_time_zone());
static boost::local_time::time_zone_ptr OUTPUT_POSIX_ZONE;

machine_time_zone::machine_time_zone()
	: boost::local_time::custom_time_zone(
		  time_zone_names("Local machine time zone", get_std_zone_abbrev(), "", ""),
		  get_utc_offset(),
		  boost::local_time::dst_adjustment_offsets(
			  time_duration_type(0, 0, 0),
			  time_duration_type(0, 0, 0), time_duration_type(0, 0, 0)),
		  boost::shared_ptr<boost::local_time::dst_calc_rule>())
{
}

// This method is not precise, real offset may be several seconds more or less.
const boost::posix_time::time_duration &machine_time_zone::get_utc_offset()
{
	using boost::posix_time::second_clock;
	static boost::posix_time::time_duration utc_offset(second_clock::local_time() - second_clock::universal_time());
	return utc_offset;
}

const std::string &machine_time_zone::get_std_zone_abbrev()
{
	// https://stackoverflow.com/questions/2136970/how-to-get-the-current-time-zone/28259774#28259774
	static std::string zone;
	static bool init = false;
	if (!init)
	{
		init = true;
		struct tm local_tm;
		time_t cur_time = 0;
		ACE_OS::localtime_r(&cur_time, &local_tm);
		char buff[64] = {0};
		strftime(buff, sizeof(buff), "%Z", &local_tm);
		zone = buff;
	}
	return zone;
}

std::chrono::system_clock::time_point DateTime::parseISO8601DateTime(const std::string &strTime, const std::string &posixTimeZone)
{
	const static char fname[] = "DateTime::parseISO8601DateTime() ";

	// Check if the input time string is empty and return epoch time if so.
	if (strTime.empty())
	{
		LOG_DBG << fname << "Empty date-time string input, returning epoch time.";
		return std::chrono::system_clock::from_time_t(0);
	}

	// Copy the input string for processing
	std::string iso8601TimeStr = strTime;

	// Extract the timezone part from the input string if present
	std::string zoneStr = DateTime::getISO8601TimeZone(iso8601TimeStr);

	if (zoneStr.empty())
	{
		if (!posixTimeZone.empty())
		{
			// Use the provided POSIX timezone if no timezone is found in the string
			zoneStr = posixTimeZone;
		}
		else
		{
			// Default to the local timezone offset if none is provided or found
			zoneStr = DateTime::getLocalZoneUTCOffset();
		}
		iso8601TimeStr += zoneStr; // Append the timezone to the date-time string
	}

	try
	{
		// Replace 'T' with a space to match the expected input format
		iso8601TimeStr = Utility::stringReplace(iso8601TimeStr, "T", " ");

		// Determine the appropriate ISO8601 format (with seconds or minutes precision)
		std::string format = ISO8601FORMAT_IN_MINUTES;
		if (!zoneStr.empty() && iso8601TimeStr.length() > zoneStr.length())
		{
			// Extract the date-time portion without the timezone
			auto dateTimeSectionStr = iso8601TimeStr.substr(0, iso8601TimeStr.length() - zoneStr.length());

			// Check the number of colons to decide the format (e.g., hours:minutes vs. hours:minutes:seconds)
			if (Utility::charCount(dateTimeSectionStr, ':') == 2)
			{
				format = ISO8601FORMAT_IN_SECONDS;
			}
		}

		// Setup a string stream for parsing the date-time string
		std::istringstream iss(iso8601TimeStr);
		iss.exceptions(std::ios_base::failbit); // Enable exception throwing on parsing errors

		// Apply a custom locale with a local_time_input_facet for parsing
		iss.imbue(std::locale(std::locale::classic(), new boost::local_time::local_time_input_facet(format)));

		// Parse the string into a boost::local_date_time object
		boost::local_time::local_date_time localDateTime(boost::date_time::special_values::not_a_date_time);
		iss >> localDateTime;

		LOG_DBG << fname << "Converted ISO8601 string <" << iso8601TimeStr << "> to local time <" << localDateTime << ">";

		// Convert the parsed time to UTC and then to std::chrono::system_clock::time_point
		auto ptime = localDateTime.utc_time();
		return std::chrono::system_clock::from_time_t(boost::posix_time::to_time_t(ptime));
	}
	catch (const std::ios_base::failure &fail)
	{
		// Log and rethrow exception for invalid ISO8601 strings
		LOG_WAR << fname << "Failed to parse ISO8601 string: <" << iso8601TimeStr << ">, Error: " << fail.what();
		throw std::invalid_argument("Invalid ISO8601 string");
	}
	catch (...)
	{
		// Catch any other exceptions and log a generic error
		LOG_WAR << fname << "Failed to parse ISO8601 string: <" << iso8601TimeStr << ">, unknown error occurred";
		throw std::invalid_argument("Invalid ISO8601 string");
	}
}

const std::string DateTime::getLocalZoneUTCOffset()
{
	const static char fname[] = "DateTime::getLocalZoneUTCOffset() ";
	// option: https://stackoverflow.com/questions/2136970/how-to-get-the-current-time-zone/28259774#28259774
	static std::string zone;
	if (zone.empty())
	{
		boost::posix_time::time_duration tz_offset = machine_time_zone::get_utc_offset();
		std::ostringstream ss;
		ss << (tz_offset.is_negative() ? "" : "+");
		ss << tz_offset;
		zone = ss.str();
		LOG_DBG << fname << "Local timezone UTC offset: " << zone;
	}
	return zone;
}

const boost::local_time::time_zone_ptr &DateTime::initOutputFormatPosixZone(const std::string &posixZone)
{
	if (posixZone.length())
	{
		auto duration = boost::posix_time::duration_from_string(posixZone);
		auto formatStr = boost::posix_time::to_simple_string(duration);
		OUTPUT_POSIX_ZONE = boost::local_time::time_zone_ptr(new boost::local_time::posix_time_zone(formatStr));
	}
	else
	{
		OUTPUT_POSIX_ZONE = LOCAL_POSIX_ZONE;
	}
	return OUTPUT_POSIX_ZONE;
}

std::string DateTime::formatISO8601Time(const std::chrono::system_clock::time_point &time)
{
	return formatLocalTime(time, ISO8601FORMAT_OUT);
}

std::string DateTime::formatRFC3339Time(const std::chrono::system_clock::time_point &time)
{
	// do not need posix zone here
	// https://www.boost.org/doc/libs/1_69_0/doc/html/date_time/date_time_io.html
	std::ostringstream oss;
	oss.exceptions(std::ios_base::failbit);
	oss.imbue(std::locale(std::locale::classic(), new boost::posix_time::time_facet(RFC3339FORMAT)));
	oss << boost::posix_time::from_time_t(std::chrono::system_clock::to_time_t(time));
	return oss.str();
}

std::string DateTime::formatLocalTime(const std::chrono::system_clock::time_point &time, const char *fmt)
{
	const static char fname[] = "DateTime::formatLocalTime() ";

	if (time == std::chrono::system_clock::time_point::min() || time == std::chrono::system_clock::time_point::max())
	{
		LOG_DBG << fname << "Invalid time point provided (min/max value)";
		return std::string();
	}

	try
	{
		if (OUTPUT_POSIX_ZONE == nullptr)
		{
			initOutputFormatPosixZone("");
		}
		struct tm local_tm;
		memset(&local_tm, 0, sizeof(local_tm));
		auto timeT = std::chrono::system_clock::to_time_t(time);
		ACE_OS::localtime_r(&timeT, &local_tm);
		boost::gregorian::date target_date(local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday);
		boost::posix_time::time_duration target_duration(local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec);
		boost::local_time::local_date_time localDateTime(target_date, target_duration, LOCAL_POSIX_ZONE, boost::local_time::local_date_time::NOT_DATE_TIME_ON_ERROR);
		if (OUTPUT_POSIX_ZONE && OUTPUT_POSIX_ZONE != LOCAL_POSIX_ZONE && OUTPUT_POSIX_ZONE->base_utc_offset() != LOCAL_POSIX_ZONE->base_utc_offset())
		{
			localDateTime = localDateTime.local_time_in(OUTPUT_POSIX_ZONE);
		}

		std::ostringstream oss;
		oss.exceptions(std::ios_base::failbit);
		oss.imbue(std::locale(std::locale::classic(), new boost::local_time::local_time_facet(fmt)));
		oss << localDateTime;
		return reducePosixZone(oss.str());
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "Failed to format time <" << std::chrono::system_clock::to_time_t(time) << "> with format <" << fmt << ">. Error: " << e.what();
	}
	return std::string();
}

std::string DateTime::getISO8601TimeZone(const std::string &strTime)
{
	// go through with reversed order
	for (size_t i = strTime.length() - 1; i > 0; i--)
	{
		switch (strTime[i])
		{
		case '-':
		case '+':
			return strTime.substr(i); // found zone string
		case ' ':
		case 'T':
			return std::string(); // not found zone string
		default:
			break;
		}
	}
	return std::string();
}

boost::posix_time::time_duration DateTime::pickDayTimeUtcDuration(const std::chrono::system_clock::time_point &time)
{
	const auto ptime = boost::posix_time::from_time_t(std::chrono::system_clock::to_time_t(time));
	return ptime.time_of_day();
}

boost::posix_time::time_duration DateTime::parseDayTimeUtcDuration(std::string strTime)
{
	const static char fname[] = "DateTime::parseDayTimeUtcDuration() ";

	const std::string posixTimezone = DateTime::getISO8601TimeZone(strTime);
	strTime = Utility::stdStringTrim(strTime, posixTimezone, false, true);
	// re-format to accept [%H:%M] and [%H], duration parse need provide [%H:%M:%S] for parseISO8601DateTime
	auto duration = boost::posix_time::duration_from_string(strTime);
	std::string fakeDate = Utility::stringFormat("2000-01-01T%02d:%02d:%02d", duration.hours(), duration.minutes(), duration.seconds());
	auto timePoint = parseISO8601DateTime(fakeDate, posixTimezone);
	duration = pickDayTimeUtcDuration(timePoint);

	LOG_DBG << fname << "Parsed <" << strTime << "> with zone <" << posixTimezone << "> to <" << formatISO8601Time(timePoint) << "> with duration: " << duration;
	return duration;
}

std::string DateTime::formatDayTimeUtcDuration(boost::posix_time::time_duration &duration)
{
	// use host zone
	const auto posixTimezone = DateTime::getLocalZoneUTCOffset();
	const std::string fakeDate = Utility::stringFormat("2000-01-01T%02d:%02d:%02d", duration.hours(), duration.minutes(), duration.seconds());
	const auto timePoint = parseISO8601DateTime(fakeDate, posixTimezone);
	auto timeStr = formatISO8601Time(timePoint);
	return Utility::splitString(timeStr, "T").back();
}

std::string DateTime::reducePosixZone(const std::string &strTime)
{
	// Check if the string contains either '+' or '-'
	if (strTime.find_last_of("+-") != std::string::npos)
	{
		return Utility::stdStringTrim(strTime, ":00", /*leftTrim=*/false, /*rightTrim=*/true);
	}
	return strTime;
}

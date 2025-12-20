// src/common/DateTime.h
#pragma once

#include <chrono>
#include <string>

#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#define ISO8601FORMAT_IN_SECONDS "%Y-%m-%d %H:%M:%S%F%ZP"
#define ISO8601FORMAT_IN_MINUTES "%Y-%m-%d %H:%M%F%ZP"
#define ISO8601FORMAT_OUT "%Y-%m-%dT%H:%M:%S%F%Q"
#define RFC3339FORMAT "%Y-%m-%dT%H:%M:%S%FZ"

/// <summary>
/// Boost local time zone
/// https://stackoverflow.com/questions/8746848/boost-get-the-current-local-date-time-with-current-time-zone-from-the-machine
/// </summary>
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

/// <summary>
/// Date Time parse and format
/// </summary>
class DateTime
{
public:
	/// <summary>
	/// Return local host posix zone string
	/// </summary>
	/// <returns>posix zone: +08:00:00 with format [%H:%M:%S]</returns>
	static const std::string getLocalZoneUTCOffset();

	/// <summary>
	/// Set DateTime output posix zone info to variable: LOCAL_POSIX_ZONE
	/// default use LOCAL_POSIX_ZONE without set
	/// </summary>
	/// <param name="posixZone">posix zone: +08:00:00 with format [%H:%M:%S]</param>
	static const boost::local_time::time_zone_ptr& initOutputFormatPosixZone(const std::string &posixZone);

	/// <summary>
	/// Parse ISO8601 date time from string, if the parameter strTime have zone info, will ignore posixTimeZone
	/// </summary>
	/// <param name="strTime">"2017-09-11 21:52:13+00:00" or "2017-09-11 21:52:13"</param>
	/// <param name="posixTimeZone">+07:00, leave empty will use getLocalZoneUTCOffset()</param>
	/// <returns></returns>
	static std::chrono::system_clock::time_point parseISO8601DateTime(const std::string &strTime, const std::string &posixTimeZone = "");

	/// <summary>
	/// Format time_point with [%Y-%m-%d %H:%M:%S%F%Q] flags and LOCAL_POSIX_ZONE (set from initOutputFormatPosixZone()) offset
	/// </summary>
	/// <param name="time">std::chrono::system_clock::time_point</param>
	/// <returns>ISO8601 date time string: 2017-09-11 21:52:13+00:00</returns>
	static std::string formatISO8601Time(const std::chrono::system_clock::time_point &time);

	/// <summary>
	/// Format time_point with provided flags and LOCAL_POSIX_ZONE (set from initOutputFormatPosixZone()) offset
	/// The format is using boost::local_time::local_date_time, only seconds will be taken.
	/// </summary>
	/// <param name="time">std::chrono::system_clock::time_point</param>
	/// <param name="fmt">The format can be found here: https://www.boost.org/doc/libs/1_69_0/doc/html/date_time/date_time_io.html#date_time.format_flags</param>
	/// <returns>Formated date time string</returns>
	static std::string formatLocalTime(const std::chrono::system_clock::time_point &time, const char *fmt = ISO8601FORMAT_OUT);

	/// <summary>
	/// Format time_point (utc) to RFC3339 format
	/// </summary>
	/// <param name="time">UTC time_point</param>
	/// <returns>RFC3339 date time: 2019-01-23T10:18:32.079Z</returns>
	static std::string formatRFC3339Time(const std::chrono::system_clock::time_point &time);

	/// <summary>
	/// Get posix time zone string from date time string
	/// </summary>
	/// <param name="strTime">ISO8601 time format: 2020-10-11T19:50:00+08:00</param>
	/// <returns>posix time zone: +08:00</returns>
	static std::string getISO8601TimeZone(const std::string &strTime);

	/// <summary>
	/// Get day time duration from time_point (time_point is UTC time)
	/// </summary>
	/// <param name="time">std::chrono::system_clock::time_point</param>
	/// <returns>boost::posix_time::time_duration</returns>
	static boost::posix_time::time_duration pickDayTimeUtcDuration(const std::chrono::system_clock::time_point &time);

	/// <summary>
	/// Parse day time string to UTC day time duration
	/// </summary>
	/// <param name="strTime">string with [%H:%M:%S] format</param>
	/// <returns>boost::posix_time::time_duration</returns>
	static boost::posix_time::time_duration parseDayTimeUtcDuration(std::string strTime);

	/// <summary>
	/// Format boost::posix_time::time_duration to day time string
	/// </summary>
	/// <param name="duration">boost::posix_time::time_duration</param>
	/// <returns>string with [%H:%M:%S] format</returns>
	static std::string formatDayTimeUtcDuration(boost::posix_time::time_duration &duration);

	/// <summary>
	/// Reduce posix zone (+08:00:00 -> +08), remove last ":00"
	/// </summary>
	/// <param name="timeStr">ISO8601 format date time string</param>
	/// <returns>reduced string</returns>
	static std::string reducePosixZone(const std::string &timeStr);
};

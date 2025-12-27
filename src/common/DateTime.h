// src/common/DateTime.h
#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <string>

#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

// Use constexpr instead of macros for type safety
constexpr const char *ISO8601FORMAT_IN_SECONDS = "%Y-%m-%d %H:%M:%S%F%ZP";
constexpr const char *ISO8601FORMAT_IN_MINUTES = "%Y-%m-%d %H:%M%F%ZP";
constexpr const char *ISO8601FORMAT_OUT = "%Y-%m-%dT%H:%M:%S%F%Q";
constexpr const char *RFC3339FORMAT = "%Y-%m-%dT%H:%M:%S%FZ";

/// @brief Boost local time zone implementation for machine's current timezone
/// @note The UTC offset is calculated once at first access and cached
class MachineTimeZone : public boost::local_time::custom_time_zone
{
	using base_type = boost::local_time::custom_time_zone;
	using time_duration_type = base_type::time_duration_type;

public:
	MachineTimeZone();

	/// @brief Get the UTC offset for the local machine
	/// @note This method is not precise; real offset may be several seconds off
	/// @return Cached UTC offset as time_duration
	static boost::posix_time::time_duration getUtcOffset();

	/// @brief Get the standard timezone abbreviation (e.g., "EST", "PST")
	/// @return Timezone abbreviation string
	static std::string getStdZoneAbbrev();

private:
	static std::once_flag s_offsetInitFlag;
	static std::once_flag s_abbrevInitFlag;
	static boost::posix_time::time_duration s_utcOffset;
	static std::string s_zoneAbbrev;
};

/// @brief Thread-safe DateTime parsing and formatting utilities
/// @details Provides ISO8601 and RFC3339 date-time parsing and formatting
///          with timezone support using Boost.DateTime
class DateTime
{
public:
	using TimePoint = std::chrono::system_clock::time_point;
	using Duration = std::chrono::system_clock::duration;
	using BoostDuration = boost::posix_time::time_duration;
	using TimeZonePtr = boost::local_time::time_zone_ptr;

	// Delete copy/move - this is a utility class with only static methods
	DateTime() = delete;
	DateTime(const DateTime &) = delete;
	DateTime &operator=(const DateTime &) = delete;
	DateTime(DateTime &&) = delete;
	DateTime &operator=(DateTime &&) = delete;

	/// @brief Get the local host's UTC offset as a POSIX zone string
	/// @return Posix zone string (e.g., "+08:00:00") in format [%H:%M:%S]
	static std::string getLocalZoneUtcOffset();

	/// @brief Initialize the output format timezone
	/// @param posixZone Posix zone string (e.g., "+08:00:00"). Empty uses local zone.
	/// @return Reference to the configured timezone pointer
	/// @thread_safety Thread-safe
	static TimeZonePtr initOutputFormatPosixZone(const std::string &posixZone);

	/// @brief Parse an ISO8601 formatted date-time string
	/// @param strTime DateTime string (e.g., "2017-09-11 21:52:13+00:00" or "2017-09-11 21:52:13")
	/// @param posixTimeZone Optional timezone (e.g., "+07:00"). Empty uses local zone.
	/// @return Parsed time_point in system_clock
	/// @throws std::invalid_argument if parsing fails
	static TimePoint parseISO8601DateTime(const std::string &strTime, const std::string &posixTimeZone = "");

	/// @brief Format a time_point to ISO8601 string
	/// @param time The time_point to format
	/// @return ISO8601 formatted string (e.g., "2017-09-11T21:52:13+00:00")
	static std::string formatISO8601Time(const TimePoint &time);

	/// @brief Format a time_point with custom format string
	/// @param time The time_point to format
	/// @param fmt Boost date_time format string
	/// @return Formatted date-time string, empty on error
	/// @see https://www.boost.org/doc/libs/1_69_0/doc/html/date_time/date_time_io.html#date_time.format_flags
	static std::string formatLocalTime(const TimePoint &time, const char *fmt = ISO8601FORMAT_OUT);

	/// @brief Format a UTC time_point to RFC3339 format
	/// @param time UTC time_point
	/// @return RFC3339 formatted string (e.g., "2019-01-23T10:18:32.079Z")
	static std::string formatRFC3339Time(const TimePoint &time);

	/// @brief Extract timezone from an ISO8601 date-time string
	/// @param strTime ISO8601 formatted string (e.g., "2020-10-11T19:50:00+08:00")
	/// @return Timezone portion (e.g., "+08:00"), empty if not found
	static std::string getISO8601TimeZone(const std::string &strTime) noexcept;

	/// @brief Extract the time-of-day from a time_point as UTC duration
	/// @param time The time_point (interpreted as UTC)
	/// @return Time of day as boost::posix_time::time_duration
	static BoostDuration pickDayTimeUtcDuration(const TimePoint &time) noexcept;

	/// @brief Parse a day-time string to UTC duration
	/// @param strTime Time string in format [%H:%M:%S] or [%H:%M] or [%H]
	/// @return Parsed duration
	static BoostDuration parseDayTimeUtcDuration(const std::string &strTime);

	/// @brief Format a duration to day-time string
	/// @param duration The duration to format
	/// @return String in format [%H:%M:%S+TZ]
	static std::string formatDayTimeUtcDuration(const BoostDuration &duration);

	/// @brief Reduce posix zone precision (e.g., "+08:00:00" -> "+08")
	/// @param timeStr ISO8601 format date-time string
	/// @return Reduced string with trailing ":00" removed from timezone
	static std::string reducePosixZone(const std::string &timeStr);

private:
	/// @brief Get or create the output timezone pointer
	/// @return Current output timezone
	static TimeZonePtr getOutputPosixZone();

	/// @brief Get the local timezone pointer
	/// @return Local machine timezone
	static TimeZonePtr getLocalPosixZone();

	static std::mutex s_outputZoneMutex;
	static TimeZonePtr s_outputPosixZone;
	static std::once_flag s_localZoneInitFlag;
	static TimeZonePtr s_localPosixZone;
	static std::string s_localZoneOffset;
};

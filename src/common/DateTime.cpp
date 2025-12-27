// src/common/DateTime.cpp
#include "DateTime.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "Utility.h"

// Static member definitions for MachineTimeZone
std::once_flag MachineTimeZone::s_offsetInitFlag;
std::once_flag MachineTimeZone::s_abbrevInitFlag;
boost::posix_time::time_duration MachineTimeZone::s_utcOffset;
std::string MachineTimeZone::s_zoneAbbrev;

// Static member definitions for DateTime
std::mutex DateTime::s_outputZoneMutex;
DateTime::TimeZonePtr DateTime::s_outputPosixZone;
std::once_flag DateTime::s_localZoneInitFlag;
DateTime::TimeZonePtr DateTime::s_localPosixZone;
std::string DateTime::s_localZoneOffset;

// ============================================================================
// MachineTimeZone Implementation
// ============================================================================

MachineTimeZone::MachineTimeZone()
	: boost::local_time::custom_time_zone(
		  boost::local_time::time_zone_names("Local machine time zone", getStdZoneAbbrev(), "", ""),
		  getUtcOffset(),
		  boost::local_time::dst_adjustment_offsets(
			  time_duration_type(0, 0, 0),
			  time_duration_type(0, 0, 0),
			  time_duration_type(0, 0, 0)),
		  boost::shared_ptr<boost::local_time::dst_calc_rule>())
{
}

boost::posix_time::time_duration MachineTimeZone::getUtcOffset()
{
	std::call_once(s_offsetInitFlag, []()
				   {
        using boost::posix_time::second_clock;
        s_utcOffset = second_clock::local_time() - second_clock::universal_time(); });
	return s_utcOffset;
}

std::string MachineTimeZone::getStdZoneAbbrev()
{
	std::call_once(s_abbrevInitFlag, []()
				   {
        std::time_t now = 0;
        std::tm local_tm{};

#if defined(_WIN32) || defined(_WIN64)
        localtime_s(&local_tm, &now);
#else
        localtime_r(&now, &local_tm);
#endif
        
        char buff[64] = {0};
        std::strftime(buff, sizeof(buff), "%Z", &local_tm);
        s_zoneAbbrev = buff; });
	return s_zoneAbbrev;
}

DateTime::TimeZonePtr DateTime::getLocalPosixZone()
{
	std::call_once(s_localZoneInitFlag, []()
				   { s_localPosixZone = boost::local_time::time_zone_ptr(new MachineTimeZone()); });
	return s_localPosixZone;
}

DateTime::TimeZonePtr DateTime::getOutputPosixZone()
{
	std::lock_guard<std::mutex> lock(s_outputZoneMutex);
	if (!s_outputPosixZone)
	{
		s_outputPosixZone = getLocalPosixZone();
	}
	return s_outputPosixZone;
}

// ============================================================================
// DateTime Public Methods
// ============================================================================

std::string DateTime::getLocalZoneUtcOffset()
{
	static std::once_flag initFlag;
	static std::string cachedOffset;

	std::call_once(initFlag, []()
				   {
        const auto tz_offset = MachineTimeZone::getUtcOffset();
        std::ostringstream ss;
        if (!tz_offset.is_negative()) {
            ss << '+';
        }
        ss << tz_offset;
        cachedOffset = ss.str();
        LOG_DBG << "DateTime::getLocalZoneUtcOffset() Local timezone UTC offset: " << cachedOffset; });

	return cachedOffset;
}

DateTime::TimeZonePtr DateTime::initOutputFormatPosixZone(const std::string &posixZone)
{
	std::lock_guard<std::mutex> lock(s_outputZoneMutex);

	if (!posixZone.empty())
	{
		try
		{
			auto duration = boost::posix_time::duration_from_string(posixZone);
			auto formatStr = boost::posix_time::to_simple_string(duration);
			s_outputPosixZone = boost::local_time::time_zone_ptr(new boost::local_time::posix_time_zone(formatStr));
		}
		catch (const std::exception &e)
		{
			LOG_WAR << "DateTime::initOutputFormatPosixZone() Failed to parse zone '" << posixZone << "': " << e.what() << ". Using local zone.";
			s_outputPosixZone = getLocalPosixZone();
		}
	}
	else
	{
		s_outputPosixZone = getLocalPosixZone();
	}

	return s_outputPosixZone;
}

std::string DateTime::getISO8601TimeZone(const std::string &strTime) noexcept
{
	if (strTime.empty())
	{
		return {};
	}

	// Scan backwards to find '+' or '-' indicating timezone
	for (auto it = strTime.rbegin(); it != strTime.rend(); ++it)
	{
		const char ch = *it;
		if (ch == '+' || ch == '-')
		{
			// Calculate the position from the beginning
			const auto pos = static_cast<size_t>(std::distance(it, strTime.rend()) - 1);
			return strTime.substr(pos);
		}
		if (ch == ' ' || ch == 'T')
		{
			// Hit date-time separator before finding timezone
			return {};
		}
	}
	return {};
}

std::chrono::system_clock::time_point DateTime::parseISO8601DateTime(const std::string &strTime, const std::string &posixTimeZone)
{
	constexpr const char *fname = "DateTime::parseISO8601DateTime() ";

	if (strTime.empty())
	{
		LOG_DBG << fname << "Empty date-time string input, returning epoch time.";
		return std::chrono::system_clock::from_time_t(0);
	}

	// Work with a copy for modification
	std::string iso8601TimeStr = strTime;

	// Extract timezone from input or use provided/local default
	std::string zoneStr = getISO8601TimeZone(iso8601TimeStr);

	if (zoneStr.empty())
	{
		zoneStr = posixTimeZone.empty() ? getLocalZoneUtcOffset() : posixTimeZone;
		iso8601TimeStr += zoneStr;
	}

	// Replace 'T' separator with space for boost parsing
	iso8601TimeStr = Utility::stringReplace(iso8601TimeStr, "T", " ");

	// Determine format based on colon count in the datetime portion
	const char *format = ISO8601FORMAT_IN_MINUTES;
	if (!zoneStr.empty() && iso8601TimeStr.length() > zoneStr.length())
	{
		const auto dateTimePortion = iso8601TimeStr.substr(0, iso8601TimeStr.length() - zoneStr.length());
		if (Utility::charCount(dateTimePortion, ':') >= 2)
		{
			format = ISO8601FORMAT_IN_SECONDS;
		}
	}

	try
	{
		std::istringstream iss(iso8601TimeStr);
		iss.exceptions(std::ios_base::failbit);

		// Note: The facet pointer is managed by the locale (it will be deleted)
		auto *facet = new boost::local_time::local_time_input_facet(format);
		iss.imbue(std::locale(std::locale::classic(), facet));

		boost::local_time::local_date_time localDateTime(boost::date_time::special_values::not_a_date_time);
		iss >> localDateTime;

		LOG_DBG << fname << "Converted ISO8601 string <" << iso8601TimeStr << "> to local time <" << localDateTime << ">";

		const auto ptime = localDateTime.utc_time();
		return std::chrono::system_clock::from_time_t(boost::posix_time::to_time_t(ptime));
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "Failed to parse ISO8601 string: <" << iso8601TimeStr << ">, Error: " << e.what();
		throw std::invalid_argument("Invalid ISO8601 string: " + iso8601TimeStr);
	}
}

std::string DateTime::formatISO8601Time(const TimePoint &time)
{
	return formatLocalTime(time, ISO8601FORMAT_OUT);
}

std::string DateTime::formatRFC3339Time(const TimePoint &time)
{
	try
	{
		std::ostringstream oss;
		oss.exceptions(std::ios_base::failbit);

		auto *facet = new boost::posix_time::time_facet(RFC3339FORMAT);
		oss.imbue(std::locale(std::locale::classic(), facet));

		const auto ptime = boost::posix_time::from_time_t(std::chrono::system_clock::to_time_t(time));
		oss << ptime;

		return oss.str();
	}
	catch (const std::exception &e)
	{
		LOG_ERR << "DateTime::formatRFC3339Time() Failed: " << e.what();
		return {};
	}
}

std::string DateTime::formatLocalTime(const TimePoint &time, const char *fmt)
{
	constexpr const char *fname = "DateTime::formatLocalTime() ";

	// Check for invalid time points
	if (time == TimePoint::min() || time == TimePoint::max())
	{
		LOG_DBG << fname << "Invalid time point provided (min/max value)";
		return {};
	}

	try
	{
		const auto outputZone = getOutputPosixZone();
		const auto localZone = getLocalPosixZone();

		const auto timeT = std::chrono::system_clock::to_time_t(time);
		std::tm local_tm{};

#if defined(_WIN32) || defined(_WIN64)
		localtime_s(&local_tm, &timeT);
#else
		localtime_r(&timeT, &local_tm);
#endif

		const boost::gregorian::date target_date(
			static_cast<unsigned short>(local_tm.tm_year + 1900),
			static_cast<unsigned short>(local_tm.tm_mon + 1),
			static_cast<unsigned short>(local_tm.tm_mday));

		const boost::posix_time::time_duration target_duration(local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec);

		boost::local_time::local_date_time localDateTime(
			target_date,
			target_duration,
			localZone,
			boost::local_time::local_date_time::NOT_DATE_TIME_ON_ERROR);

		// Convert to output timezone if different
		if (outputZone && outputZone != localZone &&
			outputZone->base_utc_offset() != localZone->base_utc_offset())
		{
			localDateTime = localDateTime.local_time_in(outputZone);
		}

		std::ostringstream oss;
		oss.exceptions(std::ios_base::failbit);

		auto *facet = new boost::local_time::local_time_facet(fmt);
		oss.imbue(std::locale(std::locale::classic(), facet));
		oss << localDateTime;

		return reducePosixZone(oss.str());
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "Failed to format time <"
				<< std::chrono::system_clock::to_time_t(time)
				<< "> with format <" << fmt << ">. Error: " << e.what();
		return {};
	}
}

boost::posix_time::time_duration DateTime::pickDayTimeUtcDuration(
	const TimePoint &time) noexcept
{
	try
	{
		const auto ptime = boost::posix_time::from_time_t(std::chrono::system_clock::to_time_t(time));
		return ptime.time_of_day();
	}
	catch (...)
	{
		return boost::posix_time::time_duration(0, 0, 0);
	}
}

boost::posix_time::time_duration DateTime::parseDayTimeUtcDuration(
	const std::string &strTime)
{
	constexpr const char *fname = "DateTime::parseDayTimeUtcDuration() ";

	std::string timeStr = strTime;
	const std::string posixTimezone = getISO8601TimeZone(timeStr);

	// Remove timezone suffix if present
	if (!posixTimezone.empty())
	{
		timeStr = timeStr.substr(0, timeStr.length() - posixTimezone.length());
	}

	// Trim whitespace
	const auto start = timeStr.find_first_not_of(" \t");
	const auto end = timeStr.find_last_not_of(" \t");
	if (start != std::string::npos)
	{
		timeStr = timeStr.substr(start, end - start + 1);
	}

	// Parse the duration and construct a fake date for timezone conversion
	const auto duration = boost::posix_time::duration_from_string(timeStr);

	std::ostringstream fakeDateStream;
	fakeDateStream << "2000-01-01T"
				   << std::setfill('0') << std::setw(2) << duration.hours() << ":"
				   << std::setfill('0') << std::setw(2) << duration.minutes() << ":"
				   << std::setfill('0') << std::setw(2) << duration.seconds();

	const auto timePoint = parseISO8601DateTime(fakeDateStream.str(), posixTimezone);
	const auto result = pickDayTimeUtcDuration(timePoint);

	LOG_DBG << fname << "Parsed <" << strTime << "> with zone <" << posixTimezone
			<< "> to <" << formatISO8601Time(timePoint) << "> with duration: " << result;

	return result;
}

std::string DateTime::formatDayTimeUtcDuration(const BoostDuration &duration)
{
	const auto posixTimezone = getLocalZoneUtcOffset();

	std::ostringstream fakeDateStream;
	fakeDateStream << "2000-01-01T"
				   << std::setfill('0') << std::setw(2) << duration.hours() << ":"
				   << std::setfill('0') << std::setw(2) << duration.minutes() << ":"
				   << std::setfill('0') << std::setw(2) << duration.seconds();

	const auto timePoint = parseISO8601DateTime(fakeDateStream.str(), posixTimezone);
	const auto timeStr = formatISO8601Time(timePoint);

	// Extract time portion after 'T'
	const auto tPos = timeStr.find('T');
	if (tPos != std::string::npos && tPos + 1 < timeStr.length())
	{
		return timeStr.substr(tPos + 1);
	}
	return timeStr;
}

std::string DateTime::reducePosixZone(const std::string &strTime)
{
	// Find the last '+' or '-' to locate timezone
	const auto tzPos = strTime.find_last_of("+-");
	if (tzPos == std::string::npos)
	{
		return strTime;
	}

	// Recursively remove trailing ":00" from timezone portion
	std::string result = strTime;
	while (result.length() >= 3)
	{
		if (result.substr(result.length() - 3) == ":00")
		{
			// Don't remove if it would leave just the sign
			if (result.length() - 3 > tzPos + 1)
			{
				result = result.substr(0, result.length() - 3);
			}
			else
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
	return result;
}

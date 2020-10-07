#include <chrono>
#include <ctime>

#include <ace/OS.h>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "Utility.h"
#include "DateTime.h"

machine_time_zone::machine_time_zone()
	: boost::local_time::custom_time_zone(
		  time_zone_names("Local machine time zone", "LOC", "", ""),
		  GetUTCOffset(),
		  boost::local_time::dst_adjustment_offsets(
			  time_duration_type(0, 0, 0),
			  time_duration_type(0, 0, 0), time_duration_type(0, 0, 0)),
		  boost::shared_ptr<boost::local_time::dst_calc_rule>())
{
}

// This method is not precise, real offset may be several seconds more or less.
const boost::posix_time::time_duration &machine_time_zone::GetUTCOffset()
{
	using boost::posix_time::second_clock;
	static boost::posix_time::time_duration utc_offset(
		second_clock::local_time() - second_clock::universal_time());
	return utc_offset;
}

std::chrono::system_clock::time_point DateTime::parseISO8601DateTime(const std::string &strTime, const std::string &posixTimeZone)
{
	// if the string have build-in time zone, just use the build-in one
	if (getISO8601TimeZone(strTime).length())
	{
		return parseISO8601DateTime(strTime);
	}

	// use provided time zone
	std::string timeWithZone = Utility::stringReplace(strTime, " ", "T");
	// https://stackoverflow.com/questions/10484232/how-to-get-boostposix-timeptime-from-formatted-string
	boost::posix_time::ptime ptime;
	boost::posix_time::time_input_facet *format = new boost::posix_time::time_input_facet();
	format->set_iso_extended_format();
	std::istringstream iss(timeWithZone);
	iss.imbue(std::locale(std::locale::classic(), format));
	if ((iss >> ptime))
	{
		if (posixTimeZone.empty())
		{
			return std::move(std::chrono::system_clock::from_time_t(boost::posix_time::to_time_t(ptime)));
		}
		else
		{
			return std::move(convertToZoneTime(ptime, posixTimeZone));
		}
	}
	else
	{
		throw std::invalid_argument(Utility::stringFormat("invalid ISO8601 string: %s", timeWithZone.c_str()));
	}
}

std::chrono::system_clock::time_point DateTime::parseISO8601DateTime(const std::string &timeWithZone)
{
	std::string strTime = Utility::stringReplace(timeWithZone, " ", "T");
	// https://stackoverflow.com/questions/10484232/how-to-get-boostposix-timeptime-from-formatted-string
	boost::posix_time::ptime ptime;
	boost::posix_time::time_input_facet *format = new boost::posix_time::time_input_facet();
	format->set_iso_extended_format();
	std::istringstream iss(strTime);
	iss.imbue(std::locale(std::locale::classic(), format));
	if ((iss >> ptime))
	{
		auto posixTimezone = getISO8601TimeZone(strTime);
		if (posixTimezone.find("+") != std::string::npos || posixTimezone.find("-") != std::string::npos)
		{
			return convertToZoneTime(ptime, posixTimezone);
		}
		return std::move(std::chrono::system_clock::from_time_t(boost::posix_time::to_time_t(ptime)));
	}
	else
	{
		throw std::invalid_argument(Utility::stringFormat("invalid ISO8601 string: %s", strTime.c_str()));
	}
}

const std::string DateTime::getLocalUtcOffset()
{
	// option: https://stackoverflow.com/questions/2136970/how-to-get-the-current-time-zone/28259774#28259774
	static std::string zone;
	if (zone.empty())
	{
		boost::posix_time::time_duration tz_offset = machine_time_zone::GetUTCOffset();
		std::ostringstream ss;
		ss << (tz_offset.is_negative() ? "" : "+");
		ss << tz_offset;
		zone = ss.str();
	}
	return zone;
}

std::string DateTime::formatISO8601Time(const std::chrono::system_clock::time_point &time)
{
	static std::string offset;
	if (offset.empty())
	{
		offset = getLocalUtcOffset();
		while (Utility::endWith(offset, ":00"))
		{
			offset = offset.substr(0, offset.length() - 3);
		}
	}
	std::stringstream ss;
	ss << formatLocalTime(time, "%FT%T") << offset;
	return ss.str();
}

std::string DateTime::formatRFC3339Time(const std::chrono::system_clock::time_point &time)
{
	// https://stackoverflow.com/questions/54325137/c-rfc3339-timestamp-with-milliseconds-using-stdchrono
	const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count() % 1000;
	const auto timeT = std::chrono::system_clock::to_time_t(time);
	struct tm timeTm;
	std::stringstream ss;
	// https://stackoverflow.com/questions/37421747/is-there-a-builtin-alternative-to-stdput-time-for-gcc-5
	// use put_time can replace bellow 4 lines
	// ss << std::put_time(gmtime_r(&timeT, &timeTm), "%FT%T") << '.' << std::setfill('0') << std::setw(3) << millis << 'Z';
	char buff[70] = {0};
	ACE_OS::localtime_r(&timeT, &timeTm);
	std::strftime(buff, sizeof(buff), "%FT%T", &timeTm);
	ss << buff << '.' << std::setfill('0') << std::setw(3) << millis << 'Z';

	return ss.str();
}

std::string DateTime::formatLocalTime(const std::chrono::system_clock::time_point &time, const char *fmt)
{
	const static char fname[] = "DateTime::formatLocalTime() ";

	struct tm localtime;
	time_t timet = std::chrono::system_clock::to_time_t(time);
	ACE_OS::localtime_r(&timet, &localtime);

	char buff[64] = {0};
	if (!std::strftime(buff, sizeof(buff), fmt, &localtime))
	{
		LOG_ERR << fname << "strftime failed with error : " << std::strerror(errno);
	}
	return buff;
}

std::chrono::system_clock::time_point DateTime::convertToZoneTime(boost::posix_time::ptime &localTime, const std::string &posixTimezone)
{
	const static char fname[] = "DateTime::convertToZoneTime() ";

	try
	{
		// https://www.boost.org/doc/libs/1_69_0/doc/html/date_time/examples.html#date_time.examples.simple_time_zone

		// 1. Covert time_point to target local_date_time
		//std::chrono::system_clock::time_point localTime = std::chrono::system_clock::now();
		//std::time_t local_timtt = std::chrono::system_clock::to_time_t(localTime);
		// struct tm local_tm = {0};
		//ACE_OS::localtime_r(&local_timtt, &local_tm);
		struct tm local_tm = boost::posix_time::to_tm(localTime);
		boost::gregorian::date target_date(local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday);
		boost::posix_time::time_duration target_duration(local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec);
		// https://stackoverflow.com/questions/36411557/how-to-make-sure-that-posix-time-zone-constructor-wont-crash-when-invalid-strin
		boost::local_time::time_zone_ptr target_zone(new boost::local_time::posix_time_zone(posixTimezone));
		boost::local_time::local_date_time target_local_time(target_date, target_duration, target_zone, boost::local_time::local_date_time::NOT_DATE_TIME_ON_ERROR);
		//std::cout << origin_local_time.to_string() << std::endl;

		// 2. Convert time to current host time zone
		const static boost::local_time::time_zone_ptr local_zone(new machine_time_zone());
		auto target_time = target_local_time.local_time_in(local_zone);
		//std::cout << target_time.to_string() << std::endl;

		// 3. Convert local_date_time to time_point
		// https://stackoverflow.com/questions/4910373/interoperability-between-boostdate-time-and-stdchrono
		auto timepoint = std::chrono::system_clock::from_time_t(boost::posix_time::to_time_t(target_time.utc_time()));

		LOG_DBG << fname << "local time <" << boost::posix_time::to_iso_extended_string(localTime) << "> with zone <" << local_zone->to_posix_string()
				<< "> convert to target time <" << target_time.to_string() << "> with zone <" << posixTimezone << ">.";
		return timepoint;
	}
	catch (...)
	{
		LOG_WAR << fname << "unknown exception : " << std::strerror(errno);
		return std::move(std::chrono::system_clock::from_time_t(boost::posix_time::to_time_t(localTime)));
	}
}

std::string DateTime::getISO8601TimeZone(const std::string &strTime)
{
	for (size_t i = strTime.length() - 1; i > 0; i--)
	{
		if (strTime[i] == '-' || strTime[i] == '+')
			return std::move(strTime.substr(i));
		if (strTime[i] == ' ' || strTime[i] == 'T')
			break;
	}
	return std::string();
}

boost::posix_time::time_duration DateTime::getDayTimeDuration(const std::chrono::system_clock::time_point &time)
{
	const std::time_t timeT = std::chrono::system_clock::to_time_t(time);
	struct tm localTm = {0};
	ACE_OS::localtime_r(&timeT, &localTm);
	//boost::gregorian::date local_date(local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday);
	return std::move(boost::posix_time::time_duration(localTm.tm_hour, localTm.tm_min, localTm.tm_sec));
}

boost::posix_time::time_duration DateTime::parseDayTimeDuration(const std::string &strTime, const std::string &posixTimezone)
{
	// 1. parse time to target local_date_time
	const boost::gregorian::date fakeDate(2000, 1, 1);
	const boost::posix_time::time_duration day_duration = boost::posix_time::duration_from_string(strTime);
	boost::local_time::time_zone_ptr targetZone;
	if (posixTimezone.length())
	{
		targetZone = boost::local_time::time_zone_ptr(new boost::local_time::posix_time_zone(posixTimezone));
	}
	boost::local_time::local_date_time targetLocalTime(fakeDate, day_duration, targetZone, boost::local_time::local_date_time::NOT_DATE_TIME_ON_ERROR);

	// 2. Convert time to current host time zone
	const static boost::local_time::time_zone_ptr localZone(new machine_time_zone());
	auto target_local_time = targetLocalTime.local_time_in(localZone);

	// 3. Construct a local zero time
	const boost::posix_time::time_duration zero_day_duration = boost::posix_time::duration_from_string("00:00:00");
	boost::local_time::local_date_time zero_local_time(fakeDate, zero_day_duration, localZone, boost::local_time::local_date_time::NOT_DATE_TIME_ON_ERROR);

	// 4. return diff
	auto result = (target_local_time - zero_local_time);

	// 5. handle range over than one day
	auto one_day_seconds = (24 * 60 * 60);
	auto one_day_duration = boost::posix_time::time_duration(24, 0, 0);
	while (result.total_seconds() > one_day_seconds)
	{
		result.operator-=(one_day_duration);
	}

	while (result.total_seconds() < -one_day_seconds)
	{
		result.operator+=(one_day_duration);
	}
	return result;
}

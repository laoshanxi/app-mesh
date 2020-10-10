#include <chrono>
#include <ctime>
#include <iostream>
#include <ace/OS.h>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "Utility.h"
#include "DateTime.h"

const char *ISO8601FORMAT_IN = "%Y-%m-%d %H:%M:%S%F%ZP";
const char *ISO8601FORMAT_OUT = "%Y-%m-%d %H:%M:%S%F%Q";
const char *RFC3339FORMAT = "%Y-%m-%dT%H:%M:%S%FZ";

static boost::local_time::time_zone_ptr outputZone = boost::local_time::time_zone_ptr(new machine_time_zone());

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
		localtime_r(&cur_time, &local_tm);
		char buff[64] = {0};
		strftime(buff, sizeof(buff), "%Z", &local_tm);
		zone = buff;
	}
	return zone;
}

std::chrono::system_clock::time_point DateTime::parseISO8601DateTime(const std::string &strTime, const std::string &posixTimeZone)
{
	const static char fname[] = "DateTime::parseISO8601DateTime() ";

	std::string iso8601TimeStr = strTime;
	if (DateTime::getISO8601TimeZone(iso8601TimeStr).length())
	{
		// have build-in posix zone
	}
	else if (posixTimeZone.length())
	{
		// provide posix zone by parameter
		iso8601TimeStr.append(posixTimeZone);
	}
	else
	{
		// use host zone
		iso8601TimeStr.append(DateTime::getLocalUtcOffset());
	}

	try
	{
		iso8601TimeStr = Utility::stringReplace(iso8601TimeStr, "T", " ");
		// https://stackoverflow.com/questions/10484232/how-to-get-boostposix-timeptime-from-formatted-string
		// https://www.boost.org/doc/libs/1_69_0/doc/html/date_time/date_time_io.html#date_time.io_tutorial
		// https://stackoverflow.com/questions/28193719/boostlocal-time-does-not-read-correct-iso-extended-format/28194968#28194968
		// "2005-10-15 13:12:11-07:00"
		//local_time_facet *output_facet = new local_time_facet(format);
		boost::local_time::local_date_time localDateTime(boost::date_time::special_values::not_a_date_time);
		std::istringstream iss(iso8601TimeStr);
		iss.exceptions(std::ios_base::failbit);
		//iss.imbue(std::locale(std::locale::classic(), output_facet));
		iss.imbue(std::locale(iss.getloc(), new boost::local_time::local_time_input_facet(ISO8601FORMAT_IN)));
		iss >> localDateTime;
		LOG_DBG << fname << "<" << iso8601TimeStr << "> covert to <" << localDateTime << "> with zone <" << posixTimeZone << ">";
		auto ptime = localDateTime.utc_time();
		return std::move(std::chrono::system_clock::from_time_t(boost::posix_time::to_time_t(ptime)));
	}
	catch (std::ios_base::failure &fail)
	{
		throw std::invalid_argument(Utility::stringFormat("invalid ISO8601 string: %s, %s", iso8601TimeStr.c_str(), fail.what()));
	}
	catch (...)
	{
		throw std::invalid_argument(Utility::stringFormat("invalid ISO8601 string: %s", iso8601TimeStr.c_str()));
	}
}

const std::string DateTime::getLocalUtcOffset()
{
	const static char fname[] = "DateTime::getLocalUtcOffset() ";
	// option: https://stackoverflow.com/questions/2136970/how-to-get-the-current-time-zone/28259774#28259774
	static std::string zone;
	if (zone.empty())
	{
		boost::posix_time::time_duration tz_offset = machine_time_zone::get_utc_offset();
		std::ostringstream ss;
		ss << (tz_offset.is_negative() ? "" : "+");
		ss << tz_offset;
		zone = ss.str();
		LOG_DBG << fname << zone;
	}
	return zone;
}

void DateTime::setTimeFormatPosixZone(const std::string &posixZone)
{
	const static char fname[] = "DateTime::setTimeFormatPosixZone() ";

	if (posixZone.length())
	{
		auto duration = boost::posix_time::duration_from_string(posixZone);
		auto formatStr = boost::posix_time::to_simple_string(duration);
		outputZone = boost::local_time::time_zone_ptr(new boost::local_time::posix_time_zone(formatStr));
	}
	else
	{
		outputZone = boost::local_time::time_zone_ptr(new machine_time_zone());
		LOG_INF << fname << "empty posix zone, using default: " << outputZone->to_posix_string();
	}

	LOG_INF << fname << "output zone was set to: " << outputZone->to_posix_string();
}

std::string DateTime::formatISO8601Time(const std::chrono::system_clock::time_point &time)
{
	return std::move(formatLocalTime(time, ISO8601FORMAT_OUT));
}

std::string DateTime::formatRFC3339Time(const std::chrono::system_clock::time_point &time)
{
	// do not need posix zoon here
	// https://www.boost.org/doc/libs/1_69_0/doc/html/date_time/date_time_io.html
	std::ostringstream oss;
	oss.exceptions(std::ios_base::failbit);
	oss.imbue(std::locale(std::locale::classic(), new boost::posix_time::time_facet(RFC3339FORMAT)));
	oss << boost::posix_time::from_time_t(std::chrono::system_clock::to_time_t(time));
	return std::move(oss.str());
}

std::string DateTime::formatLocalTime(const std::chrono::system_clock::time_point &time, const char *fmt)
{
	struct tm local_tm = {0};
	auto timeT = std::chrono::system_clock::to_time_t(time);
	ACE_OS::localtime_r(&timeT, &local_tm);
	boost::gregorian::date target_date(local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday);
	boost::posix_time::time_duration target_duration(local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec);
	boost::local_time::local_date_time localDateTime(target_date, target_duration, outputZone, boost::local_time::local_date_time::NOT_DATE_TIME_ON_ERROR);

	std::ostringstream oss;
	oss.exceptions(std::ios_base::failbit);
	oss.imbue(std::locale(std::locale::classic(), new boost::local_time::local_time_facet(fmt)));
	oss << localDateTime;
	return std::move(reducePosixZone(oss.str()));
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

boost::posix_time::time_duration DateTime::getDayTimeUtcDuration(const std::chrono::system_clock::time_point &time)
{
	const auto ptime = boost::posix_time::from_time_t(std::chrono::system_clock::to_time_t(time));
	return std::move(ptime.time_of_day());
}

boost::posix_time::time_duration DateTime::parseDayTimeUtcDuration(const std::string &strTime, const std::string &posixTimezone)
{
	const static char fname[] = "DateTime::parseDayTimeUtcDuration() ";

	// re-format to accept [%H:%M] and [%H], duration parse need provide [%H:%M:%S] for parseISO8601DateTime
	auto duration = boost::posix_time::duration_from_string(strTime);
	std::string fakeDate = Utility::stringFormat("2000-01-01T%02d:%02d:%02d", duration.hours(), duration.minutes(), duration.seconds());
	auto timePoint = parseISO8601DateTime(fakeDate, posixTimezone);
	duration = getDayTimeUtcDuration(timePoint);
	LOG_DBG << fname << "parse <" << fakeDate << "> with zone <" << posixTimezone << "> to <" << formatISO8601Time(timePoint) << "> with duration: " << duration;
	return duration;
}

std::string DateTime::reducePosixZone(const std::string &strTime)
{
	const char *reduceStr = ":00";
	while (Utility::endWith(strTime, reduceStr))
	{
		return strTime.substr(0, strTime.length() - strlen(reduceStr));
	}
	return strTime;
}

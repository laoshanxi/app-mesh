#pragma once

#include <string>
#include <chrono>
#include <memory>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <cpprest/json.h>

//////////////////////////////////////////////////////////////////////////
/// Define the valid time range in one day
//////////////////////////////////////////////////////////////////////////
class DailyLimitation
{
public:
	DailyLimitation();
	virtual ~DailyLimitation();
	bool operator==(const std::shared_ptr<DailyLimitation> &obj) const;
	void dump();

	web::json::value AsJson() const;
	static std::shared_ptr<DailyLimitation> FromJson(const web::json::value &obj, const std::string &posixTimeZone) noexcept(false);

	std::string m_startTime;
	std::string m_endTime;
	boost::posix_time::time_duration m_startTimeValue;
	boost::posix_time::time_duration m_endTimeValue;
};

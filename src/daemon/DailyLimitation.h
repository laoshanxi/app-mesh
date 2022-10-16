#pragma once

#include <chrono>
#include <memory>
#include <string>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <nlohmann/json.hpp>

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

	nlohmann::json AsJson() const;
	static std::shared_ptr<DailyLimitation> FromJson(const nlohmann::json &obj) noexcept(false);

	boost::posix_time::time_duration m_startTimeValue;
	boost::posix_time::time_duration m_endTimeValue;
};

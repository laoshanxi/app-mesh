#pragma once

#include <string>
#include <chrono>
#include <memory>
#include <cpprest/json.h>

//////////////////////////////////////////////////////////////////////////
/// Define the valid time range in one day
//////////////////////////////////////////////////////////////////////////
class DailyLimitation
{
public:
	DailyLimitation();
	virtual ~DailyLimitation();
	bool operator==(const std::shared_ptr<DailyLimitation>& obj) const;
	void dump();

	web::json::value AsJson() const;
	static std::shared_ptr<DailyLimitation> FromJson(const web::json::value& obj) noexcept(false);

	std::chrono::system_clock::time_point m_startTime;
	std::chrono::system_clock::time_point m_endTime;
};

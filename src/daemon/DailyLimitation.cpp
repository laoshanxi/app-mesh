#include "DailyLimitation.h"
#include "../common/DateTime.h"
#include "../common/Utility.h"

DailyLimitation::DailyLimitation()
{
}

DailyLimitation::~DailyLimitation()
{
}

bool DailyLimitation::operator==(const std::shared_ptr<DailyLimitation> &obj) const
{
	if (obj == nullptr)
		return false;
	return (m_startTimeValue == obj->m_startTimeValue && m_endTimeValue == obj->m_endTimeValue);
}

void DailyLimitation::dump()
{
	const static char fname[] = "DailyLimitation::dump() ";

	LOG_DBG << fname << "m_startTime:" << m_startTimeValue;
	LOG_DBG << fname << "m_endTime:" << m_endTimeValue;
}

web::json::value DailyLimitation::AsJson() const
{
	web::json::value result = web::json::value::object();
	result[JSON_KEY_DAILY_LIMITATION_daily_start] = web::json::value::number(m_startTimeValue.total_seconds());
	result[JSON_KEY_DAILY_LIMITATION_daily_end] = web::json::value::number(m_endTimeValue.total_seconds());
	return result;
}

std::shared_ptr<DailyLimitation> DailyLimitation::FromJson(const web::json::value &jsonObj)
{
	std::shared_ptr<DailyLimitation> result;
	if (!jsonObj.is_null())
	{
		if (!(HAS_JSON_FIELD(jsonObj, JSON_KEY_DAILY_LIMITATION_daily_start) && HAS_JSON_FIELD(jsonObj, JSON_KEY_DAILY_LIMITATION_daily_end)))
		{
			throw std::invalid_argument("should both have daily_start and daily_end parameter");
		}
		result = std::make_shared<DailyLimitation>();
		result->m_startTimeValue = boost::posix_time::seconds(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_DAILY_LIMITATION_daily_start));
		result->m_endTimeValue = boost::posix_time::seconds(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_DAILY_LIMITATION_daily_end));
	}
	return result;
}

#include "DailyLimitation.h"
#include "../common/Utility.h"

DailyLimitation::DailyLimitation()
{
}


DailyLimitation::~DailyLimitation()
{
}

void DailyLimitation::dump()
{
	const static char fname[] = "DailyLimitation::dump() ";

	LOG_DBG << fname << "m_startTime:" << Utility::convertDayTime2Str(m_startTime);
	LOG_DBG << fname << "m_endTime:" << Utility::convertDayTime2Str(m_endTime);
}

web::json::value DailyLimitation::AsJson()
{
	web::json::value result = web::json::value::object();

	result[GET_STRING_T("daily_start")] = web::json::value::string(GET_STRING_T(Utility::convertDayTime2Str(m_startTime)));
	result[GET_STRING_T("daily_end")] = web::json::value::string(GET_STRING_T(Utility::convertDayTime2Str(m_endTime)));
	return result;
}

std::shared_ptr<DailyLimitation> DailyLimitation::FromJson(const web::json::object & jobj)
{
	std::shared_ptr<DailyLimitation> result;
	if (!jobj.empty())
	{
		if (!(HAS_JSON_FIELD(jobj, "daily_start") && HAS_JSON_FIELD(jobj, "daily_end")))
		{
			throw std::invalid_argument("should both have daily_start and daily_end parameter");
		}
		result = std::make_shared<DailyLimitation>();
		result->m_startTime = Utility::convertStr2DayTime(GET_JSON_STR_VALUE(jobj, "daily_start"));
		result->m_endTime = Utility::convertStr2DayTime(GET_JSON_STR_VALUE(jobj, "daily_end"));
	}
	return result;
}

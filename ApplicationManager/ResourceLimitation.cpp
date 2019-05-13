#include "ResourceLimitation.h"
#include "../common/Utility.h"

ResourceLimitation::ResourceLimitation()
	:m_memoryMb(0), m_memoryVirtMb(0), m_cpuShares(0)
{
}


ResourceLimitation::~ResourceLimitation()
{
}

void ResourceLimitation::dump()
{
	const static char fname[] = "ResourceLimitation::dump() ";

	LOG_DBG << fname << "m_memoryMb:" << m_memoryMb;
	LOG_DBG << fname << "m_memoryVirtMb:" << m_memoryVirtMb;
	LOG_DBG << fname << "m_cpuShares:" << m_cpuShares;
}

web::json::value ResourceLimitation::AsJson()
{
	web::json::value result = web::json::value::object();

	result[GET_STRING_T("memory_mb")] = web::json::value::number(m_memoryMb);
	result[GET_STRING_T("memory_virt_mb")] = web::json::value::number(m_memoryVirtMb);
	result[GET_STRING_T("cpu_shares")] = web::json::value::number(m_cpuShares);
	return result;
}

std::shared_ptr<ResourceLimitation> ResourceLimitation::FromJson(const web::json::object & jobj)
{
	std::shared_ptr<ResourceLimitation> result;
	if (!jobj.empty())
	{
		result = std::make_shared<ResourceLimitation>();
		result->m_memoryMb = GET_JSON_INT_VALUE(jobj, "memory_mb");
		result->m_memoryVirtMb = GET_JSON_INT_VALUE(jobj, "memory_virt_mb");
		result->m_cpuShares = GET_JSON_INT_VALUE(jobj, "cpu_shares");
	}
	return result;
}

// src/daemon/ResourceLimitation.cpp
#include "ResourceLimitation.h"
#include <stdexcept>
#include "../common/Utility.h"

ResourceLimitation::ResourceLimitation()
	: m_memoryMb(0), m_memoryVirtMb(0), m_memoryVirtSpecified(false), m_cpuShares(0), m_index(0)
{
}

ResourceLimitation::~ResourceLimitation()
{
}

bool ResourceLimitation::operator==(const std::shared_ptr<ResourceLimitation> &obj) const
{
	if (obj == nullptr)
		return false;
	return (m_cpuShares == obj->m_cpuShares &&
			m_memoryMb == obj->m_memoryMb &&
			m_memoryVirtMb == obj->m_memoryVirtMb &&
			m_memoryVirtSpecified == obj->m_memoryVirtSpecified &&
			m_name == obj->m_name);
}

void ResourceLimitation::dump()
{
	const static char fname[] = "ResourceLimitation::dump() ";

	LOG_DBG << fname << "m_memoryMb:" << m_memoryMb;
	LOG_DBG << fname << "m_memoryVirtMb:" << m_memoryVirtMb;
	LOG_DBG << fname << "m_memoryVirtSpecified:" << m_memoryVirtSpecified;
	LOG_DBG << fname << "m_cpuShares:" << m_cpuShares;
}

nlohmann::json ResourceLimitation::AsJson()
{
	nlohmann::json result = nlohmann::json::object();

	result[JSON_KEY_RESOURCE_LIMITATION_memory_mb] = (m_memoryMb);
	if (m_memoryVirtSpecified)
		result[JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb] = (m_memoryVirtMb);
	result[JSON_KEY_RESOURCE_LIMITATION_cpu_shares] = (m_cpuShares);
	return result;
}

std::shared_ptr<ResourceLimitation> ResourceLimitation::FromJson(const nlohmann::json &jsonObj, const std::string &appName)
{
	std::shared_ptr<ResourceLimitation> result;
	if (!jsonObj.is_null())
	{
		result = std::make_shared<ResourceLimitation>();
		result->m_memoryMb = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_RESOURCE_LIMITATION_memory_mb);
		result->m_memoryVirtMb = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb);
		result->m_memoryVirtSpecified = jsonObj.contains(JSON_KEY_RESOURCE_LIMITATION_memory_virt_mb);
		result->m_cpuShares = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_RESOURCE_LIMITATION_cpu_shares);
		result->m_name = appName;
		if (result->m_memoryMb < 0 || result->m_memoryVirtMb < 0 || result->m_cpuShares < 0)
			throw std::invalid_argument("resource limits cannot be negative");
		if (result->m_cpuShares > 0 && (result->m_cpuShares < 2 || result->m_cpuShares > 262144))
			throw std::invalid_argument("cpu_shares must be between 2 and 262144");
		if (result->m_memoryVirtSpecified &&
			(result->m_memoryMb <= 0 || result->m_memoryVirtMb < result->m_memoryMb))
			throw std::invalid_argument("memory_virt_mb requires positive memory_mb and must be greater than or equal to it");
		if (0 == result->m_memoryMb &&
			!result->m_memoryVirtSpecified &&
			0 == result->m_cpuShares)
		{
			return nullptr;
		}
	}
	return result;
}

// src/daemon/ResourceLimitation.h
#pragma once

#include <string>

#include <nlohmann/json.hpp>

//////////////////////////////////////////////////////////////////////////
/// Define the application resource usage limitation
//////////////////////////////////////////////////////////////////////////
class ResourceLimitation
{
public:
	ResourceLimitation();
	virtual ~ResourceLimitation();
	bool operator==(const std::shared_ptr<ResourceLimitation> &obj) const;
	void dump();

	virtual nlohmann::json AsJson();
	static std::shared_ptr<ResourceLimitation> FromJson(const nlohmann::json &jsonObj, const std::string &appName) noexcept(false);

	int m_memoryMb;
	int m_memoryVirtMb;
	int m_cpuShares;

	// runtime info
	std::string m_name;
	int m_index;
};

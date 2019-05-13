#ifndef RESOURCE_LIMITATION_H
#define RESOURCE_LIMITATION_H
#include <cpprest/json.h>

//////////////////////////////////////////////////////////////////////////
// Define the application resource usage limitation
//////////////////////////////////////////////////////////////////////////
class ResourceLimitation
{
public:
	ResourceLimitation();
	virtual ~ResourceLimitation();
	void dump();

	virtual web::json::value AsJson();
	static std::shared_ptr<ResourceLimitation> FromJson(const web::json::object& obj);

	int m_memoryMb;
	int m_memoryVirtMb;
	int m_cpuShares;
};

#endif
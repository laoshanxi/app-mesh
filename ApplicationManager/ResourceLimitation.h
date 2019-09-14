#ifndef RESOURCE_LIMITATION_H
#define RESOURCE_LIMITATION_H
#include <cpprest/json.h>
#include <string>

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
	static std::shared_ptr<ResourceLimitation> FromJson(const web::json::object& jobj, std::string appName);

	int m_memoryMb;
	int m_memoryVirtMb;
	int m_cpuShares;

	// runtime info
	std::string n_name;
	int m_index;
};

#endif
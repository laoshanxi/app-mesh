#pragma once

#include <map>
#include <memory>

struct ConsulTopology;
struct ConsulTask;

/// <summary>
/// Leader schedule logic
/// </summary>
class Scheduler
{
public:
	static std::map<std::string, std::shared_ptr<ConsulTopology>> scheduleTask(const std::map<std::string, std::shared_ptr<ConsulTask>> &taskMap, const std::map<std::string, std::shared_ptr<ConsulTopology>> &oldTopology);
};

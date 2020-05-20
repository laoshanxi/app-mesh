#pragma once
#include <memory>
#include <map>

class ConsulTopology;
class ConsulTask;
class Scheduler
{
public:
	static std::map<std::string, std::shared_ptr<ConsulTopology>> scheduleTask(const std::map<std::string, std::shared_ptr<ConsulTask>>& taskMap, const std::map<std::string, std::shared_ptr<ConsulTopology>>& oldTopology);

};


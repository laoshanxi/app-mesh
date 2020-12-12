#include <algorithm>

#include "../common/Utility.h"
#include "Scheduler.h"
#include "rest/ConsulEntity.h"

std::map<std::string, std::shared_ptr<ConsulTopology>> Scheduler::scheduleTask(const std::map<std::string, std::shared_ptr<ConsulTask>> &taskMap, const std::map<std::string, std::shared_ptr<ConsulTopology>> &oldTopology)
{
	const static char fname[] = "Scheduler::scheduleTask() ";
	LOG_DBG << fname;

	// key: hostname, value: task list
	std::map<std::string, std::shared_ptr<ConsulTopology>> newTopology;

	// ignore old schedule
	for (const auto &task : taskMap)
	{
		const auto &taskName = task.first;
		auto &taskDedicateHosts = task.second->m_matchedHosts;
		auto &taskReplication = task.second->m_replication;
		auto &taskIndexDic = task.second->m_taskIndexDic;
		if (taskReplication <= 0)
			continue;

		for (const auto &oldHost : oldTopology)
		{
			auto &oldHostName = oldHost.first;
			auto &oldTaskSet = oldHost.second->m_scheduleApps;
			if (taskDedicateHosts.count(oldHostName) && oldTaskSet.count(taskName))
			{
				auto oldTaskIndex = oldTaskSet[taskName];
				auto consulNode = taskDedicateHosts[oldHostName];
				// found app running on old host still match
				if (taskReplication <= 0)
				{
					LOG_DBG << fname << " task <" << taskName << "> over running";
					break;
				}
				taskDedicateHosts.erase(oldHostName);
				if (taskIndexDic.count(oldTaskIndex))
					taskIndexDic.erase(oldTaskIndex);
				--taskReplication;

				LOG_DBG << fname << " task <" << taskName << "> already running on host <" << oldHostName << ">";

				{
					// save to topology
					if (!newTopology.count(oldHostName))
						newTopology[oldHostName] = std::make_shared<ConsulTopology>();
					newTopology[oldHostName]->m_scheduleApps[taskName] = oldTaskIndex;
					consulNode->assignApp(task.second->m_app);
				}
			}
		}
	}

	// do schedule
	for (const auto &task : taskMap)
	{
		// get current task
		const auto &taskDedicateHosts = task.second->m_matchedHosts;
		auto &taskReplication = task.second->m_replication;
		auto &taskIndexDic = task.second->m_taskIndexDic;
		const auto &taskName = task.first;
		std::vector<std::shared_ptr<ConsulNode>> taskDedicateHostsVec;

		LOG_DBG << fname << "schedule task <" << taskName << ">";
		if (taskReplication <= 0)
			continue;

		// copy to vector
		std::transform(taskDedicateHosts.begin(), taskDedicateHosts.end(), std::back_inserter(taskDedicateHostsVec),
					   [](const std::pair<std::string, std::shared_ptr<ConsulNode>> host) { return host.second; });
		// sort hosts
		// return left < right is Ascending
		// return left > right is Descending
		std::sort(taskDedicateHostsVec.begin(), taskDedicateHostsVec.end(),
				  [](const std::shared_ptr<ConsulNode> &left, const std::shared_ptr<ConsulNode> &right) {
					  if (left->m_assignedApps.size() < right->m_assignedApps.size())
					  {
						  return true;
					  }
					  else if (left->m_assignedApps.size() == right->m_assignedApps.size())
					  {
						  return (left->getAssignedAppMem() < right->getAssignedAppMem());
					  }
					  else
					  {
						  return false;
					  }
				  });

		if (taskReplication > taskDedicateHostsVec.size())
		{
			LOG_WAR << fname << taskName << " : Replication <" << taskReplication << "> Dedicate Host < " << taskDedicateHostsVec.size() << ">";
		}
		// assign host to task
		for (std::size_t i = 0; i < taskReplication; i++)
		{
			if (i < taskDedicateHostsVec.size())
			{
				const auto &hostname = taskDedicateHostsVec[i]->m_hostName;
				const auto &consulNode = taskDedicateHostsVec[i];
				// save to topology
				{
					if (!newTopology.count(hostname))
						newTopology[hostname] = std::make_shared<ConsulTopology>();
					int selectedIndex = -1;
					if (taskIndexDic.size())
					{
						selectedIndex = *(taskIndexDic.begin());
						taskIndexDic.erase(taskIndexDic.begin());
					}
					newTopology[hostname]->m_scheduleApps[taskName] = selectedIndex;
					consulNode->assignApp(task.second->m_app);
				}
				LOG_DBG << fname << " task <" << taskName << "> assigned to host < " << hostname << ">";
				task.second->dump();
			}
			else
			{
				break;
			}
		}
	}

	return newTopology;
}

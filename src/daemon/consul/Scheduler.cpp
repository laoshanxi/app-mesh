#include <algorithm>

#include "../../common/Utility.h"
#include "ConsulEntity.h"
#include "Scheduler.h"

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
		auto &tasksSet = task.second->m_tasksSet;
		if (tasksSet.empty())
			continue;

		for (const auto &oldHost : oldTopology)
		{
			auto &oldHostName = oldHost.first;
			auto &oldTaskSet = oldHost.second->m_scheduleApps;
			// if task already running on a host
			if (taskDedicateHosts.count(oldHostName) && oldTaskSet.count(taskName))
			{
				auto consulNode = taskDedicateHosts[oldHostName];
				// found app running on old host still match
				if (tasksSet.empty())
				{
					LOG_DBG << fname << "task <" << taskName << "> over running";
					break;
				}
				taskDedicateHosts.erase(oldHostName);
				assert(tasksSet.size());
				// remove one task from schedule pool
				tasksSet.erase(tasksSet.begin());

				LOG_DBG << fname << "task <" << taskName << "> already running on host <" << oldHostName << ">";

				{
					// save to topology
					if (!newTopology.count(oldHostName))
						newTopology[oldHostName] = std::make_shared<ConsulTopology>();
					newTopology[oldHostName]->m_scheduleApps[taskName] = oldTaskSet[taskName];
					consulNode->assignApp(task.second);
				}
			}
		}
	}

	// do schedule
	for (const auto &task : taskMap)
	{
		// get current task
		const auto &taskDedicateHosts = task.second->m_matchedHosts;
		auto &tasksSet = task.second->m_tasksSet;
		const auto &taskName = task.first;
		std::vector<std::shared_ptr<ConsulNode>> taskDedicateHostsVec;

		LOG_DBG << fname << "schedule task <" << taskName << ">";
		if (tasksSet.empty())
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

		if (tasksSet.size() > taskDedicateHostsVec.size())
		{
			LOG_WAR << fname << taskName << " : Replication <" << tasksSet.size() << "> Dedicate Host <" << taskDedicateHostsVec.size() << ">";
		}
		// assign host to task
		while (tasksSet.size() && taskDedicateHostsVec.size())
		{
			auto selectedNode = *(taskDedicateHostsVec.begin());
			taskDedicateHostsVec.erase(taskDedicateHostsVec.begin());
			const auto &hostname = selectedNode->m_hostName;
			// save to topology
			if (!selectedNode->full() && selectedNode->tryAssignApp(task.second))
			{
				if (!newTopology.count(hostname))
					newTopology[hostname] = std::make_shared<ConsulTopology>();
				assert(tasksSet.size());
				// remove one task from schedule pool
				tasksSet.erase(tasksSet.begin());

				newTopology[hostname]->m_scheduleApps[taskName] = std::chrono::system_clock::now();
				selectedNode->assignApp(task.second);
				LOG_DBG << fname << "task <" << taskName << "> assigned to host < " << hostname << ">";
			}
			else
			{
				LOG_INF << fname << "task <" << taskName << "> failed assigned to host < " << hostname << "> due to full with total bytes: " << selectedNode->getAssignedAppMem();
			}
			task.second->dump();
		}
	}

	return newTopology;
}

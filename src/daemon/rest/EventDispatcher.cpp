// src/daemon/rest/EventDispatcher.cpp
#include "EventDispatcher.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../application/Application.h"

EventDispatcher::EventDispatcher()
{
}

EventDispatcher::~EventDispatcher()
{
}

EventDispatcher *EventDispatcher::instance()
{
	return EVENT_DISPATCHER::instance();
}

std::string EventDispatcher::subscribe(const std::string &appName, uint32_t eventMask,
									   const std::string &userName, DeliveryCallback cb, ConnectionKey connKey)
{
	const static char fname[] = "EventDispatcher::subscribe() ";

	auto subId = Utility::shortID();

	Subscription sub;
	sub.subId = subId;
	sub.appName = appName;
	sub.eventMask = eventMask;
	sub.userName = userName;
	sub.deliveryCb = std::move(cb);
	sub.connKey = connKey;

	{
		std::lock_guard lock(m_mutex);
		m_subscriptions.emplace(subId, std::move(sub));
		m_appIndex.emplace(appName, subId);
		m_connectionIndex.emplace(connKey, subId);

		if (eventMask & static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT))
		{
			updateStdoutWatcherLocked(appName, +1);
		}
	}

	LOG_INF << fname << "Subscription created: " << subId << " app=" << appName << " user=" << userName;
	return subId;
}

bool EventDispatcher::unsubscribe(const std::string &subId, const std::string &userName)
{
	const static char fname[] = "EventDispatcher::unsubscribe() ";

	std::lock_guard lock(m_mutex);
	auto it = m_subscriptions.find(subId);
	if (it == m_subscriptions.end())
		return false;

	if (!userName.empty() && it->second.userName != userName)
		return false;

	auto appName = it->second.appName;
	auto eventMask = it->second.eventMask;
	removeSubscriptionLocked(subId);

	if (eventMask & static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT))
	{
		updateStdoutWatcherLocked(appName, -1);
	}

	LOG_INF << fname << "Subscription removed: " << subId;
	return true;
}

void EventDispatcher::dispatch(const std::string &appName, AppEventType type, const nlohmann::json &data)
{
	const static char fname[] = "EventDispatcher::dispatch() ";

	auto seq = m_sequence.fetch_add(1);
	auto now = std::chrono::duration_cast<std::chrono::seconds>(
				   std::chrono::system_clock::now().time_since_epoch())
				   .count();

	nlohmann::json eventPayload;
	eventPayload["event_type"] = eventTypeToString(type);
	eventPayload["app_name"] = appName;
	eventPayload["timestamp"] = now;
	eventPayload["sequence"] = seq;
	eventPayload["data"] = data;

	std::vector<std::string> deadSubscriptions;
	uint32_t typeBit = static_cast<uint32_t>(type);

	// Single lock held for both delivery and cleanup — no TOCTOU.
	std::lock_guard lock(m_mutex);

	auto deliverToMatchingSubscriptions = [&](const std::string &indexKey)
	{
		auto range = m_appIndex.equal_range(indexKey);
		for (auto it = range.first; it != range.second; ++it)
		{
			auto subIt = m_subscriptions.find(it->second);
			if (subIt == m_subscriptions.end())
				continue;

			const auto &sub = subIt->second;
			if (!(sub.eventMask & typeBit))
				continue;

			nlohmann::json payload = eventPayload;
			payload["subscription_id"] = sub.subId;

			try
			{
				if (!sub.deliveryCb(payload))
				{
					deadSubscriptions.push_back(sub.subId);
				}
			}
			catch (const std::exception &e)
			{
				LOG_WAR << fname << "Delivery failed for sub=" << sub.subId << ": " << e.what();
				deadSubscriptions.push_back(sub.subId);
			}
		}
	};

	deliverToMatchingSubscriptions(appName);
	if (appName != "*")
	{
		deliverToMatchingSubscriptions("*");
	}

	for (const auto &subId : deadSubscriptions)
	{
		LOG_WAR << fname << "Removing dead subscription: " << subId;
		removeSubscriptionLocked(subId);
	}
}

void EventDispatcher::removeByConnection(const ConnectionKey &connKey)
{
	const static char fname[] = "EventDispatcher::removeByConnection() ";

	std::lock_guard lock(m_mutex);

	auto range = m_connectionIndex.equal_range(connKey);
	std::vector<std::string> subIds;
	for (auto it = range.first; it != range.second; ++it)
	{
		subIds.push_back(it->second);
	}
	m_connectionIndex.erase(range.first, range.second);

	for (const auto &subId : subIds)
	{
		auto subIt = m_subscriptions.find(subId);
		if (subIt != m_subscriptions.end())
		{
			auto appName = subIt->second.appName;
			auto eventMask = subIt->second.eventMask;

			// Remove from app index
			auto appRange = m_appIndex.equal_range(appName);
			for (auto ait = appRange.first; ait != appRange.second;)
			{
				if (ait->second == subId)
					ait = m_appIndex.erase(ait);
				else
					++ait;
			}
			m_subscriptions.erase(subIt);

			if (eventMask & static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT))
			{
				updateStdoutWatcherLocked(appName, -1);
			}
		}
	}

	if (!subIds.empty())
	{
		LOG_INF << fname << "Removed " << subIds.size() << " subscriptions for disconnected client";
	}
}

void EventDispatcher::removeByApp(const std::string &appName)
{
	const static char fname[] = "EventDispatcher::removeByApp() ";

	std::lock_guard lock(m_mutex);

	auto range = m_appIndex.equal_range(appName);
	std::vector<std::string> subIds;
	for (auto it = range.first; it != range.second; ++it)
	{
		subIds.push_back(it->second);
	}
	m_appIndex.erase(range.first, range.second);

	for (const auto &subId : subIds)
	{
		auto subIt = m_subscriptions.find(subId);
		if (subIt != m_subscriptions.end())
		{
			// Remove from connection index
			auto connRange = m_connectionIndex.equal_range(subIt->second.connKey);
			for (auto cit = connRange.first; cit != connRange.second;)
			{
				if (cit->second == subId)
					cit = m_connectionIndex.erase(cit);
				else
					++cit;
			}
			m_subscriptions.erase(subIt);
		}
	}

	// Cancel stdout watcher for this app
	auto watchIt = m_stdoutWatchers.find(appName);
	if (watchIt != m_stdoutWatchers.end())
	{
		watchIt->second->cancelTimer(watchIt->second->timerId);
		m_stdoutWatchers.erase(watchIt);
	}

	if (!subIds.empty())
	{
		LOG_INF << fname << "Removed " << subIds.size() << " subscriptions for app=" << appName;
	}
}

bool EventDispatcher::hasStdoutSubscriber(const std::string &appName) const
{
	std::lock_guard lock(m_mutex);
	auto range = m_appIndex.equal_range(appName);
	for (auto it = range.first; it != range.second; ++it)
	{
		auto subIt = m_subscriptions.find(it->second);
		if (subIt != m_subscriptions.end() && (subIt->second.eventMask & static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT)))
			return true;
	}
	return false;
}

void EventDispatcher::removeSubscriptionLocked(const std::string &subId)
{
	auto it = m_subscriptions.find(subId);
	if (it == m_subscriptions.end())
		return;

	const auto &sub = it->second;

	auto appRange = m_appIndex.equal_range(sub.appName);
	for (auto ait = appRange.first; ait != appRange.second;)
	{
		if (ait->second == subId)
			ait = m_appIndex.erase(ait);
		else
			++ait;
	}

	auto connRange = m_connectionIndex.equal_range(sub.connKey);
	for (auto cit = connRange.first; cit != connRange.second;)
	{
		if (cit->second == subId)
			cit = m_connectionIndex.erase(cit);
		else
			++cit;
	}

	m_subscriptions.erase(it);
}

void EventDispatcher::updateStdoutWatcherLocked(const std::string &appName, int delta)
{
	if (appName == "*")
		return;

	auto it = m_stdoutWatchers.find(appName);
	if (delta > 0)
	{
		if (it != m_stdoutWatchers.end())
		{
			it->second->subscriberCount += delta;
			return;
		}

		auto watcher = std::make_shared<StdoutWatcher>();
		watcher->appName = appName;
		watcher->subscriberCount = 1;
		watcher->readPosition.store(0);

		// Use weak_ptr in callback to avoid preventing StdoutWatcher destruction
		std::weak_ptr<StdoutWatcher> weakWatcher = watcher;
		auto timerId = watcher->registerTimer(
			0, 1, // 1-second interval (TimerHandler uses seconds)
			"StdoutWatcher",
			[weakWatcher]() -> bool
			{
				auto w = weakWatcher.lock();
				if (!w)
					return false;
				return w->onTimerStdoutCheck();
			});
		if (timerId == INVALID_TIMER_ID)
		{
			LOG_WAR << "EventDispatcher::updateStdoutWatcherLocked() failed to register timer for app=" << appName;
			return;
		}
		watcher->timerId.store(timerId);
		m_stdoutWatchers.emplace(appName, std::move(watcher));
	}
	else if (delta < 0 && it != m_stdoutWatchers.end())
	{
		it->second->subscriberCount += delta;
		if (it->second->subscriberCount <= 0)
		{
			it->second->cancelTimer(it->second->timerId);
			m_stdoutWatchers.erase(it);
		}
	}
}

void EventDispatcher::flushStdout(const std::string &appName, Application *app)
{
	std::lock_guard lock(m_mutex);
	auto it = m_stdoutWatchers.find(appName);
	if (it == m_stdoutWatchers.end())
		return;

	auto &watcher = it->second;
	if (!app)
		return;

	try
	{
		long pos = watcher->readPosition.load();
		auto [output, finished, exitCode] = app->getOutput(pos, 64 * 1024, "", 0, 0);
		if (!output.empty())
		{
			watcher->readPosition.store(pos);
			nlohmann::json data;
			data["output"] = output;
			data["position"] = pos;
			data["finished"] = true;
			dispatch(appName, AppEventType::STDOUT_OUTPUT, data);
		}
	}
	catch (const std::exception &e)
	{
		LOG_WAR << "EventDispatcher::flushStdout() error: " << e.what();
	}
}

bool StdoutWatcher::onTimerStdoutCheck()
{
	try
	{
		auto app = Configuration::instance()->getApp(appName, false);
		if (!app)
			return true;

		long pos = readPosition.load();
		auto [output, finished, exitCode] = app->getOutput(pos, 8192, "", 0, 0);
		if (!output.empty())
		{
			readPosition.store(pos);
			nlohmann::json data;
			data["output"] = output;
			data["position"] = pos;
			data["finished"] = finished;
			EventDispatcher::instance()->dispatch(appName, AppEventType::STDOUT_OUTPUT, data);
		}
	}
	catch (const std::exception &e)
	{
		LOG_WAR << "StdoutWatcher::onTimerStdoutCheck() error: " << e.what();
	}
	return true;
}

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
		std::lock_guard<std::recursive_mutex> lock(m_mutex);
		m_subscriptions.emplace(subId, std::move(sub));
		m_appIndex.emplace(appName, subId);
		m_connectionIndex.emplace(connKey, subId);
	}

	LOG_INF << fname << "Subscription created: " << subId << " app=" << appName << " user=" << userName;
	return subId;
}

bool EventDispatcher::unsubscribe(const std::string &subId, const std::string &userName)
{
	const static char fname[] = "EventDispatcher::unsubscribe() ";

	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	auto it = m_subscriptions.find(subId);
	if (it == m_subscriptions.end())
		return false;

	if (!userName.empty() && it->second.userName != userName)
		return false;

	removeSubscriptionLocked(subId);

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

	std::string eventTypeStr = eventTypeToString(type);
	nlohmann::json eventPayload;
	eventPayload["event_type"] = eventTypeStr;
	eventPayload["app_name"] = appName;
	eventPayload["timestamp"] = now;
	eventPayload["sequence"] = seq;
	eventPayload["data"] = data;

	// Pre-serialize ONCE; per-subscriber toJson() splices subscription_id in by
	// string concat instead of cloning the JSON DOM N times.  error_handler::replace
	// substitutes U+FFFD for invalid UTF-8 bytes (binary stdout) instead of throwing
	// a type_error.316 that would mark every STDOUT subscriber dead.
	auto basePayloadDump = std::make_shared<std::string>(eventPayload.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));

	uint32_t typeBit = static_cast<uint32_t>(type);

	struct PendingDelivery
	{
		std::string subId;
		DeliveryCallback cb;
	};
	std::vector<PendingDelivery> pending;
	{
		std::lock_guard<std::recursive_mutex> lock(m_mutex);

		auto collectMatching = [&](const std::string &indexKey)
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

				pending.push_back({sub.subId, sub.deliveryCb});
			}
		};

		collectMatching(appName);
		if (appName != "*")
			collectMatching("*");
	}

	std::vector<std::string> deadSubscriptions;
	for (const auto &p : pending)
	{
		EventEnvelope envelope{basePayloadDump, p.subId, eventTypeStr, appName};
		try
		{
			if (!p.cb(envelope))
				deadSubscriptions.push_back(p.subId);
		}
		catch (const std::exception &e)
		{
			LOG_WAR << fname << "Delivery failed for sub=" << p.subId << ": " << e.what();
			deadSubscriptions.push_back(p.subId);
		}
	}

	if (!deadSubscriptions.empty())
	{
		std::lock_guard<std::recursive_mutex> lock(m_mutex);
		for (const auto &subId : deadSubscriptions)
		{
			LOG_WAR << fname << "Removing dead subscription: " << subId;
			removeSubscriptionLocked(subId);
		}
	}
}

void EventDispatcher::removeByConnection(const ConnectionKey &connKey)
{
	const static char fname[] = "EventDispatcher::removeByConnection() ";

	std::lock_guard<std::recursive_mutex> lock(m_mutex);

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

	std::lock_guard<std::recursive_mutex> lock(m_mutex);

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

	if (!subIds.empty())
	{
		LOG_INF << fname << "Removed " << subIds.size() << " subscriptions for app=" << appName;
	}
}

bool EventDispatcher::hasStdoutSubscriber(const std::string &appName) const
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
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

void EventDispatcher::flushStdout(const std::string &appName, Application *app, long pos)
{
	const static char fname[] = "EventDispatcher::flushStdout() ";

	// Read [pos, EOF] on disk and emit one final STDOUT_OUTPUT with finished=true.
	if (!app || !hasStdoutSubscriber(appName)) return;
	try
	{
		// Capture chunk start before getOutput advances `pos` by reference, to keep
		// `position` semantics consistent with StdoutPump's start-of-chunk convention.
		const long startPos = pos;
		auto result = app->getOutput(pos, 1024 * 1024, "", 0, 0);
		auto &output = std::get<0>(result);
		if (!output.empty())
		{
			nlohmann::json data;
			data["output"] = output;
			data["position"] = startPos;
			data["finished"] = true;
			dispatch(appName, AppEventType::STDOUT_OUTPUT, data);
		}
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "Failed to flush stdout for app <" << appName << ">: " << e.what();
	}
}

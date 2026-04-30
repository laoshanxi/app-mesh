// src/daemon/rest/EventDispatcher.h
#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>
#include <nlohmann/json.hpp>

#include "../../common/TimerHandler.h"
#include "EventTypes.h"

class Application;

struct ConnectionKey
{
	enum class Transport
	{
		TCP,
		WSS
	};

	Transport transport;
	int tcpClientId;
	uint64_t wssSessionId;

	static ConnectionKey tcp(int clientId)
	{
		ConnectionKey k;
		k.transport = Transport::TCP;
		k.tcpClientId = clientId;
		k.wssSessionId = 0;
		return k;
	}
	static ConnectionKey wss(uint64_t sessionId)
	{
		ConnectionKey k;
		k.transport = Transport::WSS;
		k.tcpClientId = 0;
		k.wssSessionId = sessionId;
		return k;
	}

	bool operator<(const ConnectionKey &rhs) const
	{
		if (transport != rhs.transport)
			return transport < rhs.transport;
		if (transport == Transport::TCP)
			return tcpClientId < rhs.tcpClientId;
		return wssSessionId < rhs.wssSessionId;
	}
};

struct EventEnvelope
{
	// Pre-serialized JSON of the base payload (without subscription_id).
	// Shared across all subscribers of one dispatch; toJson() avoids the deep
	// json clone + redundant dump per subscriber by string-splicing the id in.
	std::shared_ptr<std::string> basePayloadDump;
	std::string subscriptionId;
	std::string eventType;
	std::string appName;

	std::string toJson() const
	{
		// basePayloadDump ends with '}'. Insert ,"subscription_id":"<id>" before it.
		std::string out;
		const auto &base = *basePayloadDump;
		out.reserve(base.size() + subscriptionId.size() + 24);
		if (!base.empty() && base.back() == '}')
		{
			out.append(base, 0, base.size() - 1);
			if (out.size() > 1)
				out.append(1, ',');
			out.append("\"subscription_id\":\"");
			out.append(subscriptionId);
			out.append("\"}");
		}
		else
		{
			out = base; // defensive: shouldn't happen with valid JSON
		}
		return out;
	}
};

using DeliveryCallback = std::function<bool(const EventEnvelope &envelope)>;

struct Subscription
{
	std::string subId;
	std::string appName;
	uint32_t eventMask;
	std::string userName;
	DeliveryCallback deliveryCb;
	ConnectionKey connKey;
};

// Per-app stdout watcher state (separate from EventDispatcher to avoid shared_from_this issues)
struct StdoutWatcher : public TimerHandler
{
	std::string appName;
	std::atomic<long> readPosition{0};
	std::atomic_long timerId{INVALID_TIMER_ID};
	int subscriberCount = 0;

	bool onTimerStdoutCheck();
};

class EventDispatcher
{
public:
	EventDispatcher();
	~EventDispatcher();

	std::string subscribe(const std::string &appName, uint32_t eventMask,
						  const std::string &userName, DeliveryCallback cb, ConnectionKey connKey);

	// Unsubscribe by ID; userName must match the subscription owner.
	bool unsubscribe(const std::string &subId, const std::string &userName = "");

	void dispatch(const std::string &appName, AppEventType type, const nlohmann::json &data);

	void removeByConnection(const ConnectionKey &connKey);
	void removeByApp(const std::string &appName);

	bool hasStdoutSubscriber(const std::string &appName) const;

	// Flush remaining stdout from the watcher's current position (called on process exit)
	void flushStdout(const std::string &appName, Application *app);

	static EventDispatcher *instance();

private:
	void removeSubscriptionLocked(const std::string &subId);
	void updateStdoutWatcherLocked(const std::string &appName, int delta);

	mutable std::recursive_mutex m_mutex;
	std::map<std::string, Subscription> m_subscriptions;
	std::multimap<std::string, std::string> m_appIndex;
	std::multimap<ConnectionKey, std::string> m_connectionIndex;

	std::atomic<uint64_t> m_sequence{0};

	std::map<std::string, std::shared_ptr<StdoutWatcher>> m_stdoutWatchers;
};

typedef ACE_Singleton<EventDispatcher, ACE_Null_Mutex> EVENT_DISPATCHER;

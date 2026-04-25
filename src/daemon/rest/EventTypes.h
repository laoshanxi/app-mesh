// src/daemon/rest/EventTypes.h
#pragma once

#include <cstdint>
#include <sstream>
#include <string>

enum class AppEventType : uint32_t
{
	PROCESS_START = 0x01,
	PROCESS_EXIT = 0x02,
	STDOUT_OUTPUT = 0x04,
	HEALTH_CHANGE = 0x08,
	STATUS_CHANGE = 0x10,
	APP_REMOVED = 0x20,
	ALL_EVENTS = 0x3F
};

static_assert(
	static_cast<uint32_t>(AppEventType::ALL_EVENTS) ==
		(static_cast<uint32_t>(AppEventType::PROCESS_START) |
		 static_cast<uint32_t>(AppEventType::PROCESS_EXIT) |
		 static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT) |
		 static_cast<uint32_t>(AppEventType::HEALTH_CHANGE) |
		 static_cast<uint32_t>(AppEventType::STATUS_CHANGE) |
		 static_cast<uint32_t>(AppEventType::APP_REMOVED)),
	"ALL_EVENTS must be the union of all individual event bits");

inline const char *eventTypeToString(AppEventType type)
{
	switch (type)
	{
	case AppEventType::PROCESS_START:
		return "process_start";
	case AppEventType::PROCESS_EXIT:
		return "process_exit";
	case AppEventType::STDOUT_OUTPUT:
		return "stdout";
	case AppEventType::HEALTH_CHANGE:
		return "health_change";
	case AppEventType::STATUS_CHANGE:
		return "status_change";
	case AppEventType::APP_REMOVED:
		return "app_removed";
	default:
		return "unknown";
	}
}

// Returns 0 for unknown event type strings (not ALL_EVENTS).
inline uint32_t stringToEventBit(const std::string &str)
{
	if (str == "process_start")
		return static_cast<uint32_t>(AppEventType::PROCESS_START);
	if (str == "process_exit")
		return static_cast<uint32_t>(AppEventType::PROCESS_EXIT);
	if (str == "stdout")
		return static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT);
	if (str == "health_change")
		return static_cast<uint32_t>(AppEventType::HEALTH_CHANGE);
	if (str == "status_change")
		return static_cast<uint32_t>(AppEventType::STATUS_CHANGE);
	if (str == "app_removed")
		return static_cast<uint32_t>(AppEventType::APP_REMOVED);
	if (str == "all")
		return static_cast<uint32_t>(AppEventType::ALL_EVENTS);
	return 0;
}

// Returns 0 if events is non-empty but contains no valid event types.
// Callers should treat 0 as an error (bad input).
inline uint32_t parseEventMask(const std::string &events)
{
	if (events.empty())
		return static_cast<uint32_t>(AppEventType::ALL_EVENTS);

	uint32_t mask = 0;
	std::string token;
	std::istringstream stream(events);
	while (std::getline(stream, token, ','))
	{
		mask |= stringToEventBit(token);
	}
	return mask;
}

// src/daemon/rest/SseSink.h
#pragma once

#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <string>

// Core-side SSE sink contract. The drogon transport owns the concrete stream;
// pipeline objects only see this interface, so the msgpack boundary between
// the Adaptor and the worker pool never carries drogon types.
class SseSink
{
public:
	virtual ~SseSink() = default;
	// Sends one "event: <name>\ndata: <dataJson>\n\n" frame; false means closed.
	virtual bool sendEvent(const std::string &eventName, const std::string &dataJson) = 0;
	// Sends a keep-alive comment line. Same false-when-closed contract.
	virtual bool sendComment(const std::string &text) = 0;
	// Closes the chunked transfer. Idempotent.
	virtual void close() = 0;
	virtual bool isOpen() const = 0;
};

// Live SSE sinks keyed by the X-AppMesh-Sse-Stream marker: the Adaptor
// registers a sink when the chunked response starts and the worker-side
// handler resolves it across the msgpack boundary. Entries are weak; the
// endpoint owner holds the real reference.
class SseStreamRegistry
{
public:
	static SseStreamRegistry *instance()
	{
		static SseStreamRegistry inst;
		return &inst;
	}

	std::string emplace(const std::shared_ptr<SseSink> &sink, std::string id = "")
	{
		std::lock_guard lock(m_mutex);
		if (id.empty())
			id = std::to_string(++m_nextId);
		m_streams.emplace(id, sink);
		return id;
	}

	std::shared_ptr<SseSink> take(const std::string &id)
	{
		std::lock_guard lock(m_mutex);
		if (auto it = m_streams.find(id); it != m_streams.end())
		{
			auto sink = it->second.lock();
			m_streams.erase(it); // expired entries prune here too
			return sink;
		}
		return nullptr;
	}

	void erase(const std::string &id)
	{
		std::lock_guard lock(m_mutex);
		m_streams.erase(id);
	}

	std::size_t size() const
	{
		std::lock_guard lock(m_mutex);
		return m_streams.size();
	}

private:
	mutable std::mutex m_mutex;
	std::map<std::string, std::weak_ptr<SseSink>> m_streams;
	uint64_t m_nextId{0};
};

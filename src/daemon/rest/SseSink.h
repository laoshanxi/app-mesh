// src/daemon/rest/SseSink.h
#pragma once

#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <string>

//
// Core-side SSE sink contract. The lws transport owns the concrete stream;
// pipeline objects only see this interface, so the msgpack boundary between
// the transport and the worker pool never carries lws types.
//
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
	// One-shot hook fired when the underlying connection closes (or close() is
	// called). Connection-backed sinks honor it; detached sinks ignore it.
	virtual void setOnClosed(std::function<void()> onClosed) { (void)onClosed; }
};

//
// Live SSE sinks keyed by the X-AppMesh-Sse-Stream marker: the transport
// registers a sink when the stream response starts and the worker-side
// handler resolves it across the msgpack boundary. Entries are weak; the
// endpoint owner holds the real reference.
//
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
		std::lock_guard<std::mutex> lock(m_mutex);
		if (id.empty())
			id = std::to_string(++m_nextId);
		// A duplicate id must never shadow a fresh sink (C++11 form of
		// insert_or_assign).
		const auto found = m_streams.lower_bound(id);
		if (found != m_streams.end() && found->first == id)
			found->second = sink;
		else
			m_streams.insert(found, std::make_pair(id, sink));
		return id;
	}

	std::shared_ptr<SseSink> take(const std::string &id)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		const auto it = m_streams.find(id);
		if (it != m_streams.end())
		{
			std::shared_ptr<SseSink> sink = it->second.lock();
			m_streams.erase(it); // expired entries prune here too
			return sink;
		}
		return NULL;
	}

	void erase(const std::string &id)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_streams.erase(id);
	}

	std::size_t size() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_streams.size();
	}

private:
	mutable std::mutex m_mutex;
	std::map<std::string, std::weak_ptr<SseSink> > m_streams;
	uint64_t m_nextId{0};
};

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

/// Node-local nonce dedup cache for request replay protection.
///
/// A nonce is remembered per identity namespace (bearer hash, API key owner or
/// transport principal) for at least the configured window. A nonce seen again
/// inside the window is a replay. The cache is deliberately not replicated:
/// each node rejects replays it has already served (see Security.md).
class ReplayGuard
{
public:
	enum class Verdict
	{
		First,
		Duplicate,
	};

	/// Records `nonce` under `namespaceKey`. Returns Duplicate when the same
	/// pair was already recorded and has not expired yet.
	Verdict check(const std::string &namespaceKey, const std::string &nonce, std::chrono::seconds window);

	std::size_t size() const;
	void clear();

	/// Hard cap so a flood of unique nonces cannot grow the cache unbounded;
	/// expired entries are swept first, oldest-inserted entries after that.
	static constexpr std::size_t MAX_ENTRIES = 100000;

	ReplayGuard() = default;

private:
	struct Entry
	{
		std::chrono::steady_clock::time_point recordedAt;
		std::uint64_t sequence;
	};

	void sweepLocked(std::chrono::steady_clock::time_point now);

	mutable std::mutex m_mutex;
	std::unordered_map<std::string, Entry> m_seen;
	std::uint64_t m_insertCounter = 0;

	ReplayGuard(const ReplayGuard &) = delete;
	ReplayGuard &operator=(const ReplayGuard &) = delete;
};

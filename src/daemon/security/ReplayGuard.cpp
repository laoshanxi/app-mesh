#include "ReplayGuard.h"

#include <algorithm>
#include <vector>

namespace
{
	// Entries at or past the horizon can never report Duplicate again because
	// the replay window is clamped to <= 3600s where it is read.
	constexpr auto SWEEP_HORIZON = std::chrono::seconds(3600);

	std::string compositeKey(const std::string &namespaceKey, const std::string &nonce)
	{
		return namespaceKey + "\x1f" + nonce;
	}
}

ReplayGuard::Verdict ReplayGuard::check(const std::string &namespaceKey, const std::string &nonce,
										std::chrono::seconds window)
{
	const auto now = std::chrono::steady_clock::now();
	const auto key = compositeKey(namespaceKey, nonce);

	std::lock_guard<std::mutex> lock(m_mutex);
	const auto existing = m_seen.find(key);
	if (existing != m_seen.end() && now - existing->second.recordedAt < window)
		return Verdict::Duplicate;
	if (m_seen.size() >= MAX_ENTRIES)
		sweepLocked(now);
	m_seen[key] = Entry{now, ++m_insertCounter};
	return Verdict::First;
}

std::size_t ReplayGuard::size() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_seen.size();
}

void ReplayGuard::clear()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_seen.clear();
}

void ReplayGuard::sweepLocked(std::chrono::steady_clock::time_point now)
{
	for (auto it = m_seen.begin(); it != m_seen.end();)
	{
		if (now - it->second.recordedAt >= SWEEP_HORIZON)
			it = m_seen.erase(it);
		else
			++it;
	}
	if (m_seen.size() < MAX_ENTRIES)
		return;
	// Flood path: above the cap even with only fresh entries, drop the oldest
	// tenth in one pass so eviction stays linear, not per-insert. The cutoff
	// is the drop-th smallest sequence, so exactly `drop` entries leave.
	const std::size_t drop = m_seen.size() / 10 + 1;
	std::vector<std::uint64_t> sequences;
	sequences.reserve(m_seen.size());
	for (const auto &entry : m_seen)
		sequences.push_back(entry.second.sequence);
	std::nth_element(sequences.begin(), sequences.begin() + static_cast<std::ptrdiff_t>(drop - 1), sequences.end());
	const auto cutoff = sequences[drop - 1];
	for (auto it = m_seen.begin(); it != m_seen.end();)
	{
		if (it->second.sequence <= cutoff)
			it = m_seen.erase(it);
		else
			++it;
	}
}

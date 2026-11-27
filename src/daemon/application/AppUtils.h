// src/daemon/application/AppUtils.h
#pragma once

#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

std::string normalizeAppName(const std::string &name);

/// <summary>
/// Application status
/// </summary>
enum class STATUS : int
{
	DISABLED = 0,
	ENABLED,
	NOTAVAILABLE // used for temp app from RestHandler::parseAndRegRunApp and destroyed app
};

/// <summary>
/// Application permissions for group user and other group users
/// </summary>
enum class PERMISSION : int
{
	GROUP_DENY = 1,
	GROUP_READ = 2,
	GROUP_WRITE = 3,
	OTHER_DENY = 10,
	OTHER_READ = 20,
	OTHER_WRITE = 30
};

/// <summary>
/// Crash-loop restart backoff (k8s CrashLoopBackOff style): the delay before the next
/// start grows exponentially (base, 2x, 4x ... capped) across consecutive short-lived runs,
/// and resets to zero once a run survives the "stable" threshold. Not thread-safe; the
/// caller serializes (Application invokes it under its runtime lifecycle lock).
/// </summary>
class RestartBackoff
{
public:
	// Record a finished run by how long it lasted; returns the delay before the next start.
	std::chrono::seconds onExit(std::chrono::seconds ranFor)
	{
		constexpr long BASE_SECONDS = 1;    // first backoff step
		constexpr long MAX_SECONDS = 300;   // cap (5 min), as in k8s CrashLoopBackOff
		constexpr long STABLE_SECONDS = 60; // a run lasting this long is healthy -> reset
		constexpr int MAX_SHIFT = 9;        // 1<<9 already exceeds the cap; avoids overflow

		if (ranFor.count() >= STABLE_SECONDS)
		{
			m_failures = 0; // healthy run: next restart is immediate
			return std::chrono::seconds(0);
		}

		const long secs = BASE_SECONDS << std::min(m_failures, MAX_SHIFT);
		++m_failures;
		return std::chrono::seconds(std::min(secs, MAX_SECONDS));
	}

private:
	int m_failures = 0; // consecutive short-lived runs
};

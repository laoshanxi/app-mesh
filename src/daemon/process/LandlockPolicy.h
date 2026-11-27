// src/daemon/process/LandlockPolicy.h
#pragma once

#include <cstdint>
#include <string>
#include <vector>

/// Filesystem sandbox applied to a native application process (Linux Landlock).
enum class SandboxMode
{
	Off,   ///< unrestricted
	Write, ///< writes confined to the application workspace and share/
	Strict ///< Write, and reads limited to the system read baseline
};

/// The sandbox of one launch; Off leaves the process unrestricted.
struct SandboxSpec
{
	SandboxMode mode = SandboxMode::Off;
	std::vector<std::string> readOnlyPaths; ///< extra strict-mode read rules (the application shell script)
};

/// Parses off | write | strict (case-insensitive); any other text returns fallback.
SandboxMode parseSandboxMode(const std::string &text, SandboxMode fallback);
const char *sandboxModeName(SandboxMode mode);
/// The stricter of two modes (Off < Write < Strict).
SandboxMode stricterSandboxMode(SandboxMode left, SandboxMode right);

/// Linux Landlock rulesets for sandboxed application processes.
class LandlockPolicy
{
public:
	/// Access bits the policy handles for `mode` on kernel ABI `abi`.
	static std::uint64_t handledAccess(SandboxMode mode, int abi);
	/// Highest Landlock ABI of the running kernel; 0 when Landlock is unavailable.
	static int detectAbi();
	/// Read-write on workdir and shareDir, plus the strict baseline and readOnlyPaths.
	/// Returns -1 and fills error when the policy cannot be applied.
	static int buildRuleset(SandboxMode mode, const std::string &workdir, const std::string &shareDir,
							const std::vector<std::string> &readOnlyPaths, int abi, std::string &error);
};

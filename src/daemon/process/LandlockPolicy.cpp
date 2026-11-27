// src/daemon/process/LandlockPolicy.cpp
#include "LandlockPolicy.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "../../common/Utility.h"
#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace
{
	// UAPI values of Landlock ABI v1: build hosts may predate <linux/landlock.h>.
	constexpr std::uint64_t FS_WRITE_FILE = 1ull << 1;
	constexpr std::uint64_t FS_READ_FILE = 1ull << 2;
	constexpr std::uint64_t FS_READ_DIR = 1ull << 3;
	constexpr std::uint64_t FS_REMOVE_DIR = 1ull << 4;
	constexpr std::uint64_t FS_REMOVE_FILE = 1ull << 5;
	constexpr std::uint64_t FS_MAKE_CHAR = 1ull << 6;
	constexpr std::uint64_t FS_MAKE_DIR = 1ull << 7;
	constexpr std::uint64_t FS_MAKE_REG = 1ull << 8;
	constexpr std::uint64_t FS_MAKE_SOCK = 1ull << 9;
	constexpr std::uint64_t FS_MAKE_FIFO = 1ull << 10;
	constexpr std::uint64_t FS_MAKE_SYM = 1ull << 11;
	constexpr std::uint64_t FS_MAKE_BLOCK = 1ull << 12;
	constexpr std::uint64_t FS_REFER = 1ull << 13;	   // ABI 2
	constexpr std::uint64_t FS_TRUNCATE = 1ull << 14; // ABI 3

	constexpr std::uint64_t READ_ACCESS = FS_READ_FILE | FS_READ_DIR;

#if defined(__linux__)
	// A rule on a file may only carry these; the kernel rejects the directory-only bits.
	constexpr std::uint64_t FS_EXECUTE = 1ull << 0;
	constexpr std::uint64_t FILE_ACCESS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE;

	// The read-only baseline of strict mode; absent entries are skipped.
	const char *const STRICT_BASELINE[] = {"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/ld.so.cache",
										   "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ssl/certs", "/etc/ssl/openssl.cnf",
										   "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group",
										   "/etc/localtime", "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/proc"};

	struct LandlockRulesetAttr
	{
		std::uint64_t handledAccessFs;
	} __attribute__((packed));
	// The kernel reads the first 12 bytes; the zeroed tail is the reserved field of newer headers.
	struct LandlockPathBeneathAttr
	{
		std::uint64_t allowedAccess;
		std::int32_t parentFd;
		std::uint32_t reserved;
	};
	constexpr std::uint64_t CREATE_RULESET_VERSION = 1;
	constexpr int RULE_PATH_BENEATH = 1;
	// x86_64 and aarch64 share the generic syscall numbers.
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#endif
#endif
} // namespace

SandboxMode parseSandboxMode(const std::string &text, SandboxMode fallback)
{
	auto mode = Utility::stdStringTrim(text);
	std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) { return std::tolower(c); });
	if (mode == "write")
		return SandboxMode::Write;
	if (mode == "strict")
		return SandboxMode::Strict;
	if (mode == "off")
		return SandboxMode::Off;
	return fallback;
}

const char *sandboxModeName(SandboxMode mode)
{
	switch (mode)
	{
	case SandboxMode::Write:
		return "write";
	case SandboxMode::Strict:
		return "strict";
	case SandboxMode::Off:
		break;
	}
	return "off";
}

SandboxMode stricterSandboxMode(SandboxMode left, SandboxMode right)
{
	return static_cast<SandboxMode>(std::max(static_cast<int>(left), static_cast<int>(right)));
}

std::uint64_t LandlockPolicy::handledAccess(SandboxMode mode, int abi)
{
	auto handled = FS_WRITE_FILE | FS_REMOVE_FILE | FS_REMOVE_DIR | FS_MAKE_REG | FS_MAKE_DIR | FS_MAKE_SOCK |
				   FS_MAKE_FIFO | FS_MAKE_SYM | FS_MAKE_BLOCK | FS_MAKE_CHAR;
	if (abi >= 2)
		handled |= FS_REFER;
	if (abi >= 3)
		handled |= FS_TRUNCATE;
	if (mode == SandboxMode::Strict)
		handled |= READ_ACCESS;
	return handled;
}

int LandlockPolicy::detectAbi()
{
	static const int abi = []()
	{
#if defined(__linux__)
		const long version = ::syscall(SYS_landlock_create_ruleset, nullptr, 0, CREATE_RULESET_VERSION);
		if (version > 0)
			return static_cast<int>(version);
		LOG_INF << "LandlockPolicy::detectAbi() Landlock is unavailable: " << std::strerror(errno);
#endif
		return 0;
	}();
	return abi;
}

int LandlockPolicy::buildRuleset(SandboxMode mode, const std::string &workdir, const std::string &shareDir,
								 const std::vector<std::string> &readOnlyPaths, int abi, std::string &error)
{
#if defined(__linux__)
	if (abi <= 0)
	{
		error = "the kernel does not support Landlock";
		return -1;
	}
	const auto handled = handledAccess(mode, abi);
	const LandlockRulesetAttr attr{handled};
	const int ruleset =
		static_cast<int>(::syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), static_cast<std::uint64_t>(0)));
	if (ruleset < 0)
	{
		error = Utility::stringFormat("landlock_create_ruleset failed: %s", std::strerror(errno));
		return -1;
	}

	// `required` entries must exist (the application directories); baseline entries may be absent.
	const auto grant = [&](const std::string &path, std::uint64_t access, bool required)
	{
		const int fd = ::open(path.c_str(), O_PATH | O_CLOEXEC);
		if (fd < 0)
		{
			if (!required && errno == ENOENT)
				return true;
			error = Utility::stringFormat("cannot open <%s> for a Landlock rule: %s", path.c_str(), std::strerror(errno));
			return false;
		}
		struct stat st;
		if (::fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))
			access &= FILE_ACCESS;
		const LandlockPathBeneathAttr rule{access & handled, fd, 0};
		const int result = static_cast<int>(::syscall(SYS_landlock_add_rule, ruleset, RULE_PATH_BENEATH, &rule,
													  static_cast<std::uint64_t>(0)));
		const int savedErrno = errno;
		::close(fd);
		if (result != 0)
		{
			error = Utility::stringFormat("landlock_add_rule(<%s>) failed: %s", path.c_str(), std::strerror(savedErrno));
			return false;
		}
		return true;
	};

	bool granted = grant(workdir, handled, true) && grant(shareDir, handled, true);
	// Shells and runtimes open /dev/null for writing; WRITE_FILE covers device nodes too.
	granted = granted && grant("/dev/null", FS_WRITE_FILE | READ_ACCESS, false);
	if (granted && mode == SandboxMode::Strict)
	{
		for (const auto *path : STRICT_BASELINE)
			if (!(granted = grant(path, READ_ACCESS, false)))
				break;
	}
	if (granted)
	{
		for (const auto &path : readOnlyPaths)
			if (!(granted = grant(path, READ_ACCESS, true)))
				break;
	}
	if (!granted)
	{
		::close(ruleset);
		return -1;
	}
	// The child maps its stdio onto 0-2: keep the ruleset out of that range.
	if (ruleset > STDERR_FILENO)
		return ruleset;
	const int moved = ::fcntl(ruleset, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
	const int savedErrno = errno;
	::close(ruleset);
	if (moved < 0)
		error = Utility::stringFormat("cannot move the Landlock ruleset descriptor: %s", std::strerror(savedErrno));
	return moved;
#else
	(void)mode;
	(void)workdir;
	(void)shareDir;
	(void)readOnlyPaths;
	(void)abi;
	error = "the sandbox is not available on this platform";
	return -1;
#endif
}

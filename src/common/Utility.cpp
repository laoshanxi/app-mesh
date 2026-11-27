// src/common/Utility.cpp
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdarg>
#include <cstdlib>
#include <errno.h>
#include <fstream>
#include <future>
#include <iterator>
#include <list>
#include <locale>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#if !defined(_WIN32)
#include <iconv.h>
#include <pthread.h>
#include <sys/file.h>
#endif
#include <thread>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h> // For _NSGetExecutablePath
#elif defined(_WIN32)
#include <windows.h>
#endif

#include <boost/algorithm/string.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/tokenizer.hpp>
#include <drogon/utils/Utilities.h>
#include <json/json.h>
#include "DateTime.h"
#include <boost/algorithm/hex.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "os/proc.h"
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "Utility.h"

bool Utility::isNumber(const std::string &str)
{
	std::string s = str;
	if (s.empty())
		return false;

	size_t start = (s[0] == '-' || s[0] == '+') ? 1 : 0;
	if (start == 1 && s.size() == 1)
		return false;

	return std::all_of(s.begin() + start, s.end(), ::isdigit);
}

std::string Utility::stdStringTrim(const std::string &str) { return boost::trim_copy(str, std::locale::classic()); }

std::string Utility::stdStringTrim(const std::string &str, char trimChar, bool leftTrim, bool rightTrim)
{
	const auto isTrim = [trimChar](char c) { return c == trimChar; };
	if (leftTrim && rightTrim)
		return boost::trim_copy_if(str, isTrim);
	if (leftTrim)
		return boost::trim_left_copy_if(str, isTrim);
	if (rightTrim)
		return boost::trim_right_copy_if(str, isTrim);
	return str;
}

std::string Utility::stdStringTrim(const std::string &str, const std::string &trimChars, bool leftTrim, bool rightTrim)
{
	std::string result = str;
	while (trimChars.length() && leftTrim && result.length() >= trimChars.length() &&
		   result.compare(0, trimChars.length(), trimChars) == 0)
	{
		result.erase(0, trimChars.length());
	}
	while (trimChars.length() && rightTrim && result.length() >= trimChars.length() &&
		   result.compare(result.length() - trimChars.length(), trimChars.length(), trimChars) == 0)
	{
		result.erase(result.length() - trimChars.length(), trimChars.length());
	}
	return result;
}

std::string Utility::shortID()
{
	static std::atomic<uint16_t> counter{0};
	static const uint16_t salt = std::random_device{}() & 0xFFFF; // process unique salt

	const auto now = std::chrono::system_clock::now().time_since_epoch();
	uint64_t millis = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

	// 64-bit: time(42) + salt(16) + counter(6)
	uint64_t id = (millis << 22) | (uint64_t(salt) << 6) | (counter++ & 0x3F);

	// base62 encode
	static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::string out;
	while (id > 0)
	{
		out.push_back(alphabet[id % 62]);
		id /= 62;
	}
	std::reverse(out.begin(), out.end());
	return out;
}

std::string Utility::uuid()
{
	// Generate a UUID (RFC 4122 v4) and strip the hyphens for a 32-char id
	std::string result = drogon::utils::getUuid();
	result.erase(std::remove(result.begin(), result.end(), '-'), result.end());

	return result.empty() ? shortID() : result;
}

std::vector<std::string> Utility::splitString(const std::string &source, const std::string &splitFlag)
{
	// iter_split with first_finder keeps the multi-character delimiter
	// contract (splitFlag is a token, not a character set like is_any_of).
	std::vector<std::string> tokens;
	boost::iter_split(tokens, source, boost::first_finder(splitFlag));

	std::vector<std::string> result;
	for (auto &token : tokens)
	{
		auto str = stdStringTrim(token);
		if (!str.empty())
			result.push_back(std::move(str));
	}
	return result;
}

bool Utility::startWith(const std::string &str, const std::string &prefix) { return boost::starts_with(str, prefix); }

bool Utility::endWith(const std::string &str, const std::string &postfix) { return boost::ends_with(str, postfix); }

size_t Utility::charCount(const std::string &str, char c)
{
	return static_cast<size_t>(std::count(str.begin(), str.end(), c));
}

std::string Utility::stringReplace(const std::string &strBase, const std::string &strSrc, const std::string &strDst,
								   int startPos)
{
	std::string str = strBase;
	std::string::size_type position = startPos;
	std::string::size_type srcLen = strSrc.size();
	std::string::size_type dstLen = strDst.size();

	while ((position = str.find(strSrc, position)) != std::string::npos)
	{
		str.replace(position, srcLen, strDst);
		position += dstLen;
	}
	return str;
}

std::string Utility::stringFormat(const char *fmt_str, ...)
{
	// Two-pass vsnprintf: measure with one va_list copy, render with the other.
	// Each pass needs its own va_list, va_copy keeps both valid.
	int final_n = -1;
	va_list measure;
	va_start(measure, fmt_str);
	final_n = vsnprintf(nullptr, 0, fmt_str, measure);
	va_end(measure);
	if (final_n < 0)
		return std::string();

	va_list render;
	va_start(render, fmt_str);
	std::string formatted(static_cast<size_t>(final_n) + 1, '\0');
	vsnprintf(&formatted[0], formatted.size(), fmt_str, render);
	va_end(render);
	formatted.resize(static_cast<size_t>(final_n));
	return formatted;
}

std::string Utility::strTolower(std::string s) { return boost::to_lower_copy(s, std::locale::classic()); }

std::vector<std::string> Utility::str2argv(const std::string &commandLine)
{
	// https://stackoverflow.com/questions/1511797/convert-string-to-argv-in-c
	// backup: https://stackoverflow.com/questions/1706551/parse-string-into-argv-argc
#if defined(_WIN32)
	return boost::program_options::split_winmain(commandLine);
#else
	try
	{
		return boost::program_options::split_unix(commandLine);
	}
	catch (const boost::escaped_list_error &e)
	{
		// Client input, not a server fault: map to the 400 status.
		throw std::invalid_argument(e.what());
	}
#endif
}

std::string Utility::escapeCommandLine(const std::string &input)
{
	std::string output;
	for (char c : input)
	{
		switch (c)
		{
		case '\'':
			output += "\\'";
			break;
		case '\"':
			output += "\\\"";
			break;
		case '\\':
			output += "\\\\";
			break;
		default:
			output += c;
		}
	}
	return output;
}

bool Utility::isDouble(const std::string &str)
{
	std::string s = str;
	if (s.empty())
		return false;

	// Handle optional leading sign
	size_t start = (s[0] == '-' || s[0] == '+') ? 1 : 0;
	if (start == 1 && s.size() == 1)
		return false; // Only a sign

	bool decimalPointSeen = false;
	for (size_t i = start; i < s.size(); ++i)
	{
		if (s[i] == '.')
		{
			if (decimalPointSeen)
				return false; // Multiple decimal points
			decimalPointSeen = true;
		}
		else if (!std::isdigit(s[i]))
		{
			return false;
		}
	}
	return true;
}

bool Utility::containsSpecialCharacters(const std::string &str)
{
	for (const char &c : str)
	{
		// Check for common special characters and escape sequences
		if (c == '\n' || c == '\t' || c == '\\' || c == '\"' || c == '\b' || c == '\f' || c == '\r' || c == ',')
		{
			return true;
		}

		// Check for UTF-8 non-printable characters
		if ((unsigned char)c < 32 || (unsigned char)c == 127)
		{
			return true;
		}
	}
	return false;
}

std::string Utility::strToupper(std::string s) { return boost::to_upper_copy(s, std::locale::classic()); }

// jsoncpp coerces wrong-typed scalars (int -> "5"); these keep the reads strict
std::string Utility::jsonStringField(const Json::Value &value, const std::string &key)
{
	const Json::Value &field = value[key];
	if (!field.isString())
		throw std::invalid_argument("JSON field '" + key + "' expects a string");
	return field.asString();
}

bool Utility::jsonBoolField(const Json::Value &value, const std::string &key)
{
	const Json::Value &field = value[key];
	if (!field.isBool())
		throw std::invalid_argument("JSON field '" + key + "' expects a boolean");
	return field.asBool();
}

void Utility::addExtraAppTimeReferStr(Json::Value &appJson)
{
	// append extra string format for time values
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_register_time);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_start_time);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_end_time);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_last_start);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_last_exit);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_next_start_time);
	if (HAS_JSON_FIELD(appJson, JSON_KEY_APP_daily_limitation))
	{
		Utility::appendStrDayTimeAttr(appJson[JSON_KEY_APP_daily_limitation], JSON_KEY_DAILY_LIMITATION_daily_start);
		Utility::appendStrDayTimeAttr(appJson[JSON_KEY_APP_daily_limitation], JSON_KEY_DAILY_LIMITATION_daily_end);
	}
}

Json::Value Utility::text2json(const std::string &str)
{
	Json::Value result;
	result[REST_TEXT_MESSAGE_JSON_KEY] = std::string(str);
	return result;
}

// Infer bool/null/number from plain scalar text; anything else stays string.
// yamlToJson applies this to unquoted scalars only, and jsonToYaml quotes
// strings whose text would land here as a non-string so a reload round-trip
// keeps their type.
static Json::Value plainScalarToJson(const std::string &scalar)
{
	if (scalar == "true")
		return Json::Value(true);
	if (scalar == "false")
		return Json::Value(false);
	if (scalar == "null")
		return Json::Value();
	if (Utility::isNumber(scalar))
	{
		try
		{
			if (!scalar.empty() && scalar[0] == '-')
				return Json::Value(static_cast<Json::Int64>(std::stoll(scalar)));
			return Json::Value(static_cast<Json::UInt64>(std::stoull(scalar)));
		}
		catch (const std::out_of_range &)
		{
			// Preserve exact integer text instead of demoting to double.
			return Json::Value(Utility::stdStringTrim(scalar));
		}
	}
	if (Utility::isDouble(scalar))
	{
		try
		{
			return Json::Value(std::stod(scalar));
		}
		catch (const std::exception &)
		{
			// Out-of-range magnitude (long digit runs) or a form isDouble accepts
			// but stod rejects (a lone ".") throws; keep the exact text as a
			// string instead of aborting daemon startup.
			return Json::Value(Utility::stdStringTrim(scalar));
		}
	}
	return Json::Value(Utility::stdStringTrim(scalar));
}

// Quoted scalars carry the non-specific tag "!": the author forced a string,
// so bool/null/number inference applies to plain scalars only.
static Json::Value scalarNodeToJson(const YAML::Node &node)
{
	if (node.Tag() == "!")
		return Json::Value(Utility::stdStringTrim(node.Scalar()));
	return plainScalarToJson(node.Scalar());
}

std::string Utility::jsonToYaml(const Json::Value &j, std::shared_ptr<YAML::Emitter> out)
{
	if (out == nullptr)
	{
		out = std::make_shared<YAML::Emitter>();
	}

	if (j.isObject())
	{
		*out << YAML::BeginMap;
		for (const auto &key : j.getMemberNames())
		{
			*out << YAML::Key << key;
			jsonToYaml(j[key], out);
		}
		*out << YAML::EndMap;
	}
	else if (j.isArray())
	{
		*out << YAML::BeginSeq;
		for (const auto &element : j)
		{
			jsonToYaml(element, out);
		}
		*out << YAML::EndSeq;
	}
	else if (j.isBool())
	{
		*out << j.asBool();
	}
	else if (j.type() == Json::realValue)
	{
		*out << j.asDouble();
	}
	else if (j.type() == Json::uintValue)
	{
		*out << static_cast<Json::UInt64>(j.asUInt64());
	}
	else if (j.isIntegral())
	{
		*out << static_cast<Json::Int64>(j.asInt64());
	}
	else if (j.isNull())
	{
		*out << YAML::Null;
	}
	else
	{
		// String
		std::string str = j.asString();
		if (containsSpecialCharacters(str))
		{
			*out << YAML::Literal << str;
		}
		else if (!plainScalarToJson(str).isString())
		{
			// Quote text that would otherwise re-parse as bool/null/number on
			// the next yamlToJson load, e.g. app env "true" (Application::save).
			*out << YAML::DoubleQuoted << str;
		}
		else
		{
			*out << str;
		}
	}

	return out->c_str(); // Return the YAML string
}

Json::Value Utility::yamlToJson(const YAML::Node &node)
{
	Json::Value result;

	if (node.IsNull())
	{
		result = Json::Value();
	}
	else if (node.IsMap())
	{
		result = Json::Value(Json::objectValue);
		for (const auto &pair : node)
		{
			const std::string key = pair.first.as<std::string>();
			if (pair.second.IsNull())
			{
				result[key] = Json::Value();
			}
			else if (pair.second.IsScalar())
			{
				result[key] = scalarNodeToJson(pair.second);
			}
			else
			{
				result[key] = yamlToJson(pair.second);
			}
		}
	}
	else if (node.IsSequence())
	{
		result = Json::Value(Json::arrayValue);
		for (const auto &element : node)
		{
			result.append(yamlToJson(element));
		}
	}
	else if (node.IsScalar())
	{
		result = scalarNodeToJson(node);
	}
	else
	{
		LOG_ERR << "Failed to parse YAML node: " << node;
	}

	return result;
}

void Utility::appendStrTimeAttr(Json::Value &jsonObj, const std::string &key)
{
	if (HAS_JSON_FIELD(jsonObj, key))
	{
		jsonObj[key + JSON_KEY_TIME_POSTFIX_STR] = std::string(
			DateTime::formatLocalTime(std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, key))));
	}
}

void Utility::appendStrDayTimeAttr(Json::Value &jsonObj, const std::string &key)
{
	if (HAS_JSON_FIELD(jsonObj, key))
	{
		jsonObj[key + JSON_KEY_TIME_POSTFIX_STR] = std::string(
			splitString(
				DateTime::formatISO8601Time(std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, key))), "T")
				.back());
	}
}

// The credential after a case-insensitive "Bearer" scheme; empty when absent.
std::string Utility::bearerCredential(const std::string &authorization)
{
	const auto value = stdStringTrim(authorization);
	const auto separator = value.find(' ');
	if (separator == std::string::npos)
		return {};
	auto scheme = value.substr(0, separator);
	std::transform(scheme.begin(), scheme.end(), scheme.begin(),
				   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	if (scheme != "bearer")
		return {};
	return stdStringTrim(value.substr(separator + 1));
}

bool Utility::secureCompare(const std::string &a, const std::string &b)
{
	// Length comparison must happen first to avoid buffer overruns
	if (a.size() != b.size())
		return false;

	// Use OpenSSL's constant-time comparison (already linked)
	return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string Utility::toHex(const unsigned char *data, size_t size)
{
	// hex_lower matches the lowercase digests callers persist and compare
	std::string result;
	result.reserve(size * 2);
	boost::algorithm::hex_lower(data, data + size, std::back_inserter(result));
	return result;
}

std::string Utility::sha256Hex(const std::string &text)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int length = 0;
	if (EVP_Digest(text.data(), text.size(), digest, &length, EVP_sha256(), nullptr) != 1)
		throw std::runtime_error("Failed to compute a SHA-256 digest");
	return toHex(digest, length);
}

std::string Utility::maskSecret(const std::string &secret, size_t visibleChars, const std::string &mask)
{
	const size_t length = secret.length();

	if (length <= static_cast<size_t>(visibleChars * 2))
		return std::string(3, '*');

	std::string result;
	result.reserve(visibleChars * 2 + mask.length());

	result.append(secret, 0, visibleChars);
	result.append(mask);
	result.append(secret, length - visibleChars, visibleChars);

	return result;
}

#define _XPLATSTR(x) x
namespace web
{
	namespace http
	{
#define _METHODS
#define DAT(a, b) const method methods::a = b;
#include "http_constants.dat"
#undef _METHODS
#undef DAT

#define _HEADER_NAMES
#define DAT(a, b) const std::string header_names::a = _XPLATSTR(b);
#include "http_constants.dat"
#undef _HEADER_NAMES
#undef DAT

#define _MIME_TYPES
#define DAT(a, b) const std::string mime_types::a = _XPLATSTR(b);
#include "http_constants.dat"
#undef _MIME_TYPES
#undef DAT

// This is necessary for Linux because of a bug in GCC 4.7
#if !defined(_WIN32)
#define _PHRASES
#define DAT(a, b, c) const status_code status_codes::a;
#include "http_constants.dat"
#undef _PHRASES
#undef DAT
#endif
	}
}

NotFoundException::NotFoundException(const char *what) noexcept : std::logic_error(what) {}

NotFoundException::NotFoundException(const std::string &what) noexcept : std::logic_error(what) {}

bool Utility::runningInContainer()
{
	static const bool isInContainer = []()
	{
		// Support standard and legacy container markers.
		if (std::ifstream("/.dockerenv").good() || std::ifstream("/run/.dockerenv").good() ||
			std::ifstream("/run/.containerenv").good())
		{
			return true;
		}
		const char *containerRuntime = std::getenv("container");
		if (containerRuntime != nullptr && containerRuntime[0] != '\0')
		{
			return true;
		}

#if defined(__linux__)
		// Detect runtimes without marker files.
		const auto cgroup = Utility::readFileCpp("/proc/self/cgroup");
		static const std::vector<std::string> containerCgroupMarkers = {"docker", "kubepods", "containerd",
																		"libpod", "podman",   "lxc"};
		return std::any_of(containerCgroupMarkers.begin(), containerCgroupMarkers.end(),
						   [&cgroup](const std::string &marker) { return cgroup.find(marker) != std::string::npos; });
#else
		return false;
#endif
	}();

	return isInContainer;
}

bool Utility::ensureSystemRoot()
{
	// https://github.com/pypa/hatch/issues/1598
	// https://stackoverflow.com/questions/1554878/why-does-windows-not-allow-winsock-to-be-started-while-impersonating-another-use
	// https://github.com/golang/go/issues/61452
	// https://github.com/golang/go/issues/26457
	// https://go-review.googlesource.com/c/go/+/124858
#if defined(_WIN32)
	std::string systemRoot = Utility::getenv("SYSTEMROOT");
	if (systemRoot.empty())
	{
		char sysDir[MAX_PATH] = {0};
		UINT sysLen = GetSystemWindowsDirectoryA(sysDir, MAX_PATH);
		if (sysLen == 0 || sysLen >= MAX_PATH)
		{
			strcpy_s(sysDir, MAX_PATH, "C:\\Windows"); // fallback
			std::cerr << "[Warning] GetSystemWindowsDirectoryA failed; using fallback: " << sysDir << std::endl;
		}
		systemRoot = sysDir;

		if (_putenv_s("SYSTEMROOT", systemRoot.c_str()) != 0)
		{
			std::cerr << "[Error] Failed to set SYSTEMROOT to: " << systemRoot << " (Error " << last_error_msg() << ")"
					  << std::endl;
			return false;
		}
		std::cout << "[Info] SYSTEMROOT set to: " << systemRoot << std::endl;
	}
	else
	{
		std::cout << "[Info] SYSTEMROOT already set to: " << systemRoot << std::endl;
	}

#endif
	return true;
}

unsigned long long Utility::getThreadId()
{
	std::ostringstream oss;
	oss << std::this_thread::get_id();
	return std::stoull(oss.str());
}

void Utility::setThreadName(const std::string &name)
{
#if defined(_WIN32)
	std::wstring wide(name.begin(), name.end());
	SetThreadDescription(GetCurrentThread(), wide.c_str());
#else
	// pthread names are capped at 15 characters plus the terminator.
	const auto capped = name.substr(0, 15);
#if defined(__APPLE__)
	pthread_setname_np(capped.c_str());
#else
	pthread_setname_np(pthread_self(), capped.c_str());
#endif
#endif
}

bool &Utility::pidFileLockOwned()
{
	static bool owned = false;
	return owned;
}

bool Utility::ownsPidFileLock() { return pidFileLockOwned(); }

bool Utility::createPidFile()
{
	const static char fname[] = "Utility::createPidFile() ";
	// https://stackoverflow.com/questions/5339200/how-to-create-a-single-instance-application-in-c-or-c
	// https://stackoverflow.com/questions/65738650/c-create-a-pid-file-using-system-call
	const auto pidFile = (fs::path(Utility::getHomeDir()) / PID_FILE).string();

#if !defined(_WIN32)
	// No O_TRUNC: the running daemon's PID must survive a failed lock attempt.
	int fd = open(pidFile.c_str(), O_CREAT | O_RDWR, 0666);
	if (fd < 0)
	{
		LOG_ERR << fname << "Failed to create PID file [" << pidFile << "]: " << last_error_msg();
		return false;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) == 0)
	{
		LOG_INF << fname << "New process running. PID file locked: " << pidFile;
		std::string pid = std::to_string(getpid());
		if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) != 0 || write(fd, pid.c_str(), pid.length()) <= 0)
		{
			LOG_ERR << fname << "Failed to write PID to file [" << pidFile << "]: " << last_error_msg();
			close(fd);
			return false;
		}
		pidFileLockOwned() = true;
		return true;
	}
	else
	{
		if (errno == EWOULDBLOCK)
		{
			LOG_ERR << fname << "Process already running. PID file locked: " << pidFile;
		}
		else
		{
			LOG_ERR << fname << "Failed to lock PID file [" << pidFile << "]: " << last_error_msg();
		}
		close(fd);
		return false;
	}

#else
	// Windows implementation using file locking
	// Read and write stay unshared, which is the single-instance lock itself;
	// sharing only the delete lets the shutdown path remove the file while this
	// handle is still open.
	HANDLE hFile = CreateFileA(pidFile.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE, NULL, CREATE_ALWAYS,
							   FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SHARING_VIOLATION)
		{
			LOG_ERR << fname << "Process already running. PID file locked: " << pidFile;
		}
		else
		{
			LOG_ERR << fname << "Failed to create PID file <" << pidFile << "> with error " << error;
		}
		return false;
	}

	std::string pid = std::to_string(os::getpid());
	DWORD bytesWritten;
	if (!WriteFile(hFile, pid.c_str(), static_cast<DWORD>(pid.length()), &bytesWritten, NULL))
	{
		LOG_ERR << fname << "Failed to write PID to file <" << pidFile << "> with error " << GetLastError();
		CloseHandle(hFile);
		return false;
	}

	LOG_INF << fname << "New process running. PID file locked: " << pidFile;
	// Keep handle open to maintain lock
	pidFileLockOwned() = true;
	return true;
#endif
}

void Utility::initDateTimeZone(const std::string &posixTimezone, bool writeLog)
{
	const auto &zone = DateTime::initOutputFormatPosixZone(posixTimezone);
	if (writeLog)
	{
		LOG_INF << "Set timezone to: " << zone->to_posix_string();
	}
}

std::string Utility::getenv(const std::string &envName, const std::string &defaultValue)
{
	const char *val = std::getenv(envName.data());
	if (val == nullptr || val[0] == '\0')
		return defaultValue;

	return val;
}

std::string Utility::getenvTrimmed(const std::string &envName, const std::string &defaultValue)
{
	return stdStringTrim(getenv(envName, defaultValue));
}

std::map<std::string, std::string> Utility::getenvs()
{
	std::map<std::string, std::string> env;

#if defined(_WIN32)
	LPCH envStrings = GetEnvironmentStringsA();
	if (!envStrings)
		return env;

	for (LPCH var = envStrings; *var; var += std::strlen(var) + 1)
	{
		std::string entry(var);
		auto pos = entry.find('=');
		if (pos != std::string::npos)
		{
			env.emplace(entry.substr(0, pos), entry.substr(pos + 1));
		}
	}
	FreeEnvironmentStringsA(envStrings);

#else
	extern char **environ;
	for (char **current = environ; *current; ++current)
	{
		std::string entry(*current);
		auto pos = entry.find('=');
		if (pos != std::string::npos)
		{
			env.emplace(entry.substr(0, pos), entry.substr(pos + 1));
		}
	}
#endif

	return env;
}

static thread_local std::string g_errorMessage;

const char *last_error_msg()
{
	// Same policy as the former ACE wrapper: CRT errno first, GetLastError() on
	// Windows when errno is unset (Winsock failures land there).
	const int err_code =
#if defined(_WIN32)
		errno != 0 ? errno : static_cast<int>(::GetLastError());
#else
		errno;
#endif

#if defined(_WIN32)
	if (err_code == 0)
	{
		g_errorMessage.assign("Unknown error");
		return g_errorMessage.c_str();
	}
	char buf[256] = {0};
	if (errno != 0)
	{
		strerror_s(buf, sizeof(buf), err_code);
		g_errorMessage.assign(buf);
	}
	else
	{
		const DWORD len = ::FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, nullptr,
			static_cast<DWORD>(err_code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf), nullptr);
		if (len > 0 && buf[0] != '\0')
			g_errorMessage.assign(buf, len);
		else
			g_errorMessage.assign("Unknown error ").append(std::to_string(err_code));
	}
#else
	char buf[256] = {0};
#if defined(__GLIBC__)
	// glibc returns char*; XSI (macOS, musl) fills buf and returns an int.
	const char *error_message = ::strerror_r(err_code, buf, sizeof(buf));
#else
	const char *error_message = ::strerror_r(err_code, buf, sizeof(buf)) == 0 ? buf : nullptr;
#endif
	g_errorMessage.assign(error_message && *error_message ? error_message : "Unknown error");
#endif
	return g_errorMessage.c_str();
}


namespace
{
	// Blocking resolver core; getaddrinfo decides the wait.
	std::string resolveHostAddressBlocking(const std::string &host, std::string &errorText);
}

std::string Utility::resolveHostAddress(const std::string &host, std::string &errorText, long timeoutSeconds)
{
	// Literals skip the resolver and the bounded path below.
	struct in_addr v4;
	struct in6_addr v6;
	if (host.find(':') != std::string::npos)
	{
		if (inet_pton(AF_INET6, host.c_str(), &v6) == 1)
			return host;
	}
	else if (inet_pton(AF_INET, host.c_str(), &v4) == 1)
	{
		return host;
	}

	if (timeoutSeconds <= 0)
		return resolveHostAddressBlocking(host, errorText);

	// getaddrinfo has no timeout; resolve on a helper thread bounded by the
	// caller's budget. On timeout the thread is abandoned and exits on its own.
	auto result = std::make_shared<std::promise<std::pair<std::string, std::string>>>();
	auto future = result->get_future();
	std::thread(
		[host, result = std::move(result)]()
		{
			std::string threadError;
			std::string ip = resolveHostAddressBlocking(host, threadError);
			result->set_value({std::move(ip), std::move(threadError)});
		})
		.detach();
	if (future.wait_for(std::chrono::seconds(timeoutSeconds)) != std::future_status::ready)
	{
		errorText = "cannot resolve " + host + ": timed out after " + std::to_string(timeoutSeconds) + "s";
		return std::string();
	}
	auto resolved = future.get();
	errorText = std::move(resolved.second);
	return resolved.first;
}

namespace
{
	// Blocking resolver core; getaddrinfo decides the wait.
	std::string resolveHostAddressBlocking(const std::string &host, std::string &errorText)
	{
		// An address literal passes through; a host name resolves via getaddrinfo.
		struct in_addr v4;
		struct in6_addr v6;
		if (host.find(':') != std::string::npos)
		{
			if (inet_pton(AF_INET6, host.c_str(), &v6) == 1)
				return host;
		}
		else if (inet_pton(AF_INET, host.c_str(), &v4) == 1)
		{
			return host;
		}

		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC; // resolve both families
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_ADDRCONFIG; // skip AAAA on v4-only hosts and vice versa
		struct addrinfo *result = nullptr;
		const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &result);
		if (rc != 0 || result == nullptr)
		{
			errorText = "cannot resolve " + host + ": " + gai_strerror(rc);
			return std::string();
		}

		// Prefer IPv4: a dual-stack target keeps its legacy reachability, a v6-only
		// target still resolves through its AAAA record.
		const addrinfo *chosen = result;
		for (const addrinfo *ai = result; ai != nullptr; ai = ai->ai_next)
		{
			if (ai->ai_family == AF_INET)
			{
				chosen = ai;
				break;
			}
		}

		char numeric[INET6_ADDRSTRLEN] = {0};
		if (::getnameinfo(chosen->ai_addr, chosen->ai_addrlen, numeric, sizeof(numeric), nullptr, 0, NI_NUMERICHOST) != 0)
		{
			::freeaddrinfo(result);
			errorText = "cannot convert resolved address of " + host;
			return std::string();
		}
		::freeaddrinfo(result);
		// InetAddress parses with bare inet_pton, so a scope-qualified address
		// would silently fall back to the wildcard address.
		if (strchr(numeric, '%') != nullptr)
		{
			errorText = "scope-qualified address <" + std::string(numeric) + "> of " + host + " is not supported";
			return std::string();
		}
		return numeric;
	}
} // namespace

void Utility::initLogging(const std::string &name)
{
	std::vector<spdlog::sink_ptr> sinks;

	// Console sink
	auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	sinks.push_back(consoleSink);

	// Rotating file sink
	if (!name.empty())
	{
		auto logPath = (fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / name).string() + ".log";
		constexpr size_t maxFileSize = 50 * 1024 * 1024; // 50MB
		constexpr size_t maxFiles = 5;

		auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logPath, maxFileSize, maxFiles, false);
		sinks.push_back(fileSink);
	}

	// Create logger
	auto logger = std::make_shared<spdlog::logger>("appmesh", sinks.begin(), sinks.end());
	spdlog::set_default_logger(logger);
	// Flush everything at once: every enabled level reaches the file as it is
	// emitted, so diagnosis during an incident never reads a stale tail.
	logger->flush_on(spdlog::level::debug);

	// Pattern
	// %l = full level name (info/warning/error/debug). %L would print single chars E/D.
	spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%t] %l: %v");

	// Log level from env
	auto levelEnv = Utility::getenv("LOG_LEVEL");
	if (!levelEnv.empty())
		setLogLevel(levelEnv);

	LOG_DBG << "Logging process ID: " << os::getpid();
}

bool Utility::setLogLevel(const std::string &level)
{
	static std::map<std::string, spdlog::level::level_enum> levelMap = {
		{"NOTSET", spdlog::level::off},     {"DEBUG", spdlog::level::debug},    {"INFO", spdlog::level::info},
		{"WARN", spdlog::level::warn},      {"ERROR", spdlog::level::err},      {"CRIT", spdlog::level::critical},
		{"ALERT", spdlog::level::critical}, {"FATAL", spdlog::level::critical}, {"EMERG", spdlog::level::critical}};

	if (auto it = levelMap.find(level); it != levelMap.end())
	{
		spdlog::set_level(it->second);
		LOG_INF << "Set log level to <" << level << ">";
		return true;
	}
	else
	{
		LOG_ERR << "Unknown log level <" << level << ">";
		return false;
	}
}

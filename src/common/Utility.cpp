#include <atomic>
#include <errno.h>
#include <fstream>
#include <list>
#include <locale>
#include <random>
#include <string>
#include <vector>
#if !defined(_WIN32)
#include <sys/file.h>
#endif
#include <thread>
#if defined(__APPLE__)
#include <crt_externs.h> // For getprogname
#include <mach-o/dyld.h> // For _NSGetExecutablePath
#elif defined(_WIN32)
#include <codecvt>
#include <windows.h>
#endif

#include <ace/OS.h>
#include <ace/UUID.h>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options/parsers.hpp>
#include <hashidsxx/hashids.cpp>
#include <hashidsxx/hashids.h>
#include <nlohmann/json.hpp>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "DateTime.h"
#include "Password.h"
#include "Utility.h"
#include "json.h"
#include "os/chown.h"
#include "os/linux.h"

const char *GET_STATUS_STR(unsigned int status)
{
	static const char *STATUS_STR[] = {"disabled", "enabled", "N/A"};
	assert(status < ARRAY_LEN(STATUS_STR));
	return STATUS_STR[status];
};

Utility::Utility()
{
}

Utility::~Utility()
{
}

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

std::string Utility::stdStringTrim(const std::string &str)
{
	auto front = std::find_if_not(str.begin(), str.end(), [](int c)
								  { return std::isspace(c); });
	auto back = std::find_if_not(str.rbegin(), str.rend(), [](int c)
								 { return std::isspace(c); })
					.base();
	return (back <= front ? std::string() : std::string(front, back));
}

std::string Utility::stdStringTrim(const std::string &str, char trimChar, bool leftTrim, bool rightTrim)
{
	char *line = const_cast<char *>(str.c_str());
	// trim the line on the left and on the right
	std::size_t len = str.length();
	std::size_t start = 0;
	while (leftTrim && trimChar == (*line))
	{
		++line;
		--len;
		++start;
	}
	while (rightTrim && len > 0 && trimChar == (line[len - 1]))
	{
		--len;
	}
	return len >= start ? str.substr(start, len) : str.substr(start);
}

std::string Utility::stdStringTrim(const std::string &str, const std::string &trimChars, bool leftTrim, bool rightTrim)
{
	std::string result = str;
	while (trimChars.length() && leftTrim && result.length() >= trimChars.length() && 0 == strncmp(result.c_str(), trimChars.c_str(), trimChars.length()))
	{
		result = result.c_str() + trimChars.length();
	}

	while (trimChars.length() && rightTrim && result.length() >= trimChars.length() && 0 == strncmp(result.c_str() + (result.length() - trimChars.length()), trimChars.c_str(), trimChars.length()))
	{
		result[result.length() - trimChars.length()] = '\0';
		result = result.c_str();
	}

	return result;
}

const std::string Utility::getExecutablePath()
{
	const static char fname[] = "Utility::getExecutablePath() ";
#if defined(_WIN32)
	char buf[MAX_PATH] = {0};
	DWORD len = ::GetModuleFileNameA(NULL, buf, MAX_PATH);
	if (len == 0 || len >= MAX_PATH)
	{
		LOG_ERR << fname << "Failed to retrieve executable path: " << ::GetLastError();
		return "";
	}

	return boost::filesystem::path(buf).string();

#elif defined(__linux__)
	char buf[PATH_MAX] = {0};
	auto count = ACE_OS::readlink("/proc/self/exe", buf, PATH_MAX);
	if (count < 0 || count >= PATH_MAX)
	{
		LOG_ERR << fname << "Failed to read /proc/self/exe: " << last_error_msg();
		return "";
	}
	buf[count] = '\0';
	return buf;

#elif defined(__APPLE__)
	std::vector<char> buf(PATH_MAX);
	uint32_t size = buf.size();
	if (_NSGetExecutablePath(buf.data(), &size) != 0)
	{
		LOG_ERR << fname << "Failed to retrieve executable path";
		return "";
	}

	// Resolve symlinks to get the real path
	char realPath[PATH_MAX] = {0};
	if (realpath(buf.data(), realPath) == nullptr)
	{
		LOG_ERR << fname << "Failed to resolve real path: " << last_error_msg();
		return "";
	}
	return realPath;

#else
	LOG_ERR << fname << "Platform not supported";
	return "";
#endif
}

const std::string &Utility::getBinDir()
{
	static const std::string selfBinDir = fs::path(getExecutablePath()).parent_path().string();
	return selfBinDir;
}

const std::string &Utility::getHomeDir()
{
	static const std::string homeDir = fs::path(getBinDir()).parent_path().string();
	return homeDir;
}

const std::string Utility::getConfigFilePath(const std::string &configFile, bool write)
{
	const std::string workingConfigFile = (fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_WORK_CONFIG_DIR / configFile).string();
	if (write || Utility::isFileExist(workingConfigFile))
	{
		createDirectory((fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_WORK_CONFIG_DIR).string());
		return workingConfigFile;
	}
	return (fs::path(Utility::getHomeDir()) / configFile).string();
}

// program_name from errno.h
const std::string Utility::getBinaryName()
{
#if defined(__APPLE__)
	return getprogname(); // macOS-specific function
#elif defined(_WIN32)
	// Windows implementation without filesystem
	char buffer[MAX_PATH];
	DWORD length = GetModuleFileNameA(nullptr, buffer, MAX_PATH);
	if (length == 0)
	{
		return "";
	}

	std::string fullPath(buffer);
	size_t pos = fullPath.find_last_of("\\/");
	return pos != std::string::npos ? fullPath.substr(pos + 1) : fullPath;
#else
	// Linux implementation
	extern char *program_invocation_short_name;
	return program_invocation_short_name;
#endif
}

bool Utility::isDirExist(const std::string &path)
{
	boost::system::error_code ec;
	return fs::exists(path, ec) && fs::is_directory(path, ec);
}

bool Utility::isFileExist(const std::string &path)
{
	boost::system::error_code ec;
	return fs::exists(path, ec) && !fs::is_directory(path, ec);
}

bool Utility::createDirectory(const std::string &path, fs::perms perms)
{
	const static char fname[] = "Utility::createDirectory() ";

	if (!isDirExist(path))
	{
		const fs::path directoryPath = fs::path(path);
		if (!fs::create_directories(directoryPath))
		{
			LOG_ERR << fname << "Create directory <" << path << "> failed with error: " << last_error_msg();
			return false;
		}
		// os::chown(getuid(), getgid(), path, false);
		LOG_DBG << fname << "Created directory: " << path;
		fs::permissions(directoryPath, perms);
	}
	return true;
}

bool Utility::createRecursiveDirectory(const std::string &path, fs::perms perms)
{
	const static char fname[] = "Utility::createRecursiveDirectory() ";

	if (!isDirExist(path))
	{
		const fs::path directoryPath = fs::path(path);
		if (!fs::create_directories(directoryPath))
		{
			LOG_ERR << fname << "Create directory <" << path << "> failed with error: " << last_error_msg();
			return false;
		}
		fs::permissions(directoryPath, perms);
	}
	return true;
}

bool Utility::removeDir(const std::string &path)
{
	const static char fname[] = "Utility::removeDir() ";

	boost::system::error_code ec;
	if (fs::exists(path, ec))
	{
		auto removed = fs::remove_all(path, ec);
		if (ec)
		{
			LOG_ERR << fname << "remove <" << path << "> failed with error: " << ec.message();
			return false;
		}
		else
		{
			LOG_INF << fname << "removed <" << removed << "> files/directories from <" << path << ">";
			return true;
		}
	}
	return true;
}

void Utility::removeFile(const std::string &path)
{
	const static char fname[] = "Utility::removeFile() ";

	if (path.length() && isFileExist(path))
	{
		if (ACE_OS::unlink(path.c_str()) == 0)
		{
			LOG_DBG << fname << "file <" << path << "> removed";
		}
		else
		{
			LOG_WAR << fname << "removed file <" << path << "> failed with error: " << last_error_msg();
		}
	}
}

bool Utility::runningInContainer()
{
	static const bool isInContainer =
		std::ifstream("/run/.dockerenv").good() ||	// docker specific
		std::ifstream("/run/.containerenv").good(); // podman specific

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

		if (ACE_OS::setenv("SYSTEMROOT", systemRoot.c_str(), 0) == -1)
		{
			std::cerr << "[Error] Failed to set SYSTEMROOT to: " << systemRoot << " (Error " << last_error_msg() << ")" << std::endl;
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

	// Pattern
	spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%t] %l: %v");

	// Log level from env
	auto levelEnv = Utility::getenv("LOG_LEVEL");
	if (!levelEnv.empty())
		setLogLevel(levelEnv);

	LOG_DBG << "Logging process ID:" << getpid();
}

bool Utility::setLogLevel(const std::string &level)
{
	static std::map<std::string, spdlog::level::level_enum> levelMap =
		{
			{"NOTSET", spdlog::level::off},
			{"DEBUG", spdlog::level::debug},
			{"INFO", spdlog::level::info},
			{"WARN", spdlog::level::warn},
			{"ERROR", spdlog::level::err},
			{"CRIT", spdlog::level::critical},
			{"ALERT", spdlog::level::critical},
			{"FATAL", spdlog::level::critical},
			{"EMERG", spdlog::level::critical}};

	auto it = levelMap.find(level);
	if (it != levelMap.end())
	{
		spdlog::set_level(it->second);
		LOG_INF << "Setting log level to " << level;
		return true;
	}
	else
	{
		LOG_ERR << "No such log level " << level;
		return false;
	}
}

unsigned long long Utility::getThreadId()
{
	std::ostringstream oss;
	oss << std::this_thread::get_id();
	return std::stoull(oss.str());
}

std::string Utility::encode64(const std::string &val)
{
	using namespace boost::archive::iterators;
	using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
	auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
	return tmp.append((3 - val.size() % 3) % 3, '=');
}

std::string Utility::decode64(const std::string &val)
{
	using namespace boost::archive::iterators;
	using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
	return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(val)), It(std::end(val))), [](char c)
												{ return c == '\0'; });
}

std::string Utility::encodeURIComponent(const std::string &str)
{
	std::ostringstream escaped;
	escaped.fill('0');
	escaped << std::hex;

	for (char c : str)
	{
		// JavaScript's encodeURIComponent escapes all characters except:
		// A-Z a-z 0-9 - _ . ! ~ * ' ( )
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '!' ||
			c == '~' || c == '*' || c == '\'' || c == '(' || c == ')')
		{
			escaped << c;
		}
		else
		{
			escaped << std::uppercase;
			escaped << '%' << std::setw(2) << int((unsigned char)c);
			escaped << std::nouppercase;
		}
	}

	return escaped.str();
}

std::string Utility::decodeURIComponent(const std::string &encoded)
{
	std::string result;
	size_t i = 0;

	while (i < encoded.size())
	{
		if (encoded[i] == '%')
		{
			if (i + 2 < encoded.size() && std::isxdigit(encoded[i + 1]) && std::isxdigit(encoded[i + 2]))
			{
				int value = std::stoi(encoded.substr(i + 1, 2), nullptr, 16);
				result += static_cast<char>(value);
				i += 3;
			}
			else
			{
				throw std::invalid_argument("URI malformed");
			}
		}
		else
		{
			result += encoded[i];
			i++;
		}
	}

	return result;
}

std::string Utility::readFile(const std::string &path)
{
	const static char fname[] = "Utility::readFile() ";

	FILE *file = ::fopen(path.c_str(), "r");
	if (nullptr == file)
	{
		if (!startWith(path, "/proc/"))
			LOG_WAR << fname << "Get file <" << path << "> failed with error : " << last_error_msg();
		return "";
	}

	// Use a buffer to read the file in BUFSIZ
	// chunks and append it to the string we return.
	//
	// NOTE: We aren't able to use fseek() / ftell() here
	// to find the file size because these functions don't
	// work properly for in-memory files like /proc/*/stat.
	char *buffer = new char[BUFSIZ];
	std::string result;

	while (true)
	{
		std::size_t read = ::fread(buffer, 1, BUFSIZ, file);

		if (::ferror(file))
		{
			// NOTE: ferror() will not modify errno if the stream
			// is valid, which is the case here since it is open.
			LOG_ERR << fname << "fread failed with error : " << last_error_msg();
			delete[] buffer;
			::fclose(file);
			return "";
		}

		result.append(buffer, read);

		if (read != BUFSIZ)
		{
			assert(feof(file));
			break;
		}
	};

	::fclose(file);
	delete[] buffer;
	return result;
}

std::string Utility::readFileCpp(const std::string &path)
{
	const static char fname[] = "Utility::readFileCPP() ";

	std::ifstream file(path.c_str(), std::ios::in | std::ios::binary);
	if (!file)
	{
		LOG_WAR << fname << "Cannot open file <" << path << ">";
		return std::string();
	}

	std::string content;

	// Try to reserve size if this is a regular file
	file.seekg(0, std::ios::end);
	const std::streamoff size = file.tellg();
	if (size > 0)
		content.reserve(static_cast<size_t>(size));
	file.seekg(0, std::ios::beg);

	content.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

	return content;
}

std::string Utility::localEncodingToUtf8(const std::string &ansi)
{
#if defined(_WIN32)
	// Windows: ANSI → UTF-8
	if (ansi.empty())
		return {};

	int wideLen = MultiByteToWideChar(CP_ACP, 0, ansi.data(), static_cast<int>(ansi.size()), nullptr, 0);
	if (wideLen <= 0)
		return {};

	std::wstring wideStr(wideLen, L'\0');
	MultiByteToWideChar(CP_ACP, 0, ansi.data(), static_cast<int>(ansi.size()), wideStr.data(), wideLen);

	int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), wideLen, nullptr, 0, nullptr, nullptr);
	if (utf8Len <= 0)
		return {};

	std::string utf8Str(utf8Len, '\0');
	WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), wideLen, utf8Str.data(), utf8Len, nullptr, nullptr);

	return utf8Str;
#else
	// POSIX: already UTF-8
	return ansi;
#endif
}

std::string Utility::utf8ToLocalEncoding(const std::string &input)
{
#if defined(_WIN32)
	if (input.empty())
	{
		return input;
	}

	try
	{
		// Get the current system locale
		std::locale loc("");

		// Create UTF-8 to wchar_t converter
		std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8_conv;

		// Convert UTF-8 to wide string
		std::wstring wide_str = utf8_conv.from_bytes(input);

		// Use locale's codecvt facet to convert to local encoding
		const std::codecvt<wchar_t, char, std::mbstate_t> &codecvt_facet =
			std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t>>(loc);

		std::mbstate_t state = std::mbstate_t();
		std::string result(wide_str.length() * codecvt_facet.max_length(), '\0');

		const wchar_t *from_next;
		char *to_next;

		std::codecvt_base::result conv_result = codecvt_facet.out(
			state,
			wide_str.data(), wide_str.data() + wide_str.length(), from_next,
			&result[0], &result[0] + result.length(), to_next);

		if (conv_result == std::codecvt_base::ok ||
			conv_result == std::codecvt_base::noconv)
		{
			result.resize(to_next - &result[0]);
			return result;
		}

		// If conversion failed, return original string
		return input;
	}
	catch (...)
	{
		// If any exception occurs (locale not available, etc.),
		// return original string
		return input;
	}

#else
	// POSIX: assume UTF-8 environment
	return input;
#endif
}

// TODO: use ICU for detectAndConvertToUTF8
/*
#include <unicode/ucsdet.h>
#include <unicode/ucnv.h>

std::string detectAndConvertToUTF8(const std::string& input) {
	UErrorCode status = U_ZERO_ERROR;
	UCharsetDetector* detector = ucsdet_open(&status);

	ucsdet_setText(detector, input.c_str(), input.length(), &status);
	const UCharsetMatch* match = ucsdet_detect(detector, &status);

	if (match) {
		const char* encoding = ucsdet_getName(match, &status);
		// Convert using ICU converter
		UConverter* conv = ucnv_open(encoding, &status);
		// ... conversion code
	}

	ucsdet_close(detector);
	return result;
}
*/
std::string Utility::fileBytesToUtf8(const std::string &input)
{
#ifdef _WIN32
	if (input.empty())
		return input;

	// Check for UTF-8 BOM
	if (input.size() >= 3 &&
		static_cast<unsigned char>(input[0]) == 0xEF &&
		static_cast<unsigned char>(input[1]) == 0xBB &&
		static_cast<unsigned char>(input[2]) == 0xBF)
	{
		return input.substr(3);
	}

	// Check for UTF-16 LE BOM
	if (input.size() >= 2 &&
		static_cast<unsigned char>(input[0]) == 0xFF &&
		static_cast<unsigned char>(input[1]) == 0xFE)
	{
		const wchar_t *wstr = reinterpret_cast<const wchar_t *>(input.data() + 2);
		int len = (input.size() - 2) / 2;

		int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wstr, len, nullptr, 0, nullptr, nullptr);
		if (utf8Len == 0)
			return input;

		std::string result(utf8Len, 0);
		WideCharToMultiByte(CP_UTF8, 0, wstr, len, &result[0], utf8Len, nullptr, nullptr);
		return result;
	}

	// Check for UTF-16 BE BOM
	if (input.size() >= 2 &&
		static_cast<unsigned char>(input[0]) == 0xFE &&
		static_cast<unsigned char>(input[1]) == 0xFF)
	{
		std::wstring wstr;
		wstr.resize((input.size() - 2) / 2);
		for (size_t i = 0; i < wstr.size(); ++i)
		{
			wstr[i] = static_cast<wchar_t>(
				(static_cast<unsigned char>(input[2 + i * 2]) << 8) |
				static_cast<unsigned char>(input[2 + i * 2 + 1]));
		}

		int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), nullptr, 0, nullptr, nullptr);
		if (utf8Len == 0)
			return input;

		std::string result(utf8Len, 0);
		WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), &result[0], utf8Len, nullptr, nullptr);
		return result;
	}

	// Try to detect and convert from various encodings
	// First, try to validate if it's already valid UTF-8
	if (isValidUTF8(input))
	{
		return input;
	}

	// Try common Windows codepages in order of likelihood
	std::vector<UINT> codepages = {
		936,   // GBK/GB2312 (Simplified Chinese)
		950,   // Big5 (Traditional Chinese)
		932,   // Shift-JIS (Japanese)
		949,   // EUC-KR (Korean)
		1252,  // Windows-1252 (Western European)
		1251,  // Windows-1251 (Cyrillic)
		CP_ACP // System default ANSI codepage
	};

	for (UINT codepage : codepages)
	{
		std::string result = convertToUTF8(input, codepage);
		if (!result.empty())
		{
			return result;
		}
	}

	// If all else fails, return original
	return input;
#else
	return input;
#endif
}

// Helper function to validate UTF-8
bool Utility::isValidUTF8(const std::string &str)
{
	const unsigned char *bytes = reinterpret_cast<const unsigned char *>(str.c_str());
	size_t len = str.length();

	for (size_t i = 0; i < len;)
	{
		if (bytes[i] < 0x80)
		{
			i++;
		}
		else if ((bytes[i] & 0xE0) == 0xC0)
		{
			if (i + 1 >= len || (bytes[i + 1] & 0xC0) != 0x80)
				return false;
			i += 2;
		}
		else if ((bytes[i] & 0xF0) == 0xE0)
		{
			if (i + 2 >= len || (bytes[i + 1] & 0xC0) != 0x80 || (bytes[i + 2] & 0xC0) != 0x80)
				return false;
			i += 3;
		}
		else if ((bytes[i] & 0xF8) == 0xF0)
		{
			if (i + 3 >= len || (bytes[i + 1] & 0xC0) != 0x80 || (bytes[i + 2] & 0xC0) != 0x80 || (bytes[i + 3] & 0xC0) != 0x80)
				return false;
			i += 4;
		}
		else
		{
			return false;
		}
	}
	return true;
}

// Helper function to convert from specific codepage to UTF-8
std::string Utility::convertToUTF8(const std::string &input, unsigned int codepage)
{
#ifdef _WIN32
	if (input.empty())
		return "";

	// Convert from codepage to wide string
	int wideLen = MultiByteToWideChar(codepage, 0, input.c_str(), input.length(), nullptr, 0);
	if (wideLen == 0)
		return "";

	std::wstring wideStr(wideLen, 0);
	if (MultiByteToWideChar(codepage, 0, input.c_str(), input.length(), &wideStr[0], wideLen) == 0)
	{
		return "";
	}

	// Convert from wide string to UTF-8
	int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), wideStr.length(), nullptr, 0, nullptr, nullptr);
	if (utf8Len == 0)
		return "";

	std::string result(utf8Len, 0);
	if (WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), wideStr.length(), &result[0], utf8Len, nullptr, nullptr) == 0)
	{
		return "";
	}

	return result;
#else
	return "";
#endif
}

std::string Utility::readFileCpp(const std::string &path, long *position, long maxSize, bool readLine)
{
	const static char fname[] = "Utility::readFileCPP() ";

	if (!Utility::isFileExist(path))
	{
		LOG_WAR << fname << "File does not exist: " << path;
		return std::string();
	}

	std::ifstream fileStream(path, std::ios::in | std::ios::binary);
	if (!fileStream.is_open())
	{
		LOG_ERR << fname << "Failed to open file: " << path;
		return std::string();
	}

	// Get file size
	fileStream.seekg(0, std::ios::end);
	const std::streampos fileSize = fileStream.tellg();
	if (fileSize == std::streampos(-1))
	{
		LOG_ERR << fname << "Failed to get file size";
		return std::string();
	}

	// Validate position
	if (position && *position > fileSize)
	{
		throw std::invalid_argument(Utility::stringFormat("Invalid position <%ld>, file size: <%ld>", *position, static_cast<long>(fileSize)));
	}

	fileStream.clear();

	// Set read position
	if (position && *position >= 0)
		fileStream.seekg(*position);
	else
		fileStream.seekg(0, std::ios::beg);
	if (!fileStream.good())
	{
		LOG_ERR << fname << ("Failed to seek to specified position");
		return std::string();
	}

	std::string result;

	if (maxSize >= 0)
	{
		// Forward reading
		size_t readSize = (maxSize == 0) ? static_cast<size_t>(fileSize) : std::min(static_cast<size_t>(maxSize), static_cast<size_t>(fileSize));

		if (readLine)
		{
			std::string line;
			if (std::getline(fileStream, line))
			{
				result = line.substr(0, readSize);
			}
		}
		else
		{
			result.resize(readSize);
			fileStream.read(&result[0], readSize);
			result.resize(fileStream.gcount()); // Adjust to actual bytes read
		}
	}
	else
	{
		// Reverse reading
		size_t readSize = std::min(static_cast<size_t>(-maxSize), static_cast<size_t>(fileSize));

		// Adjust position for reverse reading
		if (position && *position == 0)
		{
			if (!fileStream.seekg(0, std::ios::end))
			{
				LOG_ERR << fname << ("Failed to seek to end for reverse reading");
				return std::string();
			}
		}

		const std::streampos endPos = fileStream.tellg();
		if (endPos == std::streampos(-1))
		{
			LOG_ERR << fname << ("Failed to get current position");
			return std::string();
		}

		if (readLine)
		{
			// Reverse line reading
			result.reserve(readSize);
			size_t bytesRead = 0;
			while (fileStream.tellg() > 0 && bytesRead < readSize)
			{
				if (!fileStream.seekg(-1, std::ios::cur))
				{
					break;
				}

				int c = fileStream.get();
				if (c == EOF || c == '\n')
				{
					break;
				}

				result.push_back(static_cast<char>(c));
				if (!fileStream.seekg(-1, std::ios::cur))
				{
					break;
				}

				++bytesRead;
			}
			std::reverse(result.begin(), result.end());
		}
		else
		{
			// Reverse block reading
			if (endPos > static_cast<std::streamoff>(readSize))
			{
				if (!fileStream.seekg(-static_cast<std::streamoff>(readSize), std::ios::end))
				{
					LOG_ERR << fname << ("Failed to seek for reverse reading");
					return std::string();
				}
			}
			else
			{
				if (!fileStream.seekg(0, std::ios::beg))
				{
					LOG_ERR << fname << ("Failed to seek to beginning");
					return std::string();
				}
				readSize = static_cast<size_t>(endPos);
			}

			result.resize(readSize);
			if (!fileStream.read(&result[0], readSize))
			{
				LOG_ERR << fname << ("Failed to read file content");
				return std::string();
			}
			result.resize(fileStream.gcount());
		}
	}

	// Update position
	if (position)
	{
		const std::streampos currentPos = fileStream.tellg();
		if (currentPos == std::streampos(-1))
		{
			// If we can't get the position, estimate it
			*position = *position + static_cast<long>(result.size());
		}
		else
		{
			*position = static_cast<long>(currentPos);
		}
	}

	return fileBytesToUtf8(result);
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
	// Generate UUID
	ACE_Utils::UUID uuid;
	ACE_Utils::UUID_GENERATOR::instance()->generate_UUID(uuid);

	// Convert to string
	const auto *uuid_str = uuid.to_string();
	if (uuid_str == nullptr)
	{
		return shortID();
	}

	// Remove hyphens
	std::string result = uuid_str->c_str();
	result.erase(std::remove(result.begin(), result.end(), '-'), result.end());

	return result;
}

bool Utility::createPidFile()
{
	const static char fname[] = "Utility::createPidFile() ";

	// https://stackoverflow.com/questions/5339200/how-to-create-a-single-instance-application-in-c-or-c
	// https://stackoverflow.com/questions/65738650/c-create-a-pid-file-using-system-call
	const auto pidFile = (fs::path(Utility::getHomeDir()) / PID_FILE).string();

#if !defined(_WIN32)
	int fd = open(pidFile.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0666);
	if (fd < 0)
	{
		std::cerr << fname << "Failed to create PID file [" << pidFile << "]: " << last_error_msg() << std::endl;
		return false;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) == 0)
	{
		std::cout << fname << "New process running. PID file locked: " << pidFile << std::endl;
		std::string pid = std::to_string(getpid());
		if (write(fd, pid.c_str(), pid.length()) <= 0)
		{
			std::cerr << fname << "Failed to write PID to file [" << pidFile << "]: " << last_error_msg() << std::endl;
			close(fd);
			return false;
		}
		return true;
	}
	else
	{
		if (ACE_OS::last_error() == EWOULDBLOCK)
		{
			std::cerr << fname << "Process already running. PID file locked: " << pidFile << std::endl;
		}
		else
		{
			std::cerr << fname << "Failed to lock PID file [" << pidFile << "]: " << last_error_msg() << std::endl;
		}
		close(fd);
		return false;
	}

#else
	// Windows implementation using file locking
	HANDLE hFile = CreateFileA(pidFile.c_str(), GENERIC_READ | GENERIC_WRITE,
							   0, // not shared, self-owned
							   NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SHARING_VIOLATION)
		{
			std::cerr << fname << "Process already running. PID file locked: " << pidFile << std::endl;
		}
		else
		{
			std::cerr << fname << "Failed to create PID file <" << pidFile << "> with error " << error << std::endl;
		}
		return false;
	}

	std::string pid = std::to_string(ACE_OS::getpid());
	DWORD bytesWritten;
	if (!WriteFile(hFile, pid.c_str(), static_cast<DWORD>(pid.length()), &bytesWritten, NULL))
	{
		std::cerr << fname << "Failed to write PID to file <" << pidFile << "> with error " << GetLastError() << std::endl;
		CloseHandle(hFile);
		return false;
	}

	std::cout << fname << "New process running. PID file locked: " << pidFile << std::endl;
	// Keep handle open to maintain lock
	return true;
#endif
}

void Utility::appendStrTimeAttr(nlohmann::json &jsonObj, const std::string &key)
{
	if (HAS_JSON_FIELD(jsonObj, key))
	{
		jsonObj[key + JSON_KEY_TIME_POSTTIX_STR] = std::string(DateTime::formatLocalTime(std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, key))));
	}
}

void Utility::appendStrDayTimeAttr(nlohmann::json &jsonObj, const std::string &key)
{
	if (HAS_JSON_FIELD(jsonObj, key))
	{
		jsonObj[key + JSON_KEY_TIME_POSTTIX_STR] = std::string(splitString(DateTime::formatISO8601Time(std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, key))), "T").back());
	}
}

void Utility::addExtraAppTimeReferStr(nlohmann::json &appJson)
{
	// append extra string format for time values
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_REG_TIME);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_SHORT_APP_start_time);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_SHORT_APP_end_time);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_last_start);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_APP_last_exit);
	Utility::appendStrTimeAttr(appJson, JSON_KEY_SHORT_APP_next_start_time);
	if (HAS_JSON_FIELD(appJson, JSON_KEY_APP_daily_limitation))
	{
		Utility::appendStrDayTimeAttr(appJson.at(JSON_KEY_APP_daily_limitation), JSON_KEY_DAILY_LIMITATION_daily_start);
		Utility::appendStrDayTimeAttr(appJson.at(JSON_KEY_APP_daily_limitation), JSON_KEY_DAILY_LIMITATION_daily_end);
	}
}

void Utility::initDateTimeZone(const std::string &posixTimezone, bool writeLog)
{
	const auto &zone = DateTime::initOutputFormatPosixZone(posixTimezone);
	if (writeLog)
	{
		LOG_INF << "Set timezone to: " << zone->to_posix_string();
	}
}

std::vector<std::string> Utility::splitString(const std::string &source, const std::string &splitFlag)
{
	std::vector<std::string> result;
	std::string::size_type pos1, pos2;
	pos2 = source.find(splitFlag);
	pos1 = 0;
	while (std::string::npos != pos2)
	{
		std::string str = stdStringTrim(source.substr(pos1, pos2 - pos1));
		if (str.length() > 0)
			result.push_back(str);

		pos1 = pos2 + splitFlag.size();
		pos2 = source.find(splitFlag, pos1);
	}
	if (pos1 != source.length())
	{
		std::string str = stdStringTrim(source.substr(pos1));
		if (!str.empty())
			result.push_back(std::move(str));
	}
	return result;
}

bool Utility::startWith(const std::string &str, const std::string &prefix)
{
	// https://luodaoyi.com/p/cpp-std-startwith-endwith.html
	if (&str == &prefix)
		return true;
	const std::string::size_type big_size = str.size();
	const std::string::size_type small_size = prefix.size();
	const bool valid_ = (big_size >= small_size);
	const bool starts_with_ = (str.compare(0, small_size, prefix) == 0);
	return valid_ && starts_with_;
}

bool Utility::endWith(const std::string &str, const std::string &postfix)
{
	if (&str == &postfix)
		return true;
	const std::string::size_type big_size = str.size();
	const std::string::size_type small_size = postfix.size();
	const bool valid_ = (big_size >= small_size);
	const bool ends_with_ = (str.compare(big_size - small_size, small_size, postfix) == 0);
	return valid_ && ends_with_;
}

size_t Utility::charCount(const std::string &str, const char &c)
{
	return std::count_if(str.begin(), str.end(), [c](char strChar)
						 { return strChar == c; });
}

std::string Utility::stringReplace(const std::string &strBase, const std::string &strSrc, const std::string &strDst, int startPos)
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

std::string Utility::humanReadableSize(long double bytesSize)
{
	static constexpr int base = 1024;
	static constexpr const char *fmt[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"};
	static constexpr size_t fmtSize = sizeof(fmt) / sizeof(fmt[0]);

	// Handle invalid cases
	if (bytesSize < 0 || std::isnan(bytesSize) || std::isinf(bytesSize))
	{
		return "N/A";
	}

	// Handle zero case
	if (bytesSize == 0)
	{
		return "0 B";
	}

	std::size_t units = 0;
	long double n = std::abs(bytesSize);

	// Find appropriate unit
	while (n >= base && units + 1 < fmtSize)
	{
		units++;
		n /= base;
	}

	// Format with 1 decimal place and handle the .0 case directly
	std::ostringstream ss;
	ss.precision(1);
	ss << std::fixed << n;
	std::string result = ss.str();

	// Remove ".0" if present
	if (result.size() > 2 && result.substr(result.size() - 2) == ".0")
	{
		result.resize(result.size() - 2);
	}

	// Add unit
	result += " " + std::string(fmt[units]);

	return result;
}

std::string Utility::humanReadableDuration(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime)
{
	std::string result;
	std::list<std::string> steps;

	if (endTime < startTime)
	{
		result = "N/A";
		return result;
	}
	const auto duration = endTime - startTime;

	const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count() % 60;
	if (seconds)
	{
		steps.push_back(std::to_string(seconds).append("s"));
	}
	const auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count() % 60;
	if (minutes)
	{
		steps.push_back(std::to_string(minutes).append("m"));
	}
	const auto hours = std::chrono::duration_cast<std::chrono::hours>(duration).count() % 24;
	if (hours)
	{
		steps.clear();
		steps.push_back(std::to_string(hours).append("h"));
	}
	const auto days = std::chrono::duration_cast<std::chrono::hours>(duration).count() / 24;
	if (days)
	{
		steps.clear();
		steps.push_back(std::to_string(days).append("d"));
	}

	while (steps.size() > 2)
	{
		steps.pop_front();
	}
	while (steps.size())
	{
		result.append(steps.back());
		steps.pop_back();
	}

	return result;
}

void Utility::getEnvironmentSize(const std::map<std::string, std::string> &envMap, int &totalEnvSize, int &totalEnvArgs)
{
	totalEnvSize = 0;
	totalEnvArgs = 0;

	for (const auto &kv : envMap)
	{
		// length of "KEY=VALUE\0"
		totalEnvSize += static_cast<int>(kv.first.length() + kv.second.length() + 2); // add 2 for = and terminator
		totalEnvArgs++;
	}

	// Add safety margin: 20% more, min 256 entries and 4KB
	totalEnvArgs += std::max(256, totalEnvArgs / 5);
	totalEnvSize += std::max(4096, totalEnvSize / 5);
}

void Utility::applyFilePermission(const std::string &file, HttpHeaderMap headers)
{
	if (Utility::isFileExist(file))
	{
		if (headers.count(HTTP_HEADER_KEY_file_mode))
			os::fileChmod(file, std::stoi(headers.find(HTTP_HEADER_KEY_file_mode)->second));
		if (headers.count(HTTP_HEADER_KEY_file_user) && headers.count(HTTP_HEADER_KEY_file_group))
			os::chown(file,
					  std::stoi(headers.find(HTTP_HEADER_KEY_file_user)->second),
					  std::stoi(headers.find(HTTP_HEADER_KEY_file_group)->second));
	}
}

std::string Utility::getenv(const std::string &envName, const std::string &defaultValue)
{
	const char *val = ACE_OS::getenv(envName.data());
	if (val == nullptr || val[0] == '\0')
		return defaultValue;

	return val;
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

std::string Utility::hash(const std::string &str)
{
	// FNV-1a hash algorithm - cross platform
	const uint64_t FNV_prime = 1099511628211ULL;
	const uint64_t FNV_offset_basis = 14695981039346656037ULL;

	uint64_t hash = FNV_offset_basis;

	for (char c : str)
	{
		hash ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
		hash *= FNV_prime;
	}

	return std::string("H") + std::to_string(hash);
}

std::string Utility::stringFormat(const std::string fmt_str, ...)
{
	// https://stackoverflow.com/questions/2342162/stdstring-formatting-like-sprintf
	int final_n, n = ((int)fmt_str.size()) * 2; /* Reserve two times as much as the length of the fmt_str */
	std::unique_ptr<char[]> formatted;
	va_list ap;
	while (true)
	{
		formatted.reset(new char[n]); /* Wrap the plain char array into the unique_ptr */
		strcpy(&formatted[0], fmt_str.c_str());
		va_start(ap, fmt_str);
		final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
		va_end(ap);
		if (final_n < 0 || final_n >= n)
			n += abs(final_n - n + 1);
		else
			break;
	}
	return std::string(formatted.get());
}

std::string Utility::strToupper(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c)
				   { return std::toupper(c); });
	return s;
}

std::string Utility::strTolower(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c)
				   { return std::tolower(c); });
	return s;
}

std::string Utility::htmlEntitiesDecode(const std::string &str)
{
	// https://forums.codeguru.com/showthread.php?448809-C-Replacing-HTML-Character-Entities
	// https://wanghi.cn/202003/20836.html

	const static std::vector<std::string> subs = {
		"&#34;", "& #34;", "&quot;", "&34;",
		"&#39;", "& #39;", "&apos;", "&39;",
		"&#38;", "& #38;", "&amp;", "&38;",
		"&#60;", "& #60;", "&lt;", "&60;",
		"&#62;", "& #62;", "&gt;", "&62;",
		"&#32;", "& #32;", "&nbsp;", "&32;", "%20",
		"&ndash;", "\u2013",
		"&#40;", "& #40;",
		"&#41;", "& #41;"};

	const static std::vector<std::string> reps = {
		"\"", "\"", "\"", "\"",
		"'", "'", "'", "'",
		"&", "&", "&", "&",
		"<", "<", "<", "<",
		">", ">", ">", ">",
		" ", " ", " ", " ", " ",
		"-", "-",
		"(", "(",
		")", ")"};

	assert(subs.size() == reps.size());

	std::string result = str;
	for (size_t j = 0; j < reps.size(); j++)
	{
		const std::string &match = subs[j];
		const std::string &repl = reps[j];
		// Replace all matches
		std::string::size_type start = result.find_first_of(match);
		while (start != std::string::npos)
		{
			result.replace(start, match.size(), repl);
			start = result.find_first_of(match, start + repl.size());
		}
	}
	return result;
}

std::vector<std::string> Utility::str2argv(const std::string &commandLine)
{
	// https://stackoverflow.com/questions/1511797/convert-string-to-argv-in-c
	// backup: https://stackoverflow.com/questions/1706551/parse-string-into-argv-argc
#if defined(_WIN32)
	return boost::program_options::split_winmain(commandLine);
#else
	return boost::program_options::split_unix(commandLine);
#endif
}

nlohmann::json Utility::text2json(const std::string &str)
{
	nlohmann::json result;
	result[REST_TEXT_MESSAGE_JSON_KEY] = std::string(str);
	return result;
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

std::string Utility::jsonToYaml(const nlohmann::json &j, std::shared_ptr<YAML::Emitter> out)
{
	if (out == nullptr)
	{
		out = std::make_shared<YAML::Emitter>();
	}

	if (j.is_object())
	{
		*out << YAML::BeginMap;
		for (auto it = j.begin(); it != j.end(); ++it)
		{
			*out << YAML::Key << it.key();
			jsonToYaml(it.value(), out);
		}
		*out << YAML::EndMap;
	}
	else if (j.is_array())
	{
		*out << YAML::BeginSeq;
		for (const auto &element : j)
		{
			jsonToYaml(element, out);
		}
		*out << YAML::EndSeq;
	}
	else if (j.is_boolean())
	{
		*out << j.get<bool>();
	}
	else if (j.is_number())
	{
		*out << j.get<double>();
	}
	else if (j.is_null())
	{
		*out << YAML::Null;
	}
	else
	{
		// String
		std::string str = j.get<std::string>();
		if (containsSpecialCharacters(str))
		{
			*out << YAML::Literal << str;
		}
		else
		{
			*out << str;
		}
	}

	return out->c_str(); // Return the YAML string
}

nlohmann::json Utility::yamlToJson(const YAML::Node &node)
{
	nlohmann::json result;

	auto parseScalar = [](const YAML::Node &scalarNode) -> nlohmann::json
	{
		const std::string scalar = scalarNode.Scalar();
		if (scalar == "true")
			return true;
		if (scalar == "false")
			return false;
		if (scalar == "null")
			return nullptr;
		if (Utility::isNumber(scalar))
			return std::stol(scalar);
		if (Utility::isDouble(scalar))
			return std::stod(scalar);
		return Utility::stdStringTrim(scalar);
	};

	if (node.IsMap())
	{
		for (const auto &pair : node)
		{
			const std::string key = pair.first.as<std::string>();
			if (pair.second.IsScalar())
			{
				result[key] = parseScalar(pair.second);
			}
			else
			{
				result[key] = yamlToJson(pair.second);
			}
		}
	}
	else if (node.IsSequence())
	{
		for (const auto &element : node)
		{
			result.push_back(yamlToJson(element));
		}
	}
	else if (node.IsScalar())
	{
		result = parseScalar(node);
	}
	else
	{
		LOG_ERR << "Failed to parse YAML node: " << node;
	}

	return result;
}

const std::string Utility::readStdin2End()
{
	std::stringstream ss;
	std::string line;
	while (!std::cin.eof() && std::getline(std::cin, line))
	{
		ss << line << std::endl;
	}
	return ss.str();
}

void Utility::printQRcode(const std::string &src)
{
	// https://www.nayuki.io/page/qr-code-generator-library#cpp
	auto qr = qrcodegen::QrCode::encodeText(src.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);

	int border = 2;
	for (int y = -border; y < qr.getSize() + border; y++)
	{
		for (int x = -border; x < qr.getSize() + border; x++)
		{
			std::cout << (qr.getModule(x, y) ? "██" : "  ");
		}
		std::cout << std::endl;
	}
	std::cout << std::endl;
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

NotFoundException::NotFoundException(const char *what) noexcept : std::logic_error(what)
{
}

NotFoundException::NotFoundException(const std::string &what) noexcept : std::logic_error(what)
{
}

static thread_local std::string g_errorMessage;

const char *last_error_msg()
{
	// Get the last error code
	int err_code = ACE_OS::last_error();

	// Retrieve the corresponding error message
	const char *error_message = ACE_OS::strerror(err_code);

	// Check if the error message is valid
	if (error_message && *error_message)
	{
		g_errorMessage.assign(error_message); // Use assign to minimize allocations
	}
	else
	{
		g_errorMessage.assign("Unknown error"); // Assign a fallback error message
	}

	// Return a pointer to the internal buffer of the thread-local string
	return g_errorMessage.c_str();
}

#include <atomic>
#include <errno.h>
#include <fstream>
#include <list>
#include <string>
#include <sys/file.h>
#include <thread>
#if defined(__APPLE__)
#include <crt_externs.h> // For getprogname
#include <mach-o/dyld.h> // For _NSGetExecutablePath
#endif

#include <ace/OS.h>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options/parsers.hpp>
#include <hashidsxx/hashids.cpp>
#include <hashidsxx/hashids.h>
#include <log4cpp/Appender.hh>
#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/Priority.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <nlohmann/json.hpp>

#include "DateTime.h"
#include "Password.h"
#include "Utility.h"
#include "os/chown.hpp"
#include "os/linux.hpp"

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
#if defined(WIN32)
	char buf[MAX_PATH] = {0};
	if (::GetModuleFileNameA(NULL, buf, MAX_PATH) == 0)
	{
		LOG_ERR << fname << "Failed to retrieve executable path: " << ::GetLastError();
		return "";
	}

	// Remove ".exe" extension if present
	std::size_t idx = 0;
	while (buf[idx] != '\0')
	{
		if (buf[idx] == '.' && buf[idx + 1] == 'e' && buf[idx + 2] == 'x' && buf[idx + 3] == 'e')
		{
			buf[idx] = '\0';
			break;
		}
	}
	return buf;

#elif defined(__linux__)
	char buf[PATH_MAX] = {0};
	auto count = ACE_OS::readlink("/proc/self/exe", buf, PATH_MAX);
	if (count < 0 || count >= PATH_MAX)
	{
		LOG_ERR << fname << "Failed to read /proc/self/exe: " << strerror(errno);
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
		LOG_ERR << fname << "Failed to resolve real path: " << strerror(errno);
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
#else
	extern char *program_invocation_short_name;
	return program_invocation_short_name; // Linux-specific variable
#endif
}

bool Utility::isDirExist(const std::string &path)
{
	fs::path p(path);
	return fs::exists(p) && fs::is_directory(p);
}

bool Utility::isFileExist(const std::string &path)
{
	fs::path p(path);
	return fs::exists(p) && !fs::is_directory(p);
}

bool Utility::createDirectory(const std::string &path, fs::perms perms)
{
	const static char fname[] = "Utility::createDirectory() ";

	if (!isDirExist(path))
	{
		const fs::path directoryPath = fs::path(path);
		if (!fs::create_directories(directoryPath))
		{
			LOG_ERR << fname << "Create directory <" << path << "> failed with error: " << std::strerror(errno);
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
			LOG_ERR << fname << "Create directory <" << path << "> failed with error: " << std::strerror(errno);
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
			LOG_WAR << fname << "removed file <" << path << "> failed with error: " << std::strerror(errno);
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

void Utility::initLogging(const std::string &name)
{
	using namespace log4cpp;

	// Configure console logging with custom date format
	auto consoleLayout = new PatternLayout();
	consoleLayout->setConversionPattern("%d{%Y-%m-%d %H:%M:%S.%l} [%t] %p %c: %m%n");
	auto consoleAppender = new OstreamAppender("console", &std::cout);
	consoleAppender->setLayout(consoleLayout);

	Category &root = Category::getRoot();

	// Configure rolling file logging if name is provided
	if (!name.empty())
	{
		auto logPath = (fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / name).string() + ".log";
		auto rollingFileAppender = new RollingFileAppender(
			"rollingFileAppender",
			logPath,
			20 * 1024 * 1024,
			5,
			true,
			00664);

		// Apply the same date format to the file layout
		auto pLayout = new PatternLayout();
		pLayout->setConversionPattern("%d{%Y-%m-%d %H:%M:%S.%l} [%t] %p %c: %m%n");
		rollingFileAppender->setLayout(pLayout);
		root.addAppender(rollingFileAppender);
	}
	root.addAppender(consoleAppender);

	// Log level
	auto levelEnv = getenv("LOG_LEVEL");
	if (levelEnv != nullptr)
	{
		setLogLevel(levelEnv);
	}

	LOG_DBG << "Logging process ID:" << getpid();
}

bool Utility::setLogLevel(const std::string &level)
{
	std::map<std::string, log4cpp::Priority::PriorityLevel> levelMap = {
		{"NOTSET", log4cpp::Priority::NOTSET},
		{"DEBUG", log4cpp::Priority::DEBUG},
		{"INFO", log4cpp::Priority::INFO},
		{"NOTICE", log4cpp::Priority::NOTICE},
		{"WARN", log4cpp::Priority::WARN},
		{"ERROR", log4cpp::Priority::ERROR},
		{"CRIT", log4cpp::Priority::CRIT},
		{"ALERT", log4cpp::Priority::ALERT},
		{"FATAL", log4cpp::Priority::FATAL},
		{"EMERG", log4cpp::Priority::EMERG}};

	if (level.length() > 0 && levelMap.find(level) != levelMap.end())
	{
		LOG_INF << "Setting log level to " << level;
		log4cpp::Category::getRoot().setPriority(levelMap[level]);
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
			LOG_WAR << fname << "Get file <" << path << "> failed with error : " << std::strerror(errno);
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
			LOG_ERR << fname << "fread failed with error : " << std::strerror(errno);
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

	if (!Utility::isFileExist(path))
	{
		LOG_WAR << fname << "File not exist :" << path;
		return std::string();
	}

	std::ifstream file(path);
	if (!file.is_open())
	{
		LOG_ERR << "can not open file <" << path << ">";
		return std::string();
	}
	std::string str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();
	return str;
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

	return result;
}

std::string Utility::createUUID()
{
	return hashId();
}

bool Utility::createPidFile()
{
	const static char fname[] = "Utility::createPidFile() ";

	const auto pidFile = (fs::path(Utility::getHomeDir()) / PID_FILE).string();
	// https://stackoverflow.com/questions/5339200/how-to-create-a-single-instance-application-in-c-or-c
	// https://stackoverflow.com/questions/65738650/c-create-a-pid-file-using-system-call
	auto fd = open(pidFile.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0666);
	if (fd < 0)
	{
		std::cout << fname << "Failed to create PID file:" << pidFile << " with error: " << std::strerror(errno) << std::endl;
		return false;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) == 0)
	{
		std::cout << fname << "New process running";
		auto pid = std::to_string(getpid());
		return write(fd, pid.c_str(), pid.length() + 1) > 0;
	}
	else
	{
		if (EWOULDBLOCK == errno)
			std::cerr << fname << "process already running";
		else
			std::cerr << fname << "Failed with error: " << std::strerror(errno);
	}
	return false;
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

bool Utility::startWith(const std::string &big, const std::string &small)
{
	// https://luodaoyi.com/p/cpp-std-startwith-endwith.html
	if (&big == &small)
		return true;
	const std::string::size_type big_size = big.size();
	const std::string::size_type small_size = small.size();
	const bool valid_ = (big_size >= small_size);
	const bool starts_with_ = (big.compare(0, small_size, small) == 0);
	return valid_ && starts_with_;
}

bool Utility::endWith(const std::string &big, const std::string &small)
{
	if (&big == &small)
		return true;
	const std::string::size_type big_size = big.size();
	const std::string::size_type small_size = small.size();
	const bool valid_ = (big_size >= small_size);
	const bool ends_with_ = (big.compare(big_size - small_size, small_size, small) == 0);
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
	const static int base = 1024;
	// const static char* fmt[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
	const static char *fmt[] = {"B", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"};

	if (bytesSize == 0)
	{
		return "0";
	}

	std::size_t units = 0;
	long double n = bytesSize;
	while (n > base && units + 1 < sizeof(fmt) / sizeof(*fmt))
	{
		units++;
		n /= base;
	}
	char buffer[64] = {0};
	snprintf(buffer, sizeof(buffer), "%.1Lf %s", n, fmt[units]);
	std::string str = buffer;
	return stringReplace(str, ".0", "");
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

bool Utility::getUid(const std::string &userName, unsigned int &uid, unsigned int &groupid)
{
	const static char fname[] = "Utility::getUid() ";

	if (userName.empty())
	{
		LOG_ERR << fname << "Empty username provided";
		return false;
	}

	bool rt = false;
	struct passwd pwd;
	struct passwd *result = NULL;
	static auto bufsize = ACE_OS::sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 16384;
	std::shared_ptr<char> buff(new char[bufsize], std::default_delete<char[]>());
	ACE_OS::getpwnam_r(userName.c_str(), &pwd, buff.get(), bufsize, &result);
	if (result)
	{
		uid = pwd.pw_uid;
		groupid = pwd.pw_gid;
		rt = true;
	}
	else
	{
		LOG_ERR << "User does not exist: <" << userName << ">.";
	}
	return rt;
}

std::string Utility::getUsernameByUid(uid_t uid)
{
	const static char fname[] = "Utility::getUsernameByUid() ";

	if (uid == std::numeric_limits<uid_t>::max())
	{
		LOG_WAR << fname << "Invalid UID provided";
		return "";
	}

	long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 16384;

	std::vector<char> buffer(bufsize);
	struct passwd pwd;
	struct passwd *result = nullptr;

	int ret = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);

	if (ret == 0 && result != nullptr)
	{
		LOG_DBG << fname << "User name for " << uid << " is " << pwd.pw_name;
		return std::string(pwd.pw_name);
	}

	if (ret == 0)
	{
		LOG_WAR << fname << "User not found for UID: " << uid;
	}
	else
	{
		LOG_WAR << fname << "Failed to get username for UID: " << uid << " with error: " << std::strerror(ret);
	}

	return "";
}

void Utility::getEnvironmentSize(const std::map<std::string, std::string> &envMap, int &totalEnvSize, int &totalEnvArgs)
{
	// get env size
	if (!envMap.empty())
	{
		auto it = envMap.begin();
		while (it != envMap.end())
		{
			totalEnvSize += (int)(it->first.length() + it->second.length() + 2); // add for = and terminator
			totalEnvArgs++;
			it++;
		}
	}

	// initialize our environment size estimates
	constexpr int numEntriesConst = 256;
	constexpr int bufferSizeConst = 4 * 1024;

	totalEnvArgs += numEntriesConst;
	totalEnvSize += bufferSizeConst;
}

void Utility::applyFilePermission(const std::string &file, const std::map<std::string, std::string> &headers)
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

std::string Utility::prettyJson(const std::string &jsonStr)
{
	return nlohmann::json::parse(jsonStr).dump(2, ' ');
}

std::string Utility::hash(const std::string &str)
{
	return std::string("H") + std::to_string(std::hash<std::string>()(str));
}

std::string Utility::hashId()
{
	// https://github.com/schoentoon/hashidsxx
	static const auto salt = generatePassword(6, true, true, false, false);
	static hashidsxx::Hashids hash(salt, 10);
	static std::atomic_int index(1000);
	return hash.encode(++index);
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
	return boost::program_options::split_unix(commandLine);
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
#ifndef _WIN32
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
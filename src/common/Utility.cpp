#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <queue>
#include <string>
#include <sstream>
#include <stdarg.h>

#include <thread>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

#include <log4cpp/Category.hh>
#include <log4cpp/Appender.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/Priority.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/OstreamAppender.hh>
#include <ace/OS.h>
#include <ace/UUID.h>

#include "../common/Utility.h"

const char* GET_STATUS_STR(unsigned int status)
{
	static const char* STATUS_STR[] =
	{
		"disabled",
		"enabled",
		"N/A",
		"init",
		"fini"
	};
	assert(status < ARRAY_LEN(STATUS_STR));
	return STATUS_STR[status];
};

Utility::Utility()
{
}

Utility::~Utility()
{
}

bool Utility::isNumber(std::string s)
{
	return !s.empty() && std::find_if(s.begin(), s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
}

std::string Utility::stdStringTrim(const std::string& str)
{
	char* line = const_cast <char*> (str.c_str());
	// trim the line on the left and on the right
	std::size_t len = str.length();
	std::size_t start = 0;
	while (isspace(*line))
	{
		++line;
		--len;
		++start;
	}
	while (len > 0 && isspace(line[len - 1]))
	{
		--len;
	}
	return len >= start ? str.substr(start, len) : str.substr(start);
}

std::string Utility::stdStringTrim(const std::string& str, char trimChar, bool trimStart, bool trimEnd)
{
	char* line = const_cast <char*> (str.c_str());
	// trim the line on the left and on the right
	std::size_t len = str.length();
	std::size_t start = 0;
	while (trimStart && trimChar == (*line))
	{
		++line;
		--len;
		++start;
	}
	while (trimEnd && len > 0 && trimChar == (line[len - 1]))
	{
		--len;
	}
	return len >= start ? str.substr(start, len) : str.substr(start);
}

std::string Utility::getSelfFullPath()
{
	const static char fname[] = "Utility::getSelfFullPath() ";
#if	defined(WIN32)
	char buf[MAX_PATH] = { 0 };
	::GetModuleFileNameA(NULL, buf, MAX_PATH);
	// Remove ".exe"
	std::size_t idx = 0;
	while (buf[idx] != '\0')
	{
		if (buf[idx] == '.' && buf[idx + 1] == 'e' && buf[idx + 2] == 'x' && buf[idx + 3] == 'e')
		{
			buf[idx] = '\0';
		}
	}
#else
#define MAX_PATH PATH_MAX
	char buf[MAX_PATH] = { 0 };
	int count = (int)readlink("/proc/self/exe", buf, MAX_PATH);
	if (count < 0 || count >= MAX_PATH)
	{
		LOG_ERR << fname << "unknown exception";
		buf[0] = '\0';
	}
	else
	{
		buf[count] = '\0';
	}
#endif
	return buf;
}

std::string Utility::getSelfDir()
{
	auto path = getSelfFullPath();
	auto index = path.rfind(ACE_DIRECTORY_SEPARATOR_CHAR);
	if (index != std::string::npos)
	{
		path[index] = '\0';
	}
	return path;
}

bool Utility::isDirExist(std::string path)
{
#if defined (WIN32)
	DWORD dwAttrib = GetFileAttributes(path.c_str());
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
#else
	struct stat pathStat;
	return (::stat(path.c_str(), &pathStat) == 0 && S_ISDIR(pathStat.st_mode));
#endif
}

bool Utility::isFileExist(std::string path)
{
	return (::access(path.c_str(), F_OK) == 0);
}

bool Utility::createDirectory(const std::string& path, mode_t mode)
{
	const static char fname[] = "Utility::createDirectory() ";

	if (!isDirExist(path))
	{
		if (mkdir(path.c_str(), mode) < 0)
		{
			LOG_ERR << fname << "Create directory <" << path << "> failed with error: " << std::strerror(errno);
			return false;
		}
	}
	return true;
}

bool Utility::createRecursiveDirectory(const std::string& path, mode_t mode)
{
	// TODO: on windows, path can both contain '/' and '\'
	auto dirVec = splitString(path, "/");
	std::string pstr;
	if (path.length() && path[0] == '/') pstr = "/";
	for (auto str : dirVec)
	{
		if (str.length() == 0) continue;
		pstr += str;
		pstr += "/";
		if (!createDirectory(pstr, mode))
		{
			return false;
		}
	}
	return true;
}

bool Utility::removeDir(const std::string& path)
{
	const static char fname[] = "Utility::removeDir() ";

	if (isDirExist(path))
	{
		if (rmdir(path.c_str()) == 0)
		{
			LOG_INF << fname << "Removed directory : " << path;
		}
		else
		{
			LOG_WAR << fname << "Failed to remove directory : " << path;
			return false;
		}
	}
	return true;
}

void Utility::removeFile(const std::string& path)
{
	const static char fname[] = "Utility::removeFile() ";

	if (path.length() && isFileExist(path))
	{
		if (ACE_OS::unlink(path.c_str()) != 0)
		{
			LOG_WAR << fname << "removed stdout file <" << path << "> failed with error: " << std::strerror(errno);
		}
		else
		{
			LOG_DBG << fname << "file  <" << path << "> removed";
		}
	}
}

void Utility::initLogging()
{
	using namespace log4cpp;

	auto logDir = Utility::stringFormat("%s/%s", Utility::getSelfDir().c_str(), "log");
	createDirectory(logDir, 00655);
	auto consoleLayout = new PatternLayout();
	consoleLayout->setConversionPattern("%d [%t] %p %c: %m%n");
	auto consoleAppender = new OstreamAppender("console", &std::cout);
	consoleAppender->setLayout(consoleLayout);

	//RollingFileAppender(const std::string&name, const std::string&fileName,
	//	std::size_tmaxFileSize = 10 * 1024 * 1024, unsigned intmaxBackupIndex = 1,
	//	boolappend = true, mode_t mode = 00644);
	auto rollingFileAppender = new RollingFileAppender(
		"rollingFileAppender",
		logDir.append("/appsvc.log"),
		20 * 1024 * 1024,
		5,
		true,
		00664);

	auto pLayout = new PatternLayout();
	pLayout->setConversionPattern("%d [%t] %p %c: %m%n");
	rollingFileAppender->setLayout(pLayout);

	Category& root = Category::getRoot();
	root.addAppender(rollingFileAppender);
	root.addAppender(consoleAppender);

	// Log level
	std::string levelEnv = "INFO";
	auto env = getenv("LOG_LEVEL");
	if (env != nullptr) levelEnv = env;
	setLogLevel(levelEnv);

	LOG_INF << "Logging process ID:" << getpid();
}

bool Utility::setLogLevel(const std::string& level)
{
	std::map<std::string, log4cpp::Priority::PriorityLevel> levelMap = {
		{ "NOTSET", log4cpp::Priority::NOTSET },
		{ "DEBUG", log4cpp::Priority::DEBUG },
		{ "INFO", log4cpp::Priority::INFO },
		{ "NOTICE", log4cpp::Priority::NOTICE },
		{ "WARN", log4cpp::Priority::WARN },
		{ "ERROR", log4cpp::Priority::ERROR },
		{ "CRIT", log4cpp::Priority::CRIT },
		{ "ALERT", log4cpp::Priority::ALERT },
		{ "FATAL", log4cpp::Priority::FATAL },
		{ "EMERG", log4cpp::Priority::EMERG }
	};

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
	std::string stid = oss.str();
	return std::stoull(stid);
}

std::chrono::system_clock::time_point Utility::convertStr2Time(const std::string& strTime)
{
	// compatibility with rfc3339 date format
	std::string time = strTime;
	for (std::size_t i = 0; i < time.length(); i++)
	{
		if ('T' == time[i]) time[i] = ' ';
	}

	struct tm tm_ = { 0 };
	int year, month, day, hour, minute, second;
	month = day = 1;
	hour = minute = second = 0;
	// "%Y-%m-%d %H:%M:%S"
	sscanf(time.c_str(), "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second);
	tm_.tm_year = year - 1900;
	tm_.tm_mon = month - 1;
	tm_.tm_mday = day;
	tm_.tm_hour = hour;
	tm_.tm_min = minute;
	tm_.tm_sec = second;
	tm_.tm_isdst = -1;

	return std::chrono::system_clock::from_time_t(std::mktime(&tm_));
}

std::string Utility::convertTime2Str(const std::chrono::system_clock::time_point& time)
{
	char buff[70] = { 0 };
	// put_time is not ready when gcc version < 5
	auto timet = std::chrono::system_clock::to_time_t(time);
	std::tm timetm;
	::localtime_r(&timet, &timetm);
	strftime(buff, sizeof(buff), DATE_TIME_FORMAT, &timetm);
	return std::string(buff);
}

std::chrono::system_clock::time_point Utility::convertStr2DayTime(const std::string& strTime)
{
	struct tm tm_ = { 0 };

	char* str = (char*)strTime.data();
	int hour, minute, second;
	// "%H:%M:%S"
	sscanf(str, "%d:%d:%d", &hour, &minute, &second);
	tm_.tm_year = 2000 - 1900;
	tm_.tm_mon = 1;
	tm_.tm_mday = 17;
	tm_.tm_hour = hour;
	tm_.tm_min = minute;
	tm_.tm_sec = second;
	tm_.tm_isdst = -1;
	return std::chrono::system_clock::from_time_t(std::mktime(&tm_));
}

std::string Utility::convertDayTime2Str(const std::chrono::system_clock::time_point& time)
{
	char buff[70] = { 0 };
	// put_time is not ready when gcc version < 5
	auto timet = std::chrono::system_clock::to_time_t(time);
	std::tm timetm;
	::localtime_r(&timet, &timetm);
	strftime(buff, sizeof(buff), "%H:%M:%S", &timetm);
	return std::string(buff);
}

std::string Utility::getSystemPosixTimeZone()
{
	// https://stackoverflow.com/questions/2136970/how-to-get-the-current-time-zone/28259774#28259774
	struct tm local_tm;
	time_t cur_time = 0; // time(NULL);
	ACE_OS::localtime_r(&cur_time, &local_tm);

	char buff[70] = { 0 };
	strftime(buff, sizeof(buff), "%Z%z", &local_tm);
	std::string str = buff;

	// remove un-used zero post-fix : 
	// CST+0800  => CST+08
	auto len = str.length();
	for (std::size_t i = len - 1; i > 0; i--)
	{
		if (str[i] == '0')
		{
			str[i] = '\0';
		}
		else
		{
			str = str.c_str();
			break;
		}
	}
	return str;
}

std::string Utility::getRfc3339Time(const std::chrono::system_clock::time_point& time)
{
	// https://blog.csdn.net/qq_27274871/article/details/83414306
	// https://stackoverflow.com/questions/54325137/c-rfc3339-timestamp-with-milliseconds-using-stdchrono
	const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count() % 1000;
	std::stringstream ss;
	ss << formatTime(time, "%FT%T") << '.' << std::setfill('0') << std::setw(3) << millis << 'Z';
	return ss.str();
}

std::string Utility::formatTime(const std::chrono::system_clock::time_point& time, const char* fmt)
{
	const static char fname[] = "Utility::getFmtTimeSeconds() ";

	struct tm localtime;
	time_t timtt = std::chrono::system_clock::to_time_t(time);
	ACE_OS::localtime_r(&timtt, &localtime);

	char buff[64] = { 0 };
	if (!strftime(buff, sizeof(buff), fmt, &localtime))
	{
		LOG_ERR << fname << "strftime failed with error : " << std::strerror(errno);
	}
	return buff;
}

std::string Utility::encode64(const std::string& val)
{
	using namespace boost::archive::iterators;
	using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
	auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
	return tmp.append((3 - val.size() % 3) % 3, '=');
}

std::string Utility::decode64(const std::string& val)
{
	using namespace boost::archive::iterators;
	using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
	return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(val)), It(std::end(val))), [](char c) {
		return c == '\0';
		});
}

std::string Utility::readFile(const std::string& path)
{
	const static char fname[] = "Utility::readFile() ";

	FILE* file = ::fopen(path.c_str(), "r");
	if (nullptr == file)
	{
		LOG_ERR << fname << "Get file <" << path << "> failed with error : " << std::strerror(errno);
		return "";
	}

	// Use a buffer to read the file in BUFSIZ
	// chunks and append it to the string we return.
	//
	// NOTE: We aren't able to use fseek() / ftell() here
	// to find the file size because these functions don't
	// work properly for in-memory files like /proc/*/stat.
	char* buffer = new char[BUFSIZ];
	std::string result;

	while (true) {
		std::size_t read = ::fread(buffer, 1, BUFSIZ, file);

		if (::ferror(file)) {
			// NOTE: ferror() will not modify errno if the stream
			// is valid, which is the case here since it is open.
			LOG_ERR << fname << "fread failed with error : " << std::strerror(errno);
			delete[] buffer;
			::fclose(file);
			return "";
		}

		result.append(buffer, read);

		if (read != BUFSIZ) {
			assert(feof(file));
			break;
		}
	};

	::fclose(file);
	delete[] buffer;
	return result;
}

std::string Utility::readFileCpp(const std::string& path)
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
	return std::move(str);
}

std::string Utility::createUUID()
{
	static bool initialized = false;
	if (!initialized)
	{
		ACE_Utils::UUID_GENERATOR::instance()->init();
		initialized = true;
	}
	ACE_Utils::UUID uuid;
	ACE_Utils::UUID_GENERATOR::instance()->generate_UUID(uuid);
	auto str = std::string(uuid.to_string()->c_str());
	return std::move(str);
}

std::string Utility::runShellCommand(std::string cmd)
{
	const static char fname[] = "Utility::runShellCommand() ";

	constexpr int LINE_LENGTH = 300;
	char line[LINE_LENGTH];
	std::stringstream stdoutMsg;
	cmd += " 2>&1"; // include stderr
	FILE* fp = popen(cmd.c_str(), "r");
	LOG_INF << fname << cmd;
	if (fp)
	{
		std::queue<std::string> msgQueue;
		while (fgets(line, LINE_LENGTH, fp) != nullptr)
		{
			msgQueue.push(line);
			if (msgQueue.size() > 512) msgQueue.pop();
		}
		pclose(fp);
		while (msgQueue.size())
		{
			stdoutMsg << msgQueue.front();
			msgQueue.pop();
		}
	}
	auto str = std::string(stdoutMsg.str());
	return std::move(str);
}

void Utility::trimLineBreak(std::string& str)
{
	str = stdStringTrim(str, '\r');
	str = stdStringTrim(str, '\n');
}

std::vector<std::string> Utility::splitString(const std::string& source, const std::string& splitFlag)
{
	std::vector<std::string> result;
	std::string::size_type pos1, pos2;
	pos2 = source.find(splitFlag);
	pos1 = 0;
	while (std::string::npos != pos2)
	{
		std::string str = stdStringTrim(source.substr(pos1, pos2 - pos1));
		if (str.length() > 0) result.push_back(str);

		pos1 = pos2 + splitFlag.size();
		pos2 = source.find(splitFlag, pos1);
	}
	if (pos1 != source.length())
	{
		std::string str = stdStringTrim(source.substr(pos1));
		if (str.length() > 0) result.push_back(str);
	}
	return std::move(result);
}

bool Utility::startWith(const std::string& big, const std::string& small)
{
	// https://luodaoyi.com/p/cpp-std-startwith-endwith.html
	if (&big == &small) return true;
	const std::string::size_type big_size = big.size();
	const std::string::size_type small_size = small.size();
	const bool valid_ = (big_size >= small_size);
	const bool starts_with_ = (big.compare(0, small_size, small) == 0);
	return valid_ && starts_with_;
}

bool Utility::endWith(const std::string& big, const std::string& small)
{
	if (&big == &small) return true;
	const std::string::size_type big_size = big.size();
	const std::string::size_type small_size = small.size();
	const bool valid_ = (big_size >= small_size);
	const bool ends_with_ = (big.compare(big_size - small_size, small_size, small) == 0);
	return valid_ && ends_with_;
}

std::string Utility::stringReplace(const std::string& strBase, const std::string& strSrc, const std::string& strDst)
{
	std::string str = strBase;
	std::string::size_type position = 0;
	std::string::size_type srcLen = strSrc.size();
	std::string::size_type dstLen = strDst.size();

	while ((position = str.find(strSrc, position)) != std::string::npos)
	{
		str.replace(position, srcLen, strDst);
		position += dstLen;
	}
	return std::move(str);
}

std::string Utility::humanReadableSize(long double bytesSize)
{
	const static int base = 1024;
	//const static char* fmt[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
	const static char* fmt[] = { "B", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi" };

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
	char buffer[64] = { 0 };
	sprintf(buffer, "%.1Lf %s", n, fmt[units]);
	std::string str = buffer;
	return std::move(stringReplace(str, ".0", ""));
}

bool Utility::getUid(std::string userName, unsigned int& uid, unsigned int& groupid)
{
	bool rt = false;
	struct passwd pwd;
	struct passwd* result = NULL;
	static auto bufsize = ACE_OS::sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1) bufsize = 16384;
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

void Utility::getEnvironmentSize(const std::map<std::string, std::string>& envMap, int& totalEnvSize, int& totalEnvArgs)
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

std::string Utility::prettyJson(const std::string& jsonStr)
{
	// https://github.com/KrzysztofSzewczyk/json-beautifier/blob/master/beautify.c
	std::ostringstream result;
	std::stringstream stream;
	stream << jsonStr;

	const char ident = '\t';
	std::size_t level = 0;
	char c;
	bool ignore_next = false, in_string = false;

	while (!stream.eof() && stream.get(c))
	{
		switch (c)
		{
		case '[':
		case '{':
			result << (c);
			if (!in_string)
			{
				++level;
				result << ('\n');
				for (std::size_t i = 0; i < level; i++)
					result << (ident);
			}
			break;
		case ']':
		case '}':
			if (!in_string)
			{
				if (level != 0)
					level--;
				result << ('\n');
				for (std::size_t i = 0; i < level; i++)
					result << (ident);
			}
			result << (c);
			break;
		case ',':
			result << (c);
			if (!in_string) {
				result << ('\n');
				for (std::size_t i = 0; i < level; i++)
					result << (ident);
			}
			break;
		case '\\':
			ignore_next = !ignore_next;
			result << (c);
			break;
		case '"':
			if (!ignore_next) in_string = !in_string;
			result << (c);
			break;
		case ' ':
			if (in_string) result << (c);
			break;
		case ':':
			result << (c);
			if (!in_string)	result << (' ');
			break;
		case '\r':
		case '\n':
			break;
		default:
			if (ignore_next) ignore_next = false;
			result << (c);
			break;
		}
	}
	return result.str();
}

std::string Utility::hash(const std::string& str)
{
	return std::move(std::to_string(std::hash<std::string>()(str)));
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

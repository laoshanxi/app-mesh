#include <string>
#include <algorithm>
#include <fstream>
#ifdef _WIN32
#include <process.h>
#include <Windows.h>
#else
#include <pwd.h>
#endif
#include <thread>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.

#include <log4cpp/Category.hh>
#include <log4cpp/Appender.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/Priority.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/OstreamAppender.hh>

#include "../common/Utility.h"

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

std::string Utility::stdStringTrim(const std::string & str)
{
	char *line = const_cast <char *> (str.c_str());
	// trim the line on the left and on the right
	size_t len = str.length();
	size_t start = 0;
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

std::string Utility::stdStringTrim(const std::string &str, char trimChar, bool trimStart, bool trimEnd)
{
	char *line = const_cast <char *> (str.c_str());
	// trim the line on the left and on the right
	size_t len = str.length();
	size_t start = 0;
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
	size_t idx = 0;
	while (buf[idx] != '\0')
	{
		if (buf[idx] == '.' && buff[idx + 1] == 'e' && buff[idx + 2] == 'x' && buff[idx + 3] == 'e')
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
	}
	else
	{
		buf[count] = '\0';
	}
#endif
	return buf;
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

bool Utility::createDirectory(const std::string & path, mode_t mode)
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

bool Utility::createRecursiveDirectory(const std::string & path, mode_t mode)
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
		if (!createDirectory(pstr))
		{
			return false;
		}
	}
	return true;
}

bool Utility::removeDir(const std::string & path)
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

void Utility::initLogging()
{
	using namespace log4cpp;

	createDirectory("./log", 00655);
	auto consoleLayout = new PatternLayout();
	consoleLayout->setConversionPattern("%d [%t] %p %c: %m%n");
	auto consoleAppender = new OstreamAppender("console", &std::cout);
	consoleAppender->setLayout(consoleLayout);

	//RollingFileAppender(const std::string&name, const std::string&fileName,
	//	size_tmaxFileSize = 10 * 1024 * 1024, unsigned intmaxBackupIndex = 1,
	//	boolappend = true, mode_t mode = 00644);
	auto rollingFileAppender = new RollingFileAppender(
		"rollingFileAppender",
		"log/appsvc.log",
		20 * 1024 * 1024,
		5,
		true,
		00664);
	
	auto pLayout = new PatternLayout();
	pLayout->setConversionPattern("%d [%t] %p %c: %m%n");
	rollingFileAppender->setLayout(pLayout);

	Category & root = Category::getRoot();
	root.addAppender(rollingFileAppender);
	root.addAppender(consoleAppender);
	
	// Log level
	std::string levelEnv = "INFO";
	auto env = getenv("LOG_LEVEL");
	if (env != nullptr) levelEnv = env;
	setLogLevel(levelEnv);

	LOG_INF << "Logging process ID:" << getpid();
}

void Utility::setLogLevel(const std::string & level)
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

	if (level.length()> 0 && levelMap.find(level) != levelMap.end())
	{
		LOG_INF << "Setting log level to " << level;
		log4cpp::Category::getRoot().setPriority(levelMap[level]);
	}
}

unsigned long long Utility::getThreadId()
{
	std::ostringstream oss;
	oss << std::this_thread::get_id();
	std::string stid = oss.str();
	return std::stoull(stid);
}

std::chrono::system_clock::time_point Utility::convertStr2Time(const std::string & strTime)
{
	char *str = (char*)strTime.data();
	struct tm tm_ = { 0 };
	int year, month, day, hour, minute, second;
	// "%Y-%m-%d %H:%M:%S"
	sscanf(str, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second);
	tm_.tm_year = year - 1900;
	tm_.tm_mon = month - 1;
	tm_.tm_mday = day;
	tm_.tm_hour = hour;
	tm_.tm_min = minute;
	tm_.tm_sec = second;
	tm_.tm_isdst = -1;

	return std::chrono::system_clock::from_time_t(std::mktime(&tm_));
}

std::string Utility::convertTime2Str(const std::chrono::system_clock::time_point & time)
{
	char buff[70] = { 0 };
	// put_time is not ready when gcc version < 5
	auto timet = std::chrono::system_clock::to_time_t(time);
	std::tm timetm = *std::localtime(&timet);
	strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", &timetm);
	return std::string(buff);
}

std::chrono::system_clock::time_point Utility::convertStr2DayTime(const std::string & strTime)
{
	struct tm tm_ = { 0 };

	char *str = (char*)strTime.data();
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

std::string Utility::convertDayTime2Str(const std::chrono::system_clock::time_point & time)
{
	char buff[70] = { 0 };
	// put_time is not ready when gcc version < 5
	auto timet = std::chrono::system_clock::to_time_t(time);
	std::tm timetm = *std::localtime(&timet);
	strftime(buff, sizeof(buff), "%H:%M:%S", &timetm);
	return std::string(buff);
}

std::string Utility::getSystemPosixTimeZone()
{
	// https://stackoverflow.com/questions/2136970/how-to-get-the-current-time-zone/28259774#28259774
	struct tm local_tm;
	time_t cur_time = 0; // time(NULL);
	localtime_r(&cur_time, &local_tm);

	char buff[70] = { 0 };
	strftime(buff, sizeof(buff), "%Z%z", &local_tm);
	std::string str = buff;

	// remove un-used zero post-fix : 
	// CST+0800  => CST+08
	auto len = str.length();
	for (size_t i = len - 1; i > 0; i--)
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

std::string Utility::encode64(const std::string & val)
{
	using namespace boost::archive::iterators;
	using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
	auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
	return tmp.append((3 - val.size() % 3) % 3, '=');
}

std::string Utility::decode64(const std::string & val)
{
	using namespace boost::archive::iterators;
	using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
	return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(val)), It(std::end(val))), [](char c) {
		return c == '\0';
	});
}

std::string Utility::readFile(const std::string & path)
{
	const static char fname[] = "Utility::readFile() ";

	FILE* file = ::fopen(path.c_str(), "r");
	if (nullptr == file)
	{
		LOG_ERR << fname << "Get file stream failed with error : " << std::strerror(errno);
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
		size_t read = ::fread(buffer, 1, BUFSIZ, file);

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

std::string Utility::readFileCpp(const std::string & path)
{
	const static char fname[] = "Utility::readFileCPP() ";

	if (!Utility::isFileExist(path))
	{
		LOG_ERR << fname << "File not exist :" << path;
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
	static boost::uuids::random_generator generator;
	boost::uuids::uuid uuid1 = generator();
	return boost::uuids::to_string(uuid1);
}

std::vector<std::string> Utility::splitString(const std::string & source, const std::string & splitFlag)
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

bool Utility::startWith(const std::string & str, std::string head)
{
	if (str.length() >= head.length())
	{
		return (str.compare(0, head.size(), head) == 0);
	}
	return false;
}

std::string Utility::stringReplace(const std::string &strBase, const std::string& strSrc, const std::string& strDst)
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
	return str;
}

std::string Utility::humanReadableSize(long double bytesSize)
{
	const static int base = 1024;
	//const static char* fmt[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
	const static char* fmt[] = { "B", "K", "M", "G", "T", "P", "E", "Z", "Y" };

	if (bytesSize == 0)
	{
		return "0";
	}

	size_t units = 0;
	long double n = bytesSize;
	while (n > base && units + 1 < sizeof(fmt) / sizeof(*fmt))
	{
		units++;
		n /= base;
	}
	char buffer[64] = { 0 };
	sprintf(buffer, "%.1Lf %s ", n, fmt[units]);
	std::string str = buffer;
	return std::move(stringReplace(str, ".0", ""));
}

bool Utility::getUid(std::string userName, unsigned int& uid, unsigned int& groupid)
{
	bool rt = false;
	struct passwd pwd;
	struct passwd *result = NULL;
	static auto bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1) bufsize = 16384;
	std::shared_ptr<char> buff(new char[bufsize], std::default_delete<char[]>());
	getpwnam_r(userName.c_str(), &pwd, buff.get(), bufsize, &result);
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

void Utility::getEnvironmentSize(const std::map<std::string, std::string>& envMap, int & totalEnvSize, int & totalEnvArgs)
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
	const int numEntriesConst = 256;
	const int bufferSizeConst = 4 * 1024;

	totalEnvArgs += numEntriesConst;
	totalEnvSize += bufferSizeConst;
}

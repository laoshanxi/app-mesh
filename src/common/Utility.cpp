#include <atomic>
#include <errno.h>
#include <fstream>
#include <list>
#include <string>
#include <sys/file.h>
#include <thread>

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

const char *GET_STATUS_STR(unsigned int status)
{
	static const char *STATUS_STR[] =
		{
			"disabled",
			"enabled",
			"N/A",
			"init",
			"fini"};
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
	// if the number is -123, just remove the first char to check left
	if (s.length() && s[0] == '-')
	{
		s = s.substr(1);
	}
	return !s.empty() && std::find_if(s.begin(), s.end(), [](char c)
									  { return !std::isdigit(c); }) == s.end();
}

std::string Utility::stdStringTrim(const std::string &str)
{
	char *line = const_cast<char *>(str.c_str());
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

std::string Utility::stdStringTrim(const std::string &str, char trimChar, bool trimStart, bool trimEnd)
{
	char *line = const_cast<char *>(str.c_str());
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

std::string Utility::stdStringTrim(const std::string &str, const std::string &trimChars, bool trimStart, bool trimEnd)
{
	std::string result = str;
	while (trimStart && result.length() >= trimChars.length() && 0 == strncmp(result.c_str(), trimChars.c_str(), trimChars.length()))
	{
		result = result.c_str() + trimChars.length();
	}

	while (trimEnd && result.length() >= trimChars.length() && 0 == strncmp(result.c_str() + (result.length() - trimChars.length()), trimChars.c_str(), trimChars.length()))
	{
		result[result.length() - trimChars.length()] = '\0';
		result = result.c_str();
	}

	return result;
}

const std::string Utility::getSelfFullPath()
{
	const static char fname[] = "Utility::getSelfFullPath() ";
#if defined(WIN32)
	char buf[MAX_PATH] = {0};
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
	char buf[PATH_MAX] = {0};
	auto count = ACE_OS::readlink("/proc/self/exe", buf, PATH_MAX);
	if (count < 0 || count >= PATH_MAX)
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

const std::string &Utility::getSelfDir()
{
	static const auto selfBinDir = fs::path(getSelfFullPath()).parent_path().string();
	return selfBinDir;
}

const std::string &Utility::getParentDir()
{
	static const auto homeDir = fs::path(getSelfDir()).parent_path().string();
	return homeDir;
}

// program_name from errno.h
extern char *program_invocation_short_name;
const std::string Utility::getBinaryName()
{
	return program_invocation_short_name;
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
		if (!fs::create_directory(directoryPath))
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

	if (isDirExist(path))
	{
		if (ACE_OS::rmdir(path.c_str()) == 0)
		{
			LOG_INF << fname << "Removed directory : " << path;
		}
		else
		{
			LOG_WAR << fname << "Remove directory <" << path << "> failed with error: " << std::strerror(errno);
			return false;
		}
	}
	return true;
}

void Utility::removeFile(const std::string &path)
{
	const static char fname[] = "Utility::removeFile() ";

	if (path.length() && isFileExist(path))
	{
		if (fs::remove(path))
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
	static bool result = (Utility::readFile("/proc/self/cgroup").find("/docker/") != std::string::npos);
	return result;
}

void Utility::initLogging(const std::string &name)
{
	using namespace log4cpp;

	auto logDir = fs::path(Utility::getParentDir()) / "log";
	createDirectory(logDir.string());
	auto consoleLayout = new PatternLayout();
	consoleLayout->setConversionPattern("%d [%t] %p %c: %m%n");
	auto consoleAppender = new OstreamAppender("console", &std::cout);
	consoleAppender->setLayout(consoleLayout);

	// RollingFileAppender(const std::string&name, const std::string&fileName,
	//	std::size_tmaxFileSize = 10 * 1024 * 1024, unsigned intmaxBackupIndex = 1,
	//	boolappend = true, mode_t mode = 00644);
	auto rollingFileAppender = new RollingFileAppender(
		"rollingFileAppender",
		logDir.operator/=(name + ".log").string(),
		20 * 1024 * 1024,
		5,
		true,
		00664);

	auto pLayout = new PatternLayout();
	pLayout->setConversionPattern("%d [%t] %p %c: %m%n");
	rollingFileAppender->setLayout(pLayout);

	Category &root = Category::getRoot();
	root.addAppender(rollingFileAppender);
	root.addAppender(consoleAppender);

	// Log level
	std::string levelEnv = "DEBUG";
	auto env = getenv("LOG_LEVEL");
	if (env != nullptr)
		levelEnv = env;
	setLogLevel(levelEnv);

	LOG_INF << "Logging process ID:" << getpid();
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
		LOG_WAR << fname << "File not exist :" << path;
		return std::string();
	}

	std::ifstream stdoutReadStream(path, ios::in);
	if (stdoutReadStream.is_open() && stdoutReadStream.good())
	{
		if (position && stdoutReadStream.seekg(0, std::ios_base::end) && *position > stdoutReadStream.tellg())
		{
			throw std::invalid_argument(Utility::stringFormat("Input invalid output position <%ld>", *position));
		}
		const std::ifstream::pos_type positionBegin = stdoutReadStream.tellg();
		// adjust read position
		std::stringstream buffer;
		if (position)
		{
			stdoutReadStream.seekg(*position);
		}
		else
		{
			stdoutReadStream.seekg(0, std::ios_base::beg);
		}
		// read to buffer
		if (maxSize > 0)
		{
			auto temp = make_shared_array<char>(maxSize);
			memset(temp.get(), '\0', maxSize);
			if (readLine)
			{
				stdoutReadStream.getline(temp.get(), maxSize);
			}
			else
			{
				stdoutReadStream.readsome(temp.get(), maxSize);
			}
			buffer << temp.get();
		}
		else if (maxSize == 0)
		{
			if (readLine)
			{
				std::string tmp;
				std::getline(stdoutReadStream, tmp);
				buffer << tmp;
			}
			else
			{
				buffer << stdoutReadStream.rdbuf();
			}
		}
		else // maxSize < 0
		{
			maxSize = -maxSize;
			// change to end for reverse read if the position is beginning
			if (position && *position == 0)
			{
				stdoutReadStream.seekg(0, std::ios_base::end);
			}

			auto temp = make_shared_array<char>(maxSize);
			memset(temp.get(), '\0', maxSize);

			if (readLine)
			{
				std::string strLine;
				long readSize = 0;
				while (stdoutReadStream.tellg() != positionBegin && ++readSize < maxSize)
				{
					char oneChar[1];
					stdoutReadStream.seekg(-1, ios::cur);
					stdoutReadStream.read(oneChar, 1);
					stdoutReadStream.seekg(-1, ios::cur);
					if (oneChar[0] == '\n')
					{
						break;
					}
					strLine.append(oneChar);
				}
				std::reverse(strLine.begin(), strLine.end());
				std::copy(strLine.begin(), strLine.end(), temp.get());
			}
			else
			{
				if (stdoutReadStream.tellg() > maxSize)
				{
					stdoutReadStream.seekg(-maxSize, ios::cur);
					stdoutReadStream.readsome(temp.get(), maxSize);
				}
				else
				{
					maxSize = stdoutReadStream.tellg();
					stdoutReadStream.seekg(0, std::ios_base::beg);
					stdoutReadStream.readsome(temp.get(), maxSize);
				}
			}
			buffer << temp.get();
		}

		if (position)
		{
			// read current position
			*position = stdoutReadStream.tellg();
		}
		stdoutReadStream.close();
		return buffer.str();
	}
	return std::string();
}

std::string Utility::createUUID()
{
	return hashId();
}

bool Utility::createPidFile()
{
	const static char fname[] = "Utility::createPidFile() ";

	// https://stackoverflow.com/questions/5339200/how-to-create-a-single-instance-application-in-c-or-c
	// https://stackoverflow.com/questions/65738650/c-create-a-pid-file-using-system-call
	auto fd = open(PID_FILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0666);
	if (fd < 0)
	{
		std::cout << fname << "Failed to create PID file:" << PID_FILE_PATH << " with error: " << std::strerror(errno) << std::endl;
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

void Utility::initDateTimeZone(bool writeLog)
{
	const std::string posixTimeZone = ACE_OS::getenv(ENV_APPMESH_POSIX_TIMEZONE) ? ACE_OS::getenv(ENV_APPMESH_POSIX_TIMEZONE) : "";
	const auto &zone = DateTime::initOutputFormatPosixZone(posixTimeZone);
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
		if (str.length() > 0)
			result.push_back(str);
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

bool Utility::getUid(std::string userName, unsigned int &uid, unsigned int &groupid)
{
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

std::string Utility::getOsUserName()
{
	static std::string userName;
	static std::atomic_flag lock = ATOMIC_FLAG_INIT;
	if (!lock.test_and_set())
	{
		struct passwd *pw_ptr;
		if ((pw_ptr = getpwuid(getuid())) != NULL)
		{
			userName = pw_ptr->pw_name;
		}
		else
		{
			throw std::runtime_error("Failed to get current user name");
		}
	}
	return userName;
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

std::string Utility::prettyJson(const std::string &jsonStr)
{
	return nlohmann::json::parse(jsonStr).dump(2, ' ');
}

std::string Utility::hash(const std::string &str)
{
	return std::to_string(std::hash<std::string>()(str));
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

std::string Utility::unEscape(const std::string &str)
{
	// https://github.com/microsoft/cpprestsdk/blob/master/Release/tests/common/UnitTestpp/src/XmlTestReporter.cpp#L52
	auto result = Utility::stringReplace(str, "&amp;", "&");
	result = Utility::stringReplace(result, "&lt;", "<");
	result = Utility::stringReplace(result, "&gt;", ">");
	result = Utility::stringReplace(result, "&apos;", "\'");
	result = Utility::stringReplace(result, "&quot;", "\"");
	result = Utility::stringReplace(result, "&#40;", "(");
	result = Utility::stringReplace(result, "&#41;", ")");

	result = Utility::stringReplace(result, "&#39;", "\'");
	return result;
}

std::vector<std::string> Utility::str2argv(const std::string &commandLine)
{
	// https://stackoverflow.com/questions/1511797/convert-string-to-argv-in-c
	// backup: https://stackoverflow.com/questions/1706551/parse-string-into-argv-argc
	return boost::program_options::split_unix(commandLine);
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

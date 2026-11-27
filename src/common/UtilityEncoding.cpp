// src/common/UtilityEncoding.cpp
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

#include <drogon/utils/Utilities.h>
#include <json/json.h>

#include "Utility.h"

std::string Utility::encode64(const std::string &val) { return drogon::utils::base64Encode(val); }

std::string Utility::decode64(const std::string &val) { return drogon::utils::base64Decode(val); }

std::string Utility::encodeURIComponent(const std::string &str)
{
	std::ostringstream escaped;
	escaped.fill('0');
	escaped << std::hex;

	for (char c : str)
	{
		// JavaScript's encodeURIComponent escapes all characters except:
		// A-Z a-z 0-9 - _ . ! ~ * ' ( )
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' ||
			c == ')')
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
			if (i + 2 < encoded.size() && std::isxdigit(static_cast<unsigned char>(encoded[i + 1])) &&
				std::isxdigit(static_cast<unsigned char>(encoded[i + 2])))
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

std::string Utility::decodeHeaderFilePath(const std::string &val)
{
	const static char fname[] = "Utility::decodeHeaderFilePath() ";
	if (val.find('%') == std::string::npos)
	{
		return val;
	}
	try
	{
		return decodeURIComponent(val);
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "malformed percent escape in header value, keep raw: " << e.what();
		return val;
	}
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

namespace
{
	// Encoding detection candidates in priority order, shared by all platforms:
	// Windows converts through the code page, POSIX through the iconv name.
	// GB18030 catches the 4-byte sequences strict GBK rejects and must precede
	// EUC-KR because glibc's EUC-KR accepts raw C1 control bytes. CP_ACP
	// (code page 0) has no portable POSIX equivalent and is skipped there.
	struct EncodingCandidate
	{
		unsigned int codepage;
		const char *iconvName;
	};

	const EncodingCandidate ENCODING_CANDIDATES[] = {
		{936, "GBK"},       // GBK/GB2312 (Simplified Chinese)
		{950, "BIG5"},      // Big5 (Traditional Chinese)
		{932, "SHIFT_JIS"}, // Shift-JIS (Japanese)
		{54936, "GB18030"}, // GB18030 (4-byte extensions GBK rejects)
		{949, "EUC-KR"},    // EUC-KR (Korean)
		{1252, "CP1252"},   // Windows-1252 (Western European)
		{1251, "CP1251"},   // Windows-1251 (Cyrillic)
		{0, nullptr}        // CP_ACP: system default ANSI code page (Windows only)
	};

#if !defined(_WIN32)
	// Outcome of one strict iconv conversion attempt.
	enum IconvOutcome
	{
		ICONV_REJECTED,  // invalid byte sequence: candidate does not match
		ICONV_ACCEPTED,  // whole buffer converted
		ICONV_SPLIT_TAIL // valid except an incomplete multi-byte tail (EINVAL)
	};

	// Convert input from fromCode to UTF-8 strictly (no //TRANSLIT): the first
	// invalid sequence rejects the candidate. On ICONV_SPLIT_TAIL output holds
	// the converted prefix and tailBytes the count of unconverted trailing bytes.
	IconvOutcome iconvToUtf8(const std::string &input, const char *fromCode, std::string &output, size_t &tailBytes)
	{
		output.clear();
		tailBytes = 0;

		iconv_t cd = iconv_open("UTF-8", fromCode);
		if (cd == reinterpret_cast<iconv_t>(-1))
		{
			return ICONV_REJECTED; // encoding unavailable on this system
		}

		// Every candidate maps one input byte to at most three UTF-8 bytes.
		std::string out(input.size() * 3 + 4, '\0');
// iconv's inbuf parameter is `char **` on glibc and Apple's SDK, but
// `const char **` on standalone GNU libiconv. Apple defines _LIBICONV_VERSION
// for compatibility while keeping the POSIX signature, so exclude it.
#if defined(_LIBICONV_VERSION) && !defined(__APPLE__) && !defined(__GLIBC__)
		const char *inPtr = input.data();
#else
		char *inPtr = const_cast<char *>(input.data());
#endif
		size_t inLeft = input.size();
		char *outPtr = &out[0];
		size_t outLeft = out.size();

		IconvOutcome outcome = ICONV_ACCEPTED;
		while (inLeft > 0)
		{
			if (iconv(cd, &inPtr, &inLeft, &outPtr, &outLeft) != static_cast<size_t>(-1))
			{
				break; // all input consumed
			}
			if (errno == EINVAL)
			{
				outcome = ICONV_SPLIT_TAIL;
				break;
			}
			if (errno != E2BIG)
			{
				outcome = ICONV_REJECTED;
				break;
			}
			// Should not happen with the 3x reserve; grow and continue.
			const size_t used = static_cast<size_t>(outPtr - &out[0]);
			out.resize(out.size() * 2);
			outPtr = &out[0] + used;
			outLeft = out.size() - used;
		}
		iconv_close(cd);

		if (outcome == ICONV_REJECTED)
		{
			return ICONV_REJECTED;
		}
		tailBytes = inLeft;
		out.resize(out.size() - outLeft);
		output.swap(out);
		return outcome;
	}

	// Length of the UTF-8 sequence starting at input[i] (0 for a stray byte or
	// a truncated tail), and whether its continuation bytes are valid.
	std::pair<size_t, bool> utf8SequenceAt(const std::string &input, size_t i)
	{
		const unsigned char lead = static_cast<unsigned char>(input[i]);
		size_t len = 0;
		if (lead < 0x80)
			len = 1;
		else if ((lead & 0xE0) == 0xC0)
			len = 2;
		else if ((lead & 0xF0) == 0xE0)
			len = 3;
		else if ((lead & 0xF8) == 0xF0)
			len = 4;
		if (len == 0 || i + len > input.size())
			return {0, false};
		for (size_t j = 1; j < len; ++j)
		{
			if ((static_cast<unsigned char>(input[i + j]) & 0xC0) != 0x80)
				return {0, false};
		}
		return {len, true};
	}

	// Count of valid multi-byte sequences and the bytes they cover: evidence
	// that a buffer is UTF-8 text with stray binary bytes.
	std::pair<size_t, size_t> utf8MultibyteEvidence(const std::string &input)
	{
		size_t count = 0, covered = 0;
		for (size_t i = 0; i < input.size();)
		{
			const auto [len, valid] = utf8SequenceAt(input, i);
			if (len > 1 && valid)
			{
				++count;
				covered += len;
			}
			i += len > 0 ? len : 1;
		}
		return {count, covered};
	}

	// Keep valid UTF-8 and replace each stray byte with U+FFFD.
	std::string utf8ReplaceInvalid(const std::string &input)
	{
		std::string out;
		out.reserve(input.size());
		for (size_t i = 0; i < input.size();)
		{
			const auto [len, valid] = utf8SequenceAt(input, i);
			if (valid)
			{
				out.append(input, i, len);
				i += len;
			}
			else
			{
				out.append("\xEF\xBF\xBD");
				++i;
			}
		}
		return out;
	}

	// GBK and the other CJK code pages accept most high-byte pairs, CP1252
	// almost any byte string: a strict acceptance alone is weak evidence. When
	// at least two multi-byte UTF-8 sequences cover half the buffer, treat it
	// as UTF-8 text with stray bytes and replace only those, instead of
	// re-encoding everything into mojibake.
	bool utf8EvidenceBeatsCandidate(const std::string &input)
	{
		const auto [count, covered] = utf8MultibyteEvidence(input);
		return count >= 2 && covered * 2 >= input.size();
	}
#endif // !defined(_WIN32)
} // namespace

std::string Utility::fileBytesToUtf8(const std::string &input)
{
#ifdef _WIN32
	if (input.empty())
		return input;

	// Check for UTF-8 BOM
	if (input.size() >= 3 && static_cast<unsigned char>(input[0]) == 0xEF && static_cast<unsigned char>(input[1]) == 0xBB &&
		static_cast<unsigned char>(input[2]) == 0xBF)
	{
		return input.substr(3);
	}

	// Check for UTF-16 LE BOM
	if (input.size() >= 2 && static_cast<unsigned char>(input[0]) == 0xFF && static_cast<unsigned char>(input[1]) == 0xFE)
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
	if (input.size() >= 2 && static_cast<unsigned char>(input[0]) == 0xFE && static_cast<unsigned char>(input[1]) == 0xFF)
	{
		std::wstring wstr;
		wstr.resize((input.size() - 2) / 2);
		for (size_t i = 0; i < wstr.size(); ++i)
		{
			wstr[i] = static_cast<wchar_t>((static_cast<unsigned char>(input[2 + i * 2]) << 8) |
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

	// Try the shared encoding candidates in order of likelihood
	for (const EncodingCandidate &candidate : ENCODING_CANDIDATES)
	{
		std::string result = convertToUTF8(input, candidate.codepage);
		if (!result.empty())
		{
			return result;
		}
	}

	// If all else fails, return original
	return input;
#else
	if (input.empty())
		return input;

	// Check for UTF-8 BOM
	if (input.size() >= 3 && static_cast<unsigned char>(input[0]) == 0xEF && static_cast<unsigned char>(input[1]) == 0xBB &&
		static_cast<unsigned char>(input[2]) == 0xBF)
	{
		return input.substr(3);
	}

	// Check for UTF-16 BOM: convert complete 16-bit units (a trailing odd byte
	// is dropped, mirroring the Windows path); keep the original bytes when the
	// payload is not decodable.
	if (input.size() >= 2)
	{
		const bool utf16Le = static_cast<unsigned char>(input[0]) == 0xFF && static_cast<unsigned char>(input[1]) == 0xFE;
		const bool utf16Be = static_cast<unsigned char>(input[0]) == 0xFE && static_cast<unsigned char>(input[1]) == 0xFF;
		if (utf16Le || utf16Be)
		{
			const size_t units = (input.size() - 2) / 2;
			std::string converted;
			size_t tailBytes = 0;
			if (iconvToUtf8(input.substr(2, units * 2), utf16Le ? "UTF-16LE" : "UTF-16BE", converted, tailBytes) ==
					ICONV_ACCEPTED &&
				!converted.empty())
			{
				return converted;
			}
			return input;
		}
	}

	// Valid UTF-8 (includes pure ASCII) passes through unchanged: the common case
	if (isValidUTF8(input))
	{
		return input;
	}

	// A trailing incomplete UTF-8 character (a chunk boundary cut a character)
	// must not be re-detected as GBK below: the prefix is already correct UTF-8
	// and the tail bytes continue in the next chunk.
	const size_t tail = utf8IncompleteTailBytes(input);
	if (tail > 0 && isValidUTF8(input.substr(0, input.size() - tail)))
	{
		return input;
	}

	// Try the shared encoding candidates in order of likelihood: the first
	// candidate that converts strictly wins. A trailing incomplete multi-byte
	// sequence (EINVAL) means the chunk split a character: convert the complete
	// prefix and pass the tail bytes through unchanged for the next chunk.
	for (const EncodingCandidate &candidate : ENCODING_CANDIDATES)
	{
		if (candidate.iconvName == nullptr)
		{
			continue; // CP_ACP has no portable POSIX equivalent
		}
		std::string converted;
		size_t tailBytes = 0;
		const IconvOutcome outcome = iconvToUtf8(input, candidate.iconvName, converted, tailBytes);
		if (outcome == ICONV_ACCEPTED)
		{
			if (utf8EvidenceBeatsCandidate(input))
			{
				return utf8ReplaceInvalid(input);
			}
			return converted;
		}
		if (outcome == ICONV_SPLIT_TAIL)
		{
			return converted + input.substr(input.size() - tailBytes);
		}
	}

	// No candidate matched: keep the original bytes, JSON serialization replaces
	// invalid UTF-8 with U+FFFD.
	return input;
#endif
}

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
			if (i + 3 >= len || (bytes[i + 1] & 0xC0) != 0x80 || (bytes[i + 2] & 0xC0) != 0x80 ||
				(bytes[i + 3] & 0xC0) != 0x80)
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

size_t Utility::utf8LeadByteLength(unsigned char c)
{
	if (c >= 0xC2 && c <= 0xDF)
		return 2;
	if (c >= 0xE0 && c <= 0xEF)
		return 3;
	if (c >= 0xF0 && c <= 0xF4)
		return 4;
	return 0;
}

size_t Utility::utf8IncompleteTailBytes(const std::string &str)
{
	const size_t len = str.size();

	// Count trailing continuation bytes (0x80-0xBF), at most three.
	size_t run = 0;
	while (run < 3 && run < len && (static_cast<unsigned char>(str[len - 1 - run]) & 0xC0) == 0x80)
	{
		++run;
	}
	if (run == len)
	{
		return 0; // only continuation bytes: the lead byte is not in this buffer
	}

	const unsigned char lead = static_cast<unsigned char>(str[len - 1 - run]);
	// utf8LeadByteLength counts the lead byte too; the tail run needs len-1
	// continuation bytes to complete the character
	const size_t leadLength = utf8LeadByteLength(lead);
	return leadLength > 0 && run < leadLength - 1 ? run + 1 : 0;
}

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

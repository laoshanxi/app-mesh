// src/common/json.cpp
#include <memory>
#include <string>

#include "Utility.h"
#include "json.h"

namespace
{
	// Length of the UTF-8 sequence led by c, or 0 when c is not a valid lead
	// byte (continuation byte alone, C0/C1 overlong lead, or above U+10FFFF).
	size_t utf8LeadLength(unsigned char c)
	{
		if (c >= 0xC2 && c <= 0xDF)
			return 2;
		if (c >= 0xE0 && c <= 0xEF)
			return 3;
		if (c >= 0xF0 && c <= 0xF4)
			return 4;
		return 0;
	}

	// Strict UTF-8 validation for request bodies: C0/C1 leads, overlong forms,
	// surrogates and values above U+10FFFF are rejected. This is deliberately
	// stricter than Utility::isValidUTF8, which also feeds the stdout encoding
	// detection and accepts C0/C1 leads.
	bool isValidUtf8Strict(const std::string &text)
	{
		const auto *p = reinterpret_cast<const unsigned char *>(text.data());
		const size_t n = text.size();
		size_t i = 0;
		while (i < n)
		{
			const unsigned char c = p[i];
			if (c < 0x80)
			{
				++i;
				continue;
			}
			const size_t len = utf8LeadLength(c);
			if (len == 0 || i + len > n)
				return false;
			uint32_t cp = c & 0x0F;
			for (size_t k = 1; k < len; ++k)
			{
				if ((p[i + k] & 0xC0) != 0x80)
					return false;
				cp = (cp << 6) | (p[i + k] & 0x3F);
			}
			if (len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)))
				return false;
			if (len == 4 && (cp < 0x10000 || cp > 0x10FFFF))
				return false;
			i += len;
		}
		return true;
	}

	// Replace invalid UTF-8 with U+FFFD: each invalid run (bad lead byte, or a
	// lead with its continuation bytes) costs a single U+FFFD.
	std::string sanitizeUtf8(const std::string &input)
	{
		static const char UFFFD[] = "\xEF\xBF\xBD";
		const auto *p = reinterpret_cast<const unsigned char *>(input.data());
		const size_t n = input.size();
		std::string out;
		out.reserve(n);
		size_t i = 0;
		while (i < n)
		{
			const unsigned char c = p[i];
			if (c < 0x80)
			{
				out.push_back(static_cast<char>(c));
				++i;
				continue;
			}
			// Consume the lead byte plus any continuation bytes that follow
			const size_t len = utf8LeadLength(c);
			if (len == 0)
			{
				out.append(UFFFD);
				++i;
				continue;
			}
			size_t k = 1;
			while (k < len && i + k < n && (p[i + k] & 0xC0) == 0x80)
				++k;
			bool valid = k == len;
			if (valid)
			{
				uint32_t cp = c & 0x0F;
				for (size_t m = 1; m < len; ++m)
					cp = (cp << 6) | (p[i + m] & 0x3F);
				valid = !((len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) ||
						  (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)));
			}
			if (valid)
				out.append(input, i, len);
			else
				out.append(UFFFD);
			i += k;
		}
		return out;
	}
}

// Dump JSON to a valid UTF-8 string; invalid sequences become U+FFFD
std::string JSON::dump(const Json::Value &j, int indent)
{
	Json::StreamWriterBuilder builder;
	builder["commentStyle"] = "None";
	builder["indentation"] = indent < 0 ? std::string() : std::string(static_cast<size_t>(indent), ' ');
	builder["emitUTF8"] = true;
	// The writer passes invalid UTF-8 through raw with emitUTF8, so the output
	// is sanitized afterwards: a reply must never fail on bad argv or stdout.
	return sanitizeUtf8(Json::writeString(builder, j));
}

// Dump JSON converted to the current ANSI code page on Windows (CP_ACP).
// For POSIX platforms this returns the UTF-8 string unchanged.
std::string JSON::dumpToLocalEncoding(const Json::Value &j, int indent)
{
	const std::string utf8Str = JSON::dump(j, indent);
	return Utility::utf8ToLocalEncoding(utf8Str);
}

// Strict parse: rejects malformed JSON and invalid UTF-8
Json::Value JSON::parse(const std::string &text)
{
	std::string error;
	const auto result = JSON::parse(text, &error);
	if (!error.empty())
		throw std::invalid_argument("Invalid JSON: " + error);
	return result;
}

// Non-throwing parse: null value on failure, error text in *error
Json::Value JSON::parse(const std::string &text, std::string *error)
{
	if (error != nullptr)
		error->clear();
	if (!isValidUtf8Strict(text))
	{
		if (error != nullptr)
			*error = "invalid UTF-8 byte in input";
		return Json::Value();
	}

	Json::CharReaderBuilder builder;
	// No comments, no trailing commas, no extra content after the root value,
	// no NaN/Infinity: malformed request bodies stay a client fault (400).
	builder["collectComments"] = false;
	builder["allowComments"] = false;
	builder["allowTrailingCommas"] = false;
	builder["allowSpecialFloats"] = false;
	builder["failIfExtra"] = true;

	Json::Value root;
	std::string errs;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	// stackLimit exhaustion throws (Json::RuntimeError) instead of returning false
	bool ok = false;
	try
	{
		ok = reader->parse(text.data(), text.data() + text.size(), &root, &errs);
	}
	catch (const Json::Exception &e)
	{
		errs = e.what();
	}
	if (!ok)
	{
		if (error != nullptr)
			*error = errs;
		return Json::Value();
	}
	return root;
}

// RFC 7386 merge-patch: null deletes a member, objects merge recursively
void JSON::mergePatch(Json::Value &target, const Json::Value &patch)
{
	if (!patch.isObject())
	{
		target = patch;
		return;
	}
	if (!target.isObject())
		target = Json::Value(Json::objectValue);
	for (const auto &key : patch.getMemberNames())
	{
		const Json::Value &value = patch[key];
		if (value.isNull())
			target.removeMember(key);
		else if (value.isObject())
			mergePatch(target[key], value);
		else
			target[key] = value;
	}
}

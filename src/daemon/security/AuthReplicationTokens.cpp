#include "AuthReplicationTokens.h"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "../../common/Utility.h"

namespace AuthReplication
{
	std::vector<AcceptedToken> parseTokenFile(const std::string &fileContent)
	{
		std::vector<AcceptedToken> tokens;
		std::istringstream stream(fileContent);
		std::string line;
		while (std::getline(stream, line))
		{
			const auto trimmed = Utility::stdStringTrim(line);
			if (trimmed.empty() || trimmed.front() == '#')
				continue;
			const auto separator = trimmed.find_first_of(" \t");
			if (separator == std::string::npos)
				continue; // a line without a label is not an accepted entry
			auto label = Utility::stdStringTrim(trimmed.substr(separator));
			if (label.empty())
				continue;
			tokens.push_back({trimmed.substr(0, separator), label});
		}
		return tokens;
	}

	std::string matchToken(const std::vector<AcceptedToken> &tokens, const std::string &presented)
	{
		std::string matched;
		for (const auto &accepted : tokens)
		{
			// Length must match exactly: folding the size delta into the
			// unsigned-char diff would let sizes differing by a multiple of
			// 256 fall through to a prefix comparison.
			if (presented.size() != accepted.token.size())
				continue;
			volatile unsigned char diff = 0;
			for (size_t i = 0; i < presented.size(); ++i)
				diff |= static_cast<unsigned char>(presented[i]) ^ static_cast<unsigned char>(accepted.token[i]);
			if (diff == 0)
				matched = accepted.label;
		}
		return matched;
	}

	std::string matchToken(const std::string &fileContent, const std::string &presented)
	{
		return matchToken(parseTokenFile(fileContent), presented);
	}

	bool isValidLabel(const std::string &label)
	{
		return !label.empty() &&
			   std::all_of(label.begin(), label.end(), [](unsigned char c) {
				   return std::isalnum(c) || c == '.' || c == '_' || c == '-';
			   });
	}
} // namespace AuthReplication

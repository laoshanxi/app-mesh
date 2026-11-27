// src/daemon/application/AppUtils.cpp
#include "AppUtils.h"

#include <algorithm>
#include <stdexcept>

#include "../../common/Utility.h"

std::string normalizeAppName(const std::string &name)
{
	const auto normalized = Utility::stdStringTrim(name);
	const bool valid = !normalized.empty() && normalized.size() <= 128 &&
					   std::all_of(normalized.begin(), normalized.end(),
								   [](unsigned char value)
								   {
									   return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
											  (value >= '0' && value <= '9') || value == '_' || value == '-';
								   });
	if (!valid)
		throw std::invalid_argument("application name must be 1-128 characters using only letters, digits, '_' or '-'");
	return normalized;
}

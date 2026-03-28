// src/common/os/filesystem.cpp
// Platform-agnostic filesystem utilities.

#include "filesystem.h"

#include "../Utility.h"

namespace os
{

	bool chmod(const std::string &path, uint16_t mode)
	{
		const static char fname[] = "chmod() ";

		if (mode > 777)
		{
			LOG_WAR << fname << "Invalid shorthand mode value <" << mode << "> for chmod <" << path << ">";
			return false;
		}

		if (mode == 0)
		{
			LOG_WAR << fname << "Warning: mode 0 will remove all permissions for path <" << path << ">";
		}

		uint16_t mode_u = mode / 100;
		uint16_t mode_g = (mode / 10) % 10;
		uint16_t mode_o = mode % 10;
		uint16_t octalMode = (mode_u << 6) | (mode_g << 3) | mode_o;

		return fileChmod(path, octalMode);
	}

} // namespace os

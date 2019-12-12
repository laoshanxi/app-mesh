#pragma once

#include <string>

//#include "detail/core_export.h"

namespace prometheus {

bool CheckMetricName(const std::string& name);
bool CheckLabelName(const std::string& name);
}  // namespace prometheus

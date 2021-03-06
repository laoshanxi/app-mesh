#pragma once

#include <iosfwd>
#include <string>
#include <vector>

#include "detail/core_export.h"
#include "metric_family.h"

namespace prometheus {

class PROMETHEUS_CPP_CORE_EXPORT Serializer {
 public:
  virtual ~Serializer() = default;
  virtual std::string Serialize(const std::vector<MetricFamily>&) const;
  virtual void Serialize(std::ostream& out,
                         const std::vector<MetricFamily>& metrics) const = 0;
};

}  // namespace prometheus

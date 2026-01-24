#include "tests/thinkit/util.h"

#include <optional>
#include <string>

#include "absl/flags/flag.h"
#include "gutil/gutil/testing.h"

ABSL_FLAG(
    std::string, pins_p4info_file, "",
    "Path to the file containing the textproto of the P4Info to be pushed");

namespace pins_test {

std::optional<p4::config::v1::P4Info> GetP4InfoFromFlag() {
  std::string p4info_file = absl::GetFlag(FLAGS_pins_p4info_file);
  if (p4info_file.empty()) {
    return std::nullopt;
  }
  return gutil::ParseProtoFileOrDie<p4::config::v1::P4Info>(p4info_file);
}

}  // namespace pins_test

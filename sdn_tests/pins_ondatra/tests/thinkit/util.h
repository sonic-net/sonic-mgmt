#ifndef PINS_TESTS_UTIL_H_
#define PINS_TESTS_UTIL_H_

#include <optional>
#include <string>

#include "absl/flags/declare.h"
#include "p4/config/v1/p4info.pb.h"

ABSL_DECLARE_FLAG(std::string, pins_p4info_file);

namespace pins_test {

// If the p4info_file flag is set, returns the P4Info from the file.
// Otherwise returns std::nullopt.
std::optional<p4::config::v1::P4Info> GetP4InfoFromFlag();

}  // namespace pins_test

#endif  // PINS_TESTS_UTIL_H_

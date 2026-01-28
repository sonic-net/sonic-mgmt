#include "tests/forwarding/configure_mirror_testbed_test.h"

#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "gutil/gutil/testing.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "p4/config/v1/p4info.pb.h"
#include "thinkit/mirror_testbed_fixture.h"

ABSL_FLAG(
    std::string, p4info_file, "",
    "Path to the file containing the textproto of the P4Info to be pushed");

namespace pins {
namespace {

ConfigureMirrorTestbedTestParams GetTestInstanceOrDie() {
  CHECK(!absl::GetFlag(FLAGS_p4info_file).empty())
      << "--p4info_file is required.";

  auto p4info = gutil::ParseProtoFileOrDie<p4::config::v1::P4Info>(
      absl::GetFlag(FLAGS_p4info_file));

  return ConfigureMirrorTestbedTestParams{
      .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
          pins::GetOndatraMirrorTestbedFixtureParams()->mirror_testbed),
      .sut_p4info = p4info,
      .control_switch_p4info = p4info,
  };
}

INSTANTIATE_TEST_SUITE_P(pinsOndatraConfigureMirrorTestbedTest,
                         ConfigureMirrorTestbedTestFixture,
                         testing::Values(GetTestInstanceOrDie()));

}  // namespace
}  // namespace pins

#include "tests/forwarding/arbitration_test.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "gtest/gtest.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/mirror_testbed_fixture.h"

ABSL_FLAG(
    std::string, p4info_file, "",
    "Path to the file containing the textproto of the P4Info to be pushed");

namespace pins {
namespace {

INSTANTIATE_TEST_SUITE_P(
    pinsArbitrationTest, ArbitrationTestFixture, testing::Values([]() {
      thinkit::MirrorTestbedFixtureParams mirror_testbed_params =
          *pins::GetOndatraMirrorTestbedFixtureParams();
      return ArbitrationTestParams{
          .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
              mirror_testbed_params.mirror_testbed),
          .gnmi_config = std::move(mirror_testbed_params.gnmi_config),
          .p4info = std::move(mirror_testbed_params.p4_info)};
    }()));

}  // namespace
}  // namespace pins

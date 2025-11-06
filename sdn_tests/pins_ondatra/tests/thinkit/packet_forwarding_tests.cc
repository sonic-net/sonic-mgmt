#include "tests/integration/system/packet_forwarding_tests.h"

#include <optional>

#include "glog/logging.h"
#include "gtest/gtest.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "tests/thinkit/util.h"
#include "thinkit/generic_testbed_fixture.h"

namespace pins_test {
namespace {

INSTANTIATE_TEST_SUITE_P(
    pinsPacketForwardingTest, PacketForwardingTestFixture,
    testing::Values([]() {
      absl::StatusOr<thinkit::GenericTestbedFixtureParams> params =
          pins::GetOndatraGenericTestbedFixtureParams();
      if (!params.ok()) {
        LOG(FATAL) << "Failed to fetch params, status: "  // Crash OK
                   << params.status();
      }
      std::optional<p4::config::v1::P4Info> p4_info =
          pins_test::GetP4InfoFromFlag();
      return PacketForwardingTestParams{
          .testbed_interface = params->testbed_interface,
          .push_p4_info = p4_info.has_value(),
          .p4_info = p4_info};
    }()));
}  // namespace
}  // namespace pins_test

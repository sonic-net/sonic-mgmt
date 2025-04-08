#include "tests/forwarding/arbitration_test.h"

#include <memory>

#include "gtest/gtest.h"
#include "infrastructure/thinkit/ondatra_params.h"

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

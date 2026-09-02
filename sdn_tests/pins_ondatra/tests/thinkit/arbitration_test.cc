#include "tests/forwarding/arbitration_test.h"

#include <memory>
#include <utility>

#include "glog/logging.h"
#include "gtest/gtest.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "p4/v1/p4runtime.pb.h"
#include "tests/thinkit/util.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins {
namespace {

INSTANTIATE_TEST_SUITE_P(
    pinsArbitrationTest, ArbitrationTestFixture, testing::Values([]() {
      absl::StatusOr<thinkit::MirrorTestbedFixtureParams> params =
          pins::GetOndatraMirrorTestbedFixtureParams();
      if (!params.ok()) {
        LOG(FATAL) << "Failed to fetch params, status: "  // Crash OK
                   << params.status();
      }
      return ArbitrationTestParams{
          .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
              params->mirror_testbed),
          .gnmi_config = std::move(params->gnmi_config),
          .p4info = pins_test::GetP4InfoFromFlag()};
    }()));

}  // namespace
}  // namespace pins

#include "tests/forwarding/l3_admit_test.h"

#include <utility>

#include "absl/log/log.h"
#include "absl/status/statusor.h"
#include "gtest/gtest.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "p4/v1/p4runtime.pb.h"
#include "tests/thinkit/util.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins {
namespace {

L3AdmitTestParams GetTestParamsOrDie() {
  absl::StatusOr<thinkit::MirrorTestbedFixtureParams> params =
      pins::GetOndatraMirrorTestbedFixtureParams();
  if (!params.ok()) {
    LOG(FATAL) << "Failed to fetch params, status: " << params.status();
  }
  return L3AdmitTestParams{
      .testbed_interface = std::move(params->mirror_testbed),
      .p4info = pins_test::GetP4InfoFromFlag().value()};
}

INSTANTIATE_TEST_SUITE_P(pinsL3AdmitTest, L3AdmitTestFixture,
                         testing::Values(GetTestParamsOrDie()));

}  // namespace
}  // namespace pins

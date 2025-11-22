#include "tests/forwarding/smoke_test.h"

#include <memory>

#include "gtest/gtest.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "tests/thinkit/util.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins_test {
namespace {
INSTANTIATE_TEST_SUITE_P(
    pinsSmokeTest, SmokeTestFixture,
    testing::Values(SmokeTestParams{
        .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
            pins::GetOndatraMirrorTestbedFixtureParams()
                .value()
                .mirror_testbed),
        .p4info = GetP4InfoFromFlag(),
        .does_not_support_gre_tunnels = true,
    }));
}  // namespace
}  // namespace pins_test

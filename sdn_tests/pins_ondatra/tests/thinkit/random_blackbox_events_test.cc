#include "absl/status/statusor.h"
#include "gtest/gtest.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "tests/integration/system/random_blackbox_events_tests.h"
#include "thinkit/generic_testbed_fixture.h"

namespace pins_test {
namespace {

INSTANTIATE_TEST_SUITE_P(
    pinsIntegrationTest, RandomBlackboxEventsTest,
    testing::Values(*pins::GetOndatraGenericTestbedFixtureParams()));

}  // namespace
}  // namespace pins_test

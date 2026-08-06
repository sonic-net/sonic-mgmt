#include <cstdlib>
#include <optional>
#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "gtest/gtest.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "tests/integration/system/random_blackbox_events_tests.h"
#include "thinkit/generic_testbed_fixture.h"

namespace pins_test {
namespace {

// TODO(PINS) - update this env variable based on the test environment
bool IsAlpineTestbed() { return std::getenv("pins_alpine_env") != nullptr; }

INSTANTIATE_TEST_SUITE_P(
    pinsIntegrationTest, RandomBlackboxEventsTest, testing::Values([] {
      thinkit::GenericTestbedFixtureParams params =
          *pins::GetOndatraGenericTestbedFixtureParams();
      return RandomBlackboxEventsTestParams{
          .testbed_interface = params.testbed_interface,
          .p4_info = std::nullopt,
          .fuzzer_config_params = {
              .qos_queues = {"0x0", "0x1", "0x2", "0x3", "0x4", "0x5", "0x6",
                             "0x7"},
              .role = "sdn_controller",
              .mutate_update_probability = 0.1f,
              .tables_for_which_to_not_exceed_resource_guarantees =
                  {"vrf_table", "mirror_session_table"},
              .disabled_fully_qualified_names =
              // TODO(PINS) - Remove once Alpine supports multicast
              IsAlpineTestbed()
                  ? absl::flat_hash_set<
                        std::string>{{"egress.packet_rewrites.multicast_"
                                      "rewrites.multicast_router_"
                                      "interface_table"}}
                  : absl::flat_hash_set<std::string>{},
              // TODO(PINS): Remove once P4RT translated types
              // are supported by P4-constraints.
              .ignore_constraints_on_tables =
                  {
                      "ingress.routing_lookup.vrf_table",
                  },
          }};
    }()));

}  // namespace
}  // namespace pins_test

#include "tests/forwarding/arriba_test.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/log/log.h"
#include "absl/time/time.h"
#include "dvaas/test_vector.pb.h"
#include "gtest/gtest.h"
#include "gutil/gutil/testing.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "thinkit/mirror_testbed_fixture.h"

ABSL_FLAG(std::vector<std::string>, arriba_test_vector_files, {},
          "Paths to files containing ArribaTestVector textprotos.");
ABSL_FLAG(double, expected_minimum_success_rate, 1.0,
          "Expected minimum success rate for the packet vectors.");
ABSL_FLAG(
    bool, wait_for_all_enabled_interfaces_to_be_up, true,
    "If true, waits for all enabled ports to be up on SUT and control switch.");
ABSL_FLAG(
    absl::Duration, max_expected_packet_in_flight_duration, absl::Seconds(3),
    R"(Maximum time expected it takes to receive output packets either from SUT
    or control switch in response to an injected input packet. Beyond that,
    the input packet might be considered dropped.)");
ABSL_FLAG(
    std::optional<int>, max_in_flight_packets, std::nullopt,
    R"(If provided, batches the packet injection and collection to control the
    number of packets in-flight. If this value is std::nullopt, then all packets
    are injected as one batch.)");
ABSL_FLAG(
    std::vector<std::string>, excluded_labels, {},
    R"(If provided, the test vectors with the given labels get excluded during
    validation. If this value is empty, then all test vectors are validated.)");
ABSL_FLAG(bool, enable_sut_packet_in_collection, true,
          R"(If false, does not collect packet-ins from SUT.)");
ABSL_FLAG(
    bool, skip_dataplane_validation, false,
    R"(If true, removes all test packets from the arriba test vector, effectively
    only checking that table entry programming is successful.)");

namespace pins_test {
namespace {

// Returns one test instance per test vector textproto file provided through the
// `--arriba_test_vector_files` flag.
absl::StatusOr<std::vector<ArribaTestParams>> GetTestInstances() {
  // Make sure there is at least one test vector present.
  if (absl::GetFlag(FLAGS_arriba_test_vector_files).empty()) {
    return absl::InvalidArgumentError(
        "--arriba_test_vector_files is required.");
  }

  ASSIGN_OR_RETURN(thinkit::MirrorTestbedFixtureParams mirror_testbed_params,
                   pins::GetOndatraMirrorTestbedFixtureParams());
  std::vector<std::string> excluded_labels =
      absl::GetFlag(FLAGS_excluded_labels);
  absl::flat_hash_set<std::string> excluded_labels_set(excluded_labels.begin(),
                                                       excluded_labels.end());

  std::vector<ArribaTestParams> test_instances;
  for (const std::string& test_vector_file :
       absl::GetFlag(FLAGS_arriba_test_vector_files)) {
    dvaas::ArribaTestVector arriba_test_vector;

    if (absl::GetFlag(FLAGS_skip_dataplane_validation)) {
      arriba_test_vector.clear_packet_test_vector_by_id();
    }

    test_instances.push_back(ArribaTestParams{
        .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
            mirror_testbed_params.mirror_testbed),
        .arriba_test_vector = arriba_test_vector,
    });
  }
  return test_instances;
}

std::vector<ArribaTestParams> GetTestInstancesOrDie() {
  absl::StatusOr<std::vector<ArribaTestParams>> test_instances =
      GetTestInstances();
  return *test_instances;
}

INSTANTIATE_TEST_SUITE_P(pinsOndatraArribaTest, ArribaTest,
                         testing::ValuesIn(GetTestInstancesOrDie()));

}  // namespace
}  // namespace pins_test

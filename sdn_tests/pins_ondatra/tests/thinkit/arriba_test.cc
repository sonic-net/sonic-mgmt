#include "tests/forwarding/arriba_test.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "dvaas/test_vector.pb.h"
#include "glog/logging.h"
#include "gtest/gtest.h"
#include "gutil/gutil/testing.h"
#include "infrastructure/thinkit/ondatra_params.h"
#include "thinkit/mirror_testbed_fixture.h"

ABSL_FLAG(std::vector<std::string>, arriba_test_vector_files, {},
          "Paths to files containing ArribaTestVector textprotos.");

namespace pins_test {
namespace {

// Unsolicited packets that, for the time being, are acceptable in a PINS
// testbeds.
inline bool AlpineIsExpectedUnsolicitedPacket(const packetlib::Packet& packet) {
  if (packet.headers().size() == 3 &&
      packet.headers(2).icmp_header().type() == "0x85") {
    return true;
  }
  // TODO Switch generates IPV6 hop_by_hop packets.
  if (packet.headers().size() == 2 &&
      packet.headers(1).ipv6_header().next_header() == "0x00") {
    return true;
  }
  // Switch generates LACP packets if LAGs are present.
  if (packet.headers().size() == 1 &&
      packet.headers(0).ethernet_header().ethertype() == "0x8809") {
    return true;
  }
  // Alpine's deployment environment sends ARP packets.
  if (!packet.headers().empty() &&
      packet.headers(0).ethernet_header().ethertype() == "0x0806") {
    LOG(INFO) << "ALPINE: ARP packet";
    return true;
  }
  // Extension to VLAN tagged ARP packets.
  if (packet.headers().size() > 1 &&
      packet.headers(0).ethernet_header().ethertype() == "0x8100" &&
      packet.headers(1).vlan_header().ethertype() == "0x0806") {
    LOG(INFO) << "ALPINE: VLAN tagged ARP packet";
    return true;
  }
  return false;
}

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

  std::vector<ArribaTestParams> test_instances;
  for (const std::string& test_vector_file :
       absl::GetFlag(FLAGS_arriba_test_vector_files)) {

    test_instances.push_back(ArribaTestParams{
        .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
            mirror_testbed_params.mirror_testbed),
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

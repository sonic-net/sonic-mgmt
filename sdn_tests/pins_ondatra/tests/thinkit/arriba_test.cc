#include "tests/forwarding/arriba_test.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
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

// Returns one test instance per test vector textproto file provided through the
// `--arriba_test_vector_files` flag.
std::vector<ArribaTestParams> GetTestInstancesOrDie() {
  // Make sure there is at least one test vector present.
  CHECK(!absl::GetFlag(FLAGS_arriba_test_vector_files).empty())
      << "--arriba_test_vector_files is required.";

  thinkit::MirrorTestbedFixtureParams mirror_testbed_params =
      *pins::GetOndatraMirrorTestbedFixtureParams();

  std::vector<ArribaTestParams> test_instances;
  for (const std::string& test_vector_file :
       absl::GetFlag(FLAGS_arriba_test_vector_files)) {
    test_instances.push_back(ArribaTestParams{
        .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
            mirror_testbed_params.mirror_testbed),
        .arriba_test_vector =
            gutil::ParseProtoFileOrDie<dvaas::ArribaTestVector>(
                test_vector_file),
    });
  }
  return test_instances;
}

INSTANTIATE_TEST_SUITE_P(pinsOndatraArribaTest, ArribaTest,
                         testing::ValuesIn(GetTestInstancesOrDie()));

}  // namespace
}  // namespace pins_test

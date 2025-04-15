// Copyright (c) 2025, Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PINS_INFRASTRUCTURE_THINKIT_ONDATRA_MIRROR_TESTBED_H_
#define PINS_INFRASTRUCTURE_THINKIT_ONDATRA_MIRROR_TESTBED_H_

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "thinkit/bazel_test_environment.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/switch.h"

namespace pins_test {

class OndatraMirrorTestbed : public thinkit::MirrorTestbed {
 public:
  OndatraMirrorTestbed(
      std::unique_ptr<thinkit::Switch> sut,
      std::unique_ptr<thinkit::Switch> control,
      std::function<void(const std::vector<std::string>&)> set_test_case_ids =
          [](auto&&) {})
      : sut_(std::move(sut)),
        control_(std::move(control)),
        test_environment_(/*mask_known_failures=*/true,
                          std::move(set_test_case_ids)) {}

  thinkit::Switch& Sut() override { return *sut_; }

  thinkit::Switch& ControlSwitch() override { return *control_; }

  thinkit::TestEnvironment& Environment() override { return test_environment_; }

 private:
  std::unique_ptr<thinkit::Switch> sut_;
  std::unique_ptr<thinkit::Switch> control_;
  thinkit::BazelTestEnvironment test_environment_;
};

}  // namespace pins_test

#endif  // PINS_INFRASTRUCTURE_THINKIT_ONDATRA_MIRROR_TESTBED_H_

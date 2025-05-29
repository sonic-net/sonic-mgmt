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

#ifndef PINS_INFRASTRUCTURE_THINKIT_ONDATRA_GENERIC_TESTBED_FIXTURE_H_
#define PINS_INFRASTRUCTURE_THINKIT_ONDATRA_GENERIC_TESTBED_FIXTURE_H_

#include <memory>
#include <utility>

#include "absl/status/statusor.h"
#include "infrastructure/thinkit/thinkit.h"
#include "thinkit/generic_testbed.h"
#include "thinkit/generic_testbed_fixture.h"
#include "thinkit/proto/generic_testbed.pb.h"

namespace pins_test {

class OndatraGenericTestbedFixture : public thinkit::GenericTestbedInterface {
 public:
  explicit OndatraGenericTestbedFixture(
      OndatraHooks ondatra_hooks = OndatraHooks())
      : ondatra_hooks_(std::move(ondatra_hooks)) {}

  void SetUp() override {}

  void TearDown() override;

  absl::StatusOr<std::unique_ptr<thinkit::GenericTestbed>>
  GetTestbedWithRequirements(
      const thinkit::TestRequirements& requirements) override;

  void ExpectLinkFlaps() override {}

 private:
  OndatraHooks ondatra_hooks_;
};

}  // namespace pins_test

#endif  // PINS_INFRASTRUCTURE_THINKIT_ONDATRA_GENERIC_TESTBED_FIXTURE_H_

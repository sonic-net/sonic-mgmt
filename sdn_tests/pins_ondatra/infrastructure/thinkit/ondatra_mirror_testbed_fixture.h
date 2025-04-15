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

#ifndef PINS_INFRASTRUCTURE_THINKIT_ONDATRA_MIRROR_TESTBED_FIXTURE_H_
#define PINS_INFRASTRUCTURE_THINKIT_ONDATRA_MIRROR_TESTBED_FIXTURE_H_

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "infrastructure/thinkit/ondatra_mirror_testbed.h"
#include "infrastructure/thinkit/thinkit.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins_test {

class OndatraMirrorTestbedFixture : public thinkit::MirrorTestbedInterface {
 public:
  explicit OndatraMirrorTestbedFixture(
      OndatraHooks ondatra_hooks = OndatraHooks())
      : ondatra_hooks_(std::move(ondatra_hooks)) {}

  void SetUp() override;

  void TearDown() override;

  thinkit::MirrorTestbed& GetMirrorTestbed() override;
  absl::Status SaveSwitchLogs(absl::string_view save_prefix) override;
  void ExpectLinkFlaps() override {}

 private:
  OndatraHooks ondatra_hooks_;
  std::unique_ptr<OndatraMirrorTestbed> mirror_testbed_ = nullptr;
};

}  // namespace pins_test

#endif  // PINS_INFRASTRUCTURE_THINKIT_ONDATRA_MIRROR_TESTBED_FIXTURE_H_

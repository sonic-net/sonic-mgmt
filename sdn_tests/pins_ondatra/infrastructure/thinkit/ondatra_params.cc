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

#include "infrastructure/thinkit/ondatra_params.h"

#include "absl/status/statusor.h"
#include "infrastructure/thinkit/ondatra_generic_testbed_fixture.h"
#include "infrastructure/thinkit/ondatra_mirror_testbed_fixture.h"
#include "thinkit/generic_testbed_fixture.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins {

absl::StatusOr<thinkit::GenericTestbedFixtureParams>
GetOndatraGenericTestbedFixtureParams() {
  return thinkit::GenericTestbedFixtureParams{
      .testbed_interface = new pins_test::OndatraGenericTestbedFixture()};
}

absl::StatusOr<thinkit::MirrorTestbedFixtureParams>
GetOndatraMirrorTestbedFixtureParams() {
  return thinkit::MirrorTestbedFixtureParams{
      .mirror_testbed = new pins_test::OndatraMirrorTestbedFixture()};
}

}  // namespace pins

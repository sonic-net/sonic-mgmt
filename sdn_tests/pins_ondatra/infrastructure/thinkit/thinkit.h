// Copyright (c) 2023, Google Inc.
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

#ifndef PINS_INFRA_ONDATRA_THINKIT_THINKIT_H_
#define PINS_INFRA_ONDATRA_THINKIT_THINKIT_H_

#include <functional>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "github.com/openconfig/ondatra/proto/testbed.pb.h"
#include "github.com/openconfig/ondatra/proxy/proto/reservation.pb.h"

namespace pins_test {

absl::Status OndatraInit(const ondatra::Testbed& testbed_request,
                         absl::Duration wait_time, absl::Duration run_time);

absl::StatusOr<reservation::Reservation> OndatraTestbed();

absl::Status OndatraRelease();

struct OndatraHooks {
  std::function<absl::Status(const ondatra::Testbed&, absl::Duration,
                             absl::Duration)>
      init = OndatraInit;
  std::function<absl::StatusOr<reservation::Reservation>()> testbed =
      OndatraTestbed;
  std::function<absl::Status()> release = OndatraRelease;
};

}  // namespace pins_test

#endif  // PINS_INFRA_ONDATRA_THINKIT_THINKIT_H_

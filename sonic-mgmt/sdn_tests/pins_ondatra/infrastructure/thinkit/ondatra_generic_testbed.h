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

#ifndef PINS_INFRASTRUCTURE_THINKIT_ONDATRA_GENERIC_TESTBED_H_
#define PINS_INFRASTRUCTURE_THINKIT_ONDATRA_GENERIC_TESTBED_H_

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "thinkit/bazel_test_environment.h"
#include "thinkit/control_device.h"
#include "thinkit/generic_testbed.h"
#include "thinkit/switch.h"

namespace pins_test {

class OndatraGenericTestbed : public thinkit::GenericTestbed {
 public:
  OndatraGenericTestbed(
      std::unique_ptr<thinkit::Switch> sut,
      std::unique_ptr<thinkit::ControlDevice> control_device,
      absl::flat_hash_map<std::string, thinkit::InterfaceInfo>
          control_port_by_sut_port,
      std::function<void(const std::vector<std::string>&)> set_test_case_ids =
          [](auto&&) {})
      : sut_(std::move(sut)),
        control_device_(std::move(control_device)),
        control_port_by_sut_port_(std::move(control_port_by_sut_port)),
        test_environment_(true, std::move(set_test_case_ids)) {}

  thinkit::Switch& Sut() override { return *sut_; }

  thinkit::ControlDevice& ControlDevice() override { return *control_device_; }

  thinkit::ControlDevice& ControlDevice(int index) override {
    return *control_device_;
  }

  thinkit::TestEnvironment& Environment() override { return test_environment_; }

  absl::flat_hash_map<std::string, thinkit::InterfaceInfo> GetSutInterfaceInfo()
      override {
    return control_port_by_sut_port_;
  }

  absl::StatusOr<thinkit::HttpResponse> SendRestRequestToIxia(
      thinkit::RequestType type, std::string_view url,
      std::string_view payload) override {
    return absl::UnimplementedError("");
  }

 private:
  std::unique_ptr<thinkit::Switch> sut_;
  std::unique_ptr<thinkit::ControlDevice> control_device_;
  absl::flat_hash_map<std::string, thinkit::InterfaceInfo>
      control_port_by_sut_port_;
  thinkit::BazelTestEnvironment test_environment_;
};

}  // namespace pins_test

#endif  // PINS_INFRASTRUCTURE_THINKIT_ONDATRA_GENERIC_TESTBED_H_

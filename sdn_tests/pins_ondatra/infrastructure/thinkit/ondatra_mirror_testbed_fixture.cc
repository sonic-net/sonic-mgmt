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

#include "infrastructure/thinkit/ondatra_mirror_testbed_fixture.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "github.com/openconfig/ondatra/proto/testbed.pb.h"
#include "github.com/openconfig/ondatra/proxy/proto/reservation.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/gutil/status.h"
#include "gutil/gutil/status_matchers.h"
#include "lib/basic_switch.h"
#include "lib/gnmi/gnmi_helper.h"
#include "infrastructure/thinkit/ondatra_mirror_testbed.h"
#include "infrastructure/thinkit/thinkit.h"
#include "p4/v1/p4runtime.grpc.pb.h"
#include "proto/gnmi/gnmi.grpc.pb.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/switch.h"

namespace pins_test {
namespace {

constexpr std::string_view kDutId = "DUT";
constexpr std::string_view kControlId = "CONTROL";

ondatra::Testbed GetTestbedRequest() {
  ondatra::Testbed testbed_request;
  ondatra::Device& sut = *testbed_request.add_duts();
  ondatra::Device& control = *testbed_request.add_duts();
  sut.set_id(kDutId);
  control.set_id(kControlId);
  return testbed_request;
}

template <class T>
absl::StatusOr<const T*> Find(const google::protobuf::Map<std::string, T>& map,
                              std::string_view key) {
  auto value = map.find(key);
  if (value == map.end()) {
    return absl::NotFoundError(absl::StrCat("Key ", key, " not found in map."));
  }
  return &value->second;
}

absl::StatusOr<std::unique_ptr<thinkit::Switch>> CreateSwitchFromDevice(
    const reservation::ResolvedDevice& device) {
  ASSIGN_OR_RETURN(const reservation::Service* service,
                   Find(device.services(), gnmi::gNMI::service_full_name()),
                   _.SetAppend() << absl::StrCat(device));
  std::string gnmi_address = service->has_grpc()
                                 ? service->grpc().address()
                                 : service->proxied_grpc().proxy(0);

  ASSIGN_OR_RETURN(
      service, Find(device.services(), p4::v1::P4Runtime::service_full_name()),
      _.SetAppend() << absl::StrCat(device));
  std::string p4rt_address = service->has_grpc()
                                 ? service->grpc().address()
                                 : service->proxied_grpc().proxy(0);

  pins_test::CreateGrpcStub<pins_test::LocalTcp> grpc_builder;
  auto gnmi_stub = grpc_builder.Create(gnmi::gNMI::NewStub, gnmi_address,
                                       device.name(), "gNMI");

  ASSIGN_OR_RETURN(uint64_t device_id, pins_test::GetDeviceId(*gnmi_stub));

  return std::make_unique<
      pins_test::BasicSwitch<pins_test::CreateGrpcStub<pins_test::LocalTcp>>>(
      device.name(), device_id,
      pins_test::SwitchServices{.p4runtime_address = p4rt_address,
                                .gnmi_address = gnmi_address,
                                .gnoi_address = gnmi_address});
}
}  // namespace

void OndatraMirrorTestbedFixture::TearDown() {
  mirror_testbed_.reset();
  EXPECT_OK(ondatra_hooks_.release());
}

absl::Status OndatraMirrorTestbedFixture::SaveSwitchLogs(
    absl::string_view save_prefix) {
  return absl::OkStatus();
}

void OndatraMirrorTestbedFixture::SetUp() {
  if (mirror_testbed_) {
    ADD_FAILURE() << "SetUp should be called only once before a TearDown.";
    return;
  }

  const ondatra::Testbed testbed_request = GetTestbedRequest();
  ASSERT_OK(ondatra_hooks_.init(testbed_request,
                                /*wait_time=*/absl::Hours(1),
                                /*run_time=*/absl::Hours(1)));
  ASSERT_OK_AND_ASSIGN(reservation::Reservation reservation,
                       ondatra_hooks_.testbed());
  ASSERT_OK_AND_ASSIGN(const reservation::ResolvedDevice* dut,
                       Find(reservation.devices(), kDutId));
  ASSERT_OK_AND_ASSIGN(const reservation::ResolvedDevice* control_device,
                       Find(reservation.devices(), kControlId));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<thinkit::Switch> sut,
                       CreateSwitchFromDevice(*dut));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<thinkit::Switch> control,
                       CreateSwitchFromDevice(*control_device));

  mirror_testbed_ = std::make_unique<OndatraMirrorTestbed>(std::move(sut),
                                                           std::move(control));
}

thinkit::MirrorTestbed& OndatraMirrorTestbedFixture::GetMirrorTestbed() {
  return *mirror_testbed_;
}
}  // namespace pins_test

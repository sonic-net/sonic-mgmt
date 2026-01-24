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

#include "infrastructure/thinkit/ondatra_generic_testbed_fixture.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/time/time.h"
#include "github.com/openconfig/ondatra/proto/testbed.pb.h"
#include "github.com/openconfig/ondatra/proxy/proto/reservation.pb.h"
#include "gmock/gmock.h"
#include "gutil/gutil/status.h"
#include "gutil/gutil/status_matchers.h"
#include "lib/basic_switch.h"
#include "lib/gnmi/gnmi_helper.h"
#include "lib/pins_control_device.h"
#include "infrastructure/thinkit/ondatra_generic_testbed.h"
#include "infrastructure/thinkit/thinkit.h"
#include "p4/v1/p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "proto/gnmi/gnmi.grpc.pb.h"
#include "thinkit/generic_testbed.h"
#include "thinkit/proto/generic_testbed.pb.h"
#include "thinkit/switch.h"

namespace pins_test {
namespace {

constexpr std::string_view kDutId = "DUT";
constexpr std::string_view kControlId = "CONTROL";

absl::StatusOr<ondatra::Testbed> ConvertRequirementsToTestbedRequest(
    const thinkit::TestRequirements& requirements) {
  ondatra::Testbed testbed_request;
  ondatra::Device& sut = *testbed_request.add_duts();
  sut.set_id(kDutId);
  int sut_interface_index = 0;
  for (const thinkit::InterfaceRequirement& requirement :
       requirements.interface_requirements()) {
    switch (requirement.interface_mode()) {
      case thinkit::CONTROL_INTERFACE: {
        ondatra::Device& control_device = *testbed_request.add_duts();
        control_device.set_id(kControlId);
        for (int control_device_interface_index = 0;
             control_device_interface_index < requirement.count();
             control_device_interface_index++, sut_interface_index++) {
          // Currently, the PINs bind has ports named as portN, where N is
          // 1-indexed.
          control_device.add_ports()->set_id(
              absl::StrCat("port", control_device_interface_index + 1));
          sut.add_ports()->set_id(
              absl::StrCat("port", sut_interface_index + 1));
          ondatra::Link& link = *testbed_request.add_links();
          link.set_a(absl::StrCat(kDutId, ":port", sut_interface_index + 1));
          link.set_b(absl::StrCat(kControlId, ":port",
                                  control_device_interface_index + 1));
        }
      } break;
      default:
        return absl::InvalidArgumentError(absl::StrCat(
            thinkit::InterfaceMode_Name(requirement.interface_mode()),
            " is not supported."));
    }
  }
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

absl::StatusOr<absl::flat_hash_map<std::string, thinkit::InterfaceInfo>>
GetSutInterfaceInfoFromReservation(
    const ondatra::Testbed& testbed_request,
    const reservation::Reservation& reservation) {
  ASSIGN_OR_RETURN(const reservation::ResolvedDevice* dut,
                   Find(reservation.devices(), kDutId),
                   _.SetAppend() << absl::StrCat(reservation));
  const reservation::ResolvedDevice* control = nullptr;

  absl::flat_hash_map<std::string, thinkit::InterfaceInfo> sut_interface_info;
  // We loop over the request links instead of the reservation's resolved links
  // because PINs bind does not properly support those.
  for (const ondatra::Link& link : testbed_request.links()) {
    // If there is a link, then there is a control switch (at the moment).
    if (control == nullptr) {
      ASSIGN_OR_RETURN(control, Find(reservation.devices(), kControlId),
                       _.SetAppend() << absl::StrCat(reservation));
    }

    std::string_view sut_port_name = link.a();
    std::string_view control_port_name = link.b();
    if (!absl::StrContains(sut_port_name, kDutId)) {
      std::swap(sut_port_name, control_port_name);
    }
    if (!absl::StrContains(sut_port_name, kDutId) ||
        !absl::StrContains(control_port_name, kControlId)) {
      return absl::InvalidArgumentError(
          absl::StrCat("Link is not between DUT and CONTROL: ", link));
    }

    std::vector<std::string_view> sut_port_parts =
        absl::StrSplit(sut_port_name, ':');
    std::vector<std::string_view> control_port_parts =
        absl::StrSplit(control_port_name, ':');
    if (sut_port_parts.size() != 2 || control_port_parts.size() != 2) {
      return absl::InvalidArgumentError(
          absl::StrCat(sut_port_name, " or ", control_port_name,
                       " is not of the format \"<device-id>:<port-id>\"."));
    }
    ASSIGN_OR_RETURN(const reservation::ResolvedPort* sut_port,
                     Find(dut->ports(), sut_port_parts[1]));
    ASSIGN_OR_RETURN(const reservation::ResolvedPort* control_port,
                     Find(control->ports(), control_port_parts[1]));

    thinkit::InterfaceInfo& info = sut_interface_info[sut_port->name()];
    info.interface_modes = {thinkit::CONTROL_INTERFACE};
    info.peer_interface_name = control_port->name();
  }
  return sut_interface_info;
}

}  // namespace

void OndatraGenericTestbedFixture::TearDown() {
  EXPECT_OK(ondatra_hooks_.release());
}

absl::StatusOr<std::unique_ptr<thinkit::GenericTestbed>>
OndatraGenericTestbedFixture::GetTestbedWithRequirements(
    const thinkit::TestRequirements& requirements) {
  ASSIGN_OR_RETURN(ondatra::Testbed testbed_request,
                   ConvertRequirementsToTestbedRequest(requirements));
  RETURN_IF_ERROR(ondatra_hooks_.init(testbed_request,
                                      /*wait_time=*/absl::Hours(1),
                                      /*run_time=*/absl::Hours(1)));
  ASSIGN_OR_RETURN(reservation::Reservation reservation,
                   ondatra_hooks_.testbed());

  ASSIGN_OR_RETURN(auto sut_interface_info, GetSutInterfaceInfoFromReservation(
                                                testbed_request, reservation));
  ASSIGN_OR_RETURN(const reservation::ResolvedDevice* dut,
                   Find(reservation.devices(), kDutId),
                   _.SetAppend() << absl::StrCat(reservation));
  ASSIGN_OR_RETURN(auto sut, CreateSwitchFromDevice(*dut));

  absl::StatusOr<const reservation::ResolvedDevice*> control =
      Find(reservation.devices(), kControlId);
  if (!control.ok()) {
    return std::make_unique<pins_test::OndatraGenericTestbed>(
        std::move(sut), /*control_device=*/nullptr,
        std::move(sut_interface_info));
  }

  ASSIGN_OR_RETURN(auto control_switch, CreateSwitchFromDevice(*(*control)));
  ASSIGN_OR_RETURN(auto session,
                   pdpi::P4RuntimeSession::Create(*control_switch));
  ASSIGN_OR_RETURN(p4::v1::GetForwardingPipelineConfigResponse response,
                   pdpi::GetForwardingPipelineConfig(session.get()));
  ASSIGN_OR_RETURN(
      auto control_device,
      pins_test::PinsControlDevice::Create(
          std::move(control_switch),
          std::move(*response.mutable_config()->mutable_p4info())));
  auto control_device_pointer =
      std::make_unique<pins_test::PinsControlDevice>(std::move(control_device));
  return std::make_unique<pins_test::OndatraGenericTestbed>(
      std::move(sut), std::move(control_device_pointer),
      std::move(sut_interface_info));
}

}  // namespace pins_test

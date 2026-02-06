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

#include <list>
#include <memory>
#include <string>
#include <tuple>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"
#include "github.com/openconfig/ondatra/proto/testbed.pb.h"
#include "github.com/openconfig/ondatra/proxy/proto/reservation.pb.h"
#include "gmock/gmock.h"
#include "grpc/grpc_security_constants.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/server_context.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "gtest/gtest.h"
#include "gutil/gutil/proto_matchers.h"
#include "gutil/gutil/status.h"
#include "gutil/gutil/status_matchers.h"
#include "gutil/gutil/testing.h"
#include "infrastructure/thinkit/thinkit.h"
#include "p4/v1/p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"
#include "proto/gnmi/gnmi.grpc.pb.h"
#include "proto/gnmi/gnmi.pb.h"
#include "thinkit/generic_testbed.h"
#include "thinkit/proto/generic_testbed.pb.h"

namespace pins_test {
namespace {

using ::gutil::EqualsProto;
using ::testing::_;
using ::testing::Eq;
using ::testing::MockFunction;
using ::testing::Return;
using ::testing::TestParamInfo;
using ::testing::UnorderedPointwise;
using ::testing::ValuesIn;

// This class fakes the arbitration and config push.
class FakeSwitchP4rt : public p4::v1::P4Runtime::Service {
 public:
  grpc::Status GetForwardingPipelineConfig(
      grpc::ServerContext* context,
      const p4::v1::GetForwardingPipelineConfigRequest* request,
      p4::v1::GetForwardingPipelineConfigResponse* response) override {
    return grpc::Status::OK;
  }

  grpc::Status SetForwardingPipelineConfig(
      grpc::ServerContext* context,
      const p4::v1::SetForwardingPipelineConfigRequest* request,
      p4::v1::SetForwardingPipelineConfigResponse* response) override {
    return grpc::Status::OK;
  }

  grpc::Status StreamChannel(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<p4::v1::StreamMessageResponse,
                               p4::v1::StreamMessageRequest>* stream) override {
    p4::v1::StreamMessageRequest request;
    while (stream->Read(&request)) {
      p4::v1::StreamMessageResponse response;
      *response.mutable_arbitration()->mutable_election_id() =
          request.arbitration().election_id();
      response.mutable_arbitration()->set_device_id(183934027);
      stream->Write(response);
    }
    return grpc::Status::OK;
  }
};

// This class fakes the config push and getting interface information.
class FakeSwitchGnmi : public gnmi::gNMI::Service {
 public:
  grpc::Status Set(grpc::ServerContext* context,
                   const gnmi::SetRequest* request,
                   gnmi::SetResponse* response) override {
    return grpc::Status::OK;
  }

  grpc::Status Get(grpc::ServerContext* context,
                   const gnmi::GetRequest* request,
                   gnmi::GetResponse* response) override {
    std::string json_itef_val;
    if (request->path().Get(0).elem().Get(0).name() == "components") {
      json_itef_val = R"json({"openconfig-p4rt:node-id":"183934027"})json";
    } else {
      json_itef_val =
          R"json({"openconfig-interfaces:interfaces":{"interface":[]}})json";
    }

    response->add_notification()
        ->add_update()
        ->mutable_val()
        ->set_json_ietf_val(json_itef_val);
    return grpc::Status::OK;
  }
};

// `FakeSwitch` creates a fake local gRPC server that can emulate gNMI and P4RT
// config processes enough to succeed during generic testbed creation.
class FakeSwitch {
 public:
  FakeSwitch() : port_(), server_(), fake_p4rt_(), fake_gnmi_() {
    grpc::ServerBuilder builder;
    builder.AddListeningPort(
        "[::]:0", grpc::experimental::LocalServerCredentials(LOCAL_TCP),
        &port_);
    builder.RegisterService(&fake_p4rt_);
    builder.RegisterService(&fake_gnmi_);
    server_ = builder.BuildAndStart();
  }
  FakeSwitch(FakeSwitch&&) = default;
  ~FakeSwitch() { server_->Shutdown(); }

  int GetPort() const { return port_; }

 private:
  int port_;
  std::unique_ptr<grpc::Server> server_;
  FakeSwitchP4rt fake_p4rt_;
  FakeSwitchGnmi fake_gnmi_;
};

struct TestParameters {
  std::string test_name;
  thinkit::TestRequirements generic_testbed_requirements;
  std::string expected_testbed_request;
  absl::StatusOr<reservation::Reservation> returned_reservation;
  absl::StatusOr<absl::flat_hash_map<std::string, thinkit::InterfaceInfo>>
      expected_sut_interface_info;
};

class OndatraGenericTestbedFixtureTest
    : public testing::TestWithParam<TestParameters> {};

TEST_P(OndatraGenericTestbedFixtureTest, Test) {
  MockFunction<absl::Status(const ondatra::Testbed&, absl::Duration,
                            absl::Duration)>
      mock_init;
  EXPECT_CALL(mock_init,
              Call(EqualsProto(GetParam().expected_testbed_request), _, _))
      .WillOnce(Return(absl::OkStatus()));
  MockFunction<absl::StatusOr<reservation::Reservation>()> mock_testbed;
  std::list<FakeSwitch> fake_switches;
  if (GetParam().returned_reservation.ok()) {
    reservation::Reservation reservation = *GetParam().returned_reservation;
    for (auto& [id, device] : *reservation.mutable_devices()) {
      const FakeSwitch& fake_switch = fake_switches.emplace_back();
      reservation::Service& gnmi_service =
          (*device.mutable_services())["gnmi.gNMI"];
      gnmi_service.mutable_proxied_grpc()->add_proxy(
          absl::StrCat("[::]:", fake_switch.GetPort()));
      reservation::Service& p4rt_service =
          (*device.mutable_services())["p4.v1.P4Runtime"];
      p4rt_service.mutable_proxied_grpc()->add_proxy(
          absl::StrCat("[::]:", fake_switch.GetPort()));
    }
    EXPECT_CALL(mock_testbed, Call).WillOnce(Return(reservation));
  } else {
    EXPECT_CALL(mock_testbed, Call)
        .WillOnce(Return(GetParam().returned_reservation));
  }
  MockFunction<absl::Status()> mock_release;
  EXPECT_CALL(mock_release, Call).WillOnce(Return(absl::OkStatus()));

  OndatraGenericTestbedFixture fixture(
      OndatraHooks{.init = mock_init.AsStdFunction(),
                   .testbed = mock_testbed.AsStdFunction(),
                   .release = mock_release.AsStdFunction()});

  fixture.SetUp();
  if (GetParam().expected_sut_interface_info.ok()) {
    ASSERT_OK_AND_ASSIGN(auto generic_testbed,
                         fixture.GetTestbedWithRequirements(
                             GetParam().generic_testbed_requirements));
    EXPECT_THAT(
        generic_testbed->GetSutInterfaceInfo(),
        UnorderedPointwise(Eq(), *GetParam().expected_sut_interface_info));
  } else {
    EXPECT_EQ(
        fixture
            .GetTestbedWithRequirements(GetParam().generic_testbed_requirements)
            .status(),
        GetParam().expected_sut_interface_info.status());
  }
  fixture.TearDown();
}

INSTANTIATE_TEST_SUITE_P(
    PinsTest, OndatraGenericTestbedFixtureTest,
    ValuesIn<TestParameters>(
        {{.test_name = "SingleSwitch",
          .generic_testbed_requirements = {},
          .expected_testbed_request = R"pb(duts { id: "DUT" })pb",
          .returned_reservation =
              gutil::ParseProtoOrDie<reservation::Reservation>(R"pb(devices {
                                                                      key: "DUT"
                                                                    })pb"),
          .expected_sut_interface_info =
              absl::flat_hash_map<std::string, thinkit::InterfaceInfo>{}},
         {.test_name = "DualSwitch",
          .generic_testbed_requirements =
              gutil::ParseProtoOrDie<thinkit::TestRequirements>(
                  R"pb(interface_requirements {
                         interface_mode: CONTROL_INTERFACE
                         count: 2
                       })pb"),
          .expected_testbed_request =
              R"pb(duts {
                     id: "DUT"
                     ports { id: "port1" }
                     ports { id: "port2" }
                   }
                   duts {
                     id: "CONTROL"
                     ports { id: "port1" }
                     ports { id: "port2" }
                   }
                   links { a: "DUT:port1" b: "CONTROL:port1" }
                   links { a: "DUT:port2" b: "CONTROL:port2" })pb",
          .returned_reservation =
              gutil::ParseProtoOrDie<reservation::Reservation>(
                  R"pb(devices {
                         key: "DUT"
                         value {
                           ports {
                             key: "port1"
                             value { name: "Ethernet1" }
                           }
                           ports {
                             key: "port2"
                             value { name: "Ethernet2" }
                           }
                         }
                       }
                       devices {
                         key: "CONTROL"
                         value {
                           ports {
                             key: "port1"
                             value { name: "Ethernet3" }
                           }
                           ports {
                             key: "port2"
                             value { name: "Ethernet4" }
                           }
                         }
                       })pb"),
          .expected_sut_interface_info =
              absl::flat_hash_map<std::string, thinkit::InterfaceInfo>{
                  {"Ethernet1",
                   {.interface_modes =
                        {thinkit::InterfaceMode::CONTROL_INTERFACE},
                    .peer_interface_name = "Ethernet3"}},
                  {"Ethernet2",
                   {.interface_modes =
                        {thinkit::InterfaceMode::CONTROL_INTERFACE},
                    .peer_interface_name = "Ethernet4"}}}},
         {
             .test_name = "Error",
             .generic_testbed_requirements =
                 gutil::ParseProtoOrDie<thinkit::TestRequirements>(
                     R"pb(interface_requirements {
                            interface_mode: CONTROL_INTERFACE
                            count: 2
                          })pb"),
             .expected_testbed_request =
                 R"pb(duts {
                        id: "DUT"
                        ports { id: "port1" }
                        ports { id: "port2" }
                      }
                      duts {
                        id: "CONTROL"
                        ports { id: "port1" }
                        ports { id: "port2" }
                      }
                      links { a: "DUT:port1" b: "CONTROL:port1" }
                      links { a: "DUT:port2" b: "CONTROL:port2" })pb",
             .returned_reservation = absl::InternalError("Error"),
             .expected_sut_interface_info = absl::InternalError("Error"),
         }}),
    [](const TestParamInfo<TestParameters>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace pins_test

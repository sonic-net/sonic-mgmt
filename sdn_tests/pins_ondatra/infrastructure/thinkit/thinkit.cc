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

#include "infrastructure/thinkit/thinkit.h"

#include <cstddef>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "github.com/openconfig/ondatra/proto/testbed.pb.h"
#include "github.com/openconfig/ondatra/proxy/proto/reservation.pb.h"
#include "google/protobuf/message.h"
#include "gutil/status.h"
#include "infrastructure/thinkit/thinkit_cgo.h"

namespace pins_test {
namespace {

ProtoIn ToProtoIn(absl::string_view serialized_message) {
  return {.data = serialized_message.data(),
          .length = serialized_message.size()};
}

ProtoOut ToProtoOut(google::protobuf::Message& message) {
  return {.proto = &message,
          .write_proto = [](void* proto_handle, char* data, size_t length) {
            google::protobuf::Message& proto =
                *static_cast<google::protobuf::Message*>(proto_handle);
            proto.ParseFromArray(data, length);
          }};
}

/*StringOut ToStringOut(std::string& string) {
  return {.string = &string,.resize = [](void* string_handle, size_t length) {
            std::string& string = *static_cast<std::string*>(string_handle);
            string.resize(length);
            return string.data();
          }};
}*/

StringOut ToStringOut(std::string& string) {
  StringOut result;
  result.string = &string;
  result.resize = [](void* string_handle, size_t length) {
            std::string& string = *static_cast<std::string*>(string_handle);
            string.resize(length);
            return const_cast<char*>(string.data());
          };
  return result;
}


absl::Status FromErrorMessage(absl::string_view error_message) {
  if (error_message.empty()) {
    return absl::OkStatus();
  } else {
    return absl::InternalError(error_message);
  }
}

}  // namespace

absl::Status OndatraInit(const ondatra::Testbed& testbed_request,
                         absl::Duration wait_time, absl::Duration run_time) {
  std::string error_message;
  platforms_networking_pins_ondatra_thinkit_Init(
      ToProtoIn(testbed_request.SerializePartialAsString()),
      absl::ToInt64Nanoseconds(wait_time), absl::ToInt64Nanoseconds(run_time),
      ToStringOut(error_message));
  return FromErrorMessage(error_message);
}

absl::StatusOr<reservation::Reservation> OndatraTestbed() {
  std::string error_message;
  reservation::Reservation reservation;
  platforms_networking_pins_ondatra_thinkit_Testbed(
      ToProtoOut(reservation), ToStringOut(error_message));
  RETURN_IF_ERROR(FromErrorMessage(error_message));
  return reservation;
}

absl::Status OndatraRelease() {
  std::string error_message;
  platforms_networking_pins_ondatra_thinkit_Release(
      ToStringOut(error_message));
  return FromErrorMessage(error_message);
}

}  // namespace pins_test

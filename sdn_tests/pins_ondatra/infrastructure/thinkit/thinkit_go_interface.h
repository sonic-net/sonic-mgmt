#ifndef PINS_INFRASTRUCTURE_THINKIT_THINKIT_GO_INTERFACE_H_
#define PINS_INFRASTRUCTURE_THINKIT_THINKIT_GO_INTERFACE_H_

// The header is shared between the CC and GO libraries.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ProtoIn {
  const char* data;
  size_t length;
};

struct ProtoOut {
  void* proto;
  void (*write_proto)(void* proto, char* data, size_t length);
};

struct StringOut {
  void* string;
  char* (*resize)(void* string, size_t length);
};

static void write_proto(struct ProtoOut proto_out, char* data, size_t length) {
  proto_out.write_proto(proto_out.proto, data, length);
}

static char* resize_string(struct StringOut string_out, size_t length) {
  return string_out.resize(string_out.string, length);
}

// Options for creating a new teardown.
// Used to create TearDownOptions defined in testhelper.go.
struct testhelper_TeardownCreateOpts {
  char* id;
  bool with_config_restorer;
};

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // PINS_INFRASTRUCTURE_THINKIT_THINKIT_GO_INTERFACE_H_

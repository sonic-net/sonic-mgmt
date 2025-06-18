# Third-Party gRPC Proto Definitions and Stubs for SONiC Tests

## Purpose

The purpose of this document is to define a standardized approach for managing third-party gRPC protocol buffer definitions and generating client stubs to be used in SONiC tests. This design aims to provide a consistent, maintainable, and version-controlled method for integrating gRPC-based APIs from various third-party providers (e.g., OpenConfig, gNOI, gNMI).

## High Level Design Document

| Rev      | Date        | Author                   | Change Description                |
|----------|-------------|--------------------------|-----------------------------------|
| Draft    | 17-06-2025  | Dawei Huang              | Initial version                   |

## Introduction

SONiC tests in the [sonic-mgmt](https://github.com/sonic-net/sonic-mgmt) repository often need to interact with various gRPC-based APIs for configuration, telemetry, and validation purposes. These APIs typically rely on protocol buffer definitions maintained by third-party projects such as OpenConfig's gNMI, gNOI, and others.

Currently, different test components handle these dependencies in ad-hoc ways, leading to:
- Duplication of proto files and generated stubs
- Inconsistent versioning of third-party dependencies
- Maintenance challenges when updating dependencies
- Lack of standardization across test components

This design proposes a unified approach to manage these dependencies using Git submodules and a centralized build process.

## Current Design

There are currently two different approaches being used in the codebase for handling gRPC proto definitions:

### SAI Validation Approach

The approach as implemented for SAI validation involves:

1. A shell script (`build-gnmi-stubs.sh`) that:
   - Clones the OpenConfig gNMI repository at test runtime
   - Generates Python stubs using protoc
   - Organizes the generated files in a specific directory structure

2. Integration with pytest via hooks that:
   - Invoke the build script during session setup
   - Provide fixtures for using the generated stubs

### gNMI Tests Approach

A completely different approach is used in the `tests/gnmi` directory:

1. It manually includes and maintains proto files directly in the repository:
   - Proto files are stored in `gnmi/protos` directory
   - The directory structure mimics the original repository structure

2. A fixture in `tests/gnmi/conftest.py` that:
   - Compiles protos at runtime using grpc_tools.protoc
   - Uses a different directory structure than the SAI validation approach
   - Provides helper functions like `get_gnoi_system_stubs()` in `grpc_utils.py` to import the generated stubs

3. Unlike the SAI validation approach, it:
   - Generates the stubs in place, rather than in a designated directory
   - Cleans up the generated files after tests complete

While both approaches are functional, they have limitations:
- Requires internet connectivity to clone repositories during test execution (SAI validation)
- Difficult to support `import` in `.proto` files from other repo. (GNMI)
- Lacks version control for third-party dependencies (both approaches)
- Has limited scope (only handles specific proto files that each approach needs)
- Duplicates effort across different test components
- Creates inconsistency in how proto files are imported and used
- Makes updating proto definitions difficult and error-prone
- Leads to maintenance challenges as each approach must be updated separately

## Proposed Design

### Overview

The proposed design creates a centralized approach with the following components:

1. A `third_party/` directory under `tests/` to store Git submodules for all required proto definitions
2. A unified build script to generate stubs for all third-party proto definitions
3. Session-scoped fixtures to provide access to the generated stubs
4. A standardized import pattern for using the generated stubs in tests

### Directory Structure

```
tests/
├── third_party/                           # Root for all third-party dependencies
│   ├── openconfig/                        # Organization-level directory
│   │   ├── gnmi/                          # Git submodule for gnmi
│   │   ├── gnoi/                          # Git submodule for gnoi
│   │   └── ...
│   └── ...
├── common/
│   └── grpc_stubs/                        # Generated stubs for all protos
│       ├── openconfig/
│       │   ├── gnmi/
│       │   └── gnoi/
├── build_grpc_stubs.sh                    # Unified build script
└── ...
```

### Git Submodules

Git submodules will be used to maintain specific versions of third-party proto definitions. This approach provides:

1. **Version Control**: Each submodule can be pinned to a specific commit/tag
2. **Reproducibility**: Tests will always use the same version of dependencies
3. **Offline Operation**: No network connectivity required during test execution
4. **Update Process**: Clear mechanism for updating dependencies when needed

Example of adding a submodule:
```bash
git submodule add https://github.com/openconfig/gnmi.git tests/third_party/openconfig/gnmi
git submodule add https://github.com/openconfig/gnoi.git tests/third_party/openconfig/gnoi
```

### Unified Build Script

A single build script (`build_grpc_stubs.sh`) will generate stubs for all proto definitions. The script will:

1. Take a base directory as input (typically the test directory)
2. Generate stubs for all proto files in all submodules
3. Organize the output in a standardized directory structure
4. Create necessary `__init__.py` files for Python package imports

```bash
#!/bin/bash

# This script generates gRPC stubs for all third-party proto definitions

set -e
set -u
set -o pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <base_directory>"
    exit 1
fi

BASE_DIR="$1"
THIRD_PARTY_DIR="$BASE_DIR/third_party"
GENERATED_DIR="$BASE_DIR/common/grpc_stubs"

# Clean generated directory
if [ -d "$GENERATED_DIR" ]; then
    echo "Removing existing directory: $GENERATED_DIR"
    rm -rf "$GENERATED_DIR"
fi
echo "Creating directory: $GENERATED_DIR"
mkdir -p "$GENERATED_DIR"

# Function to generate stubs for a proto file
generate_stubs() {
    local proto_file="$1"
    local proto_dir=$(dirname "$proto_file")
    local proto_path="$THIRD_PARTY_DIR"

    echo "Generating stubs for $proto_file"
    python -m grpc_tools.protoc \
        --proto_path="$proto_path" \
        --python_out="$GENERATED_DIR" \
        --grpc_python_out="$GENERATED_DIR" \
        "$proto_file"
}

# Find all proto files
find "$THIRD_PARTY_DIR" -name "*.proto" | while read proto_file; do
    generate_stubs "$proto_file"
done

# Create __init__.py files for all directories
find "$GENERATED_DIR" -type d | while read dir; do
    touch "$dir/__init__.py"
done

# Handle path corrections for grpc compiler bug if needed
# (similar to the existing build-gnmi-stubs.sh script)

echo "gRPC stubs generated successfully."
```

### Integration with pytest

The build script will be invoked during pytest session setup through a session-scoped fixture in `conftest.py`:

```python
@pytest.fixture(scope="session", autouse=True)
def build_grpc_stubs(request):
    """Build gRPC stubs for third-party proto definitions."""
    script_path = os.path.join(os.path.dirname(__file__), "build_grpc_stubs.sh")
    base_dir = os.path.dirname(__file__)

    # Skip if running in check mode
    if request.config.getoption("--check"):
        return

    result = subprocess.run([script_path, base_dir], check=True)
    if result.returncode != 0:
        pytest.fail(f"Failed to build gRPC stubs: {result.stderr}")
```

### Using the Generated Stubs

Tests will import the generated stubs using a standardized import pattern:

```python
from tests.common.grpc_stubs.openconfig.gnmi.proto.gnmi import gnmi_pb2
from tests.common.grpc_stubs.openconfig.gnmi.proto.gnmi import gnmi_pb2_grpc
```

This provides a consistent, predictable way to access the generated stubs across all tests.

### Helper Classes/Utilities

For commonly used gRPC services, helper classes will be provided to simplify usage:

```python
# tests/common/grpc/gnmi_client.py
import grpc
from tests.common.grpc_stubs.openconfig.gnmi.proto.gnmi import gnmi_pb2
from tests.common.grpc_stubs.openconfig.gnmi.proto.gnmi import gnmi_pb2_grpc

class GnmiClient:
    """Helper class for interacting with gNMI servers."""

    def __init__(self, target, secure=False, root_cert=None, client_key=None, client_cert=None):
        """Initialize a gNMI client."""
        self.target = target

        if secure:
            credentials = self._get_credentials(root_cert, client_key, client_cert)
            self.channel = grpc.secure_channel(target, credentials)
        else:
            self.channel = grpc.insecure_channel(target)

        self.stub = gnmi_pb2_grpc.gNMIStub(self.channel)

    def _get_credentials(self, root_cert, client_key, client_cert):
        """Get credentials for secure connection."""
        # Implementation details...

    def get(self, path, datatype="ALL"):
        """Send a Get request to the gNMI server."""
        # Implementation details...

    def set(self, updates, deletes=None):
        """Send a Set request to the gNMI server."""
        # Implementation details...

    def subscribe(self, paths, mode="STREAM", subscription_mode="ON_CHANGE"):
        """Subscribe to updates for the specified paths."""
        # Implementation details...
```

Similar helper classes would be provided for other commonly used gRPC services.

## Implementation Plan

The implementation will proceed in the following phases:

1. **Setup Base Structure**:
   - Create `tests/third_party/` directory
   - Create unified build script
   - Add initial submodules for most commonly used proto definitions

2. **Migrate Existing Usage**:
   - Update SAI validation to use the new structure
   - Gradually migrate other test components

3. **Documentation and Examples**:
   - Update documentation with usage examples
   - Provide helper utilities for common operations

4. **CI Integration**:
   - Ensure submodules are properly cloned during CI builds
   - Add checks for compatibility between proto versions and test code

## Benefits and Considerations

### Benefits

- **Consistency**: Standardized approach across all test components
  - Currently, the `tests/gnmi` tests vendor their own gNOI dependencies directly, which is not scalable and creates inconsistencies across the codebase
  - Different test directories may use different versions of the same proto definitions, leading to compatibility issues
  - The proposed approach ensures all tests use the same version of each proto definition
- **Maintainability**: Centralized management of dependencies
  - When proto definitions need to be updated, only one change is required instead of updating multiple copies
  - Reduces the risk of missing updates in some parts of the codebase
- **Version Control**: Explicit versioning of third-party dependencies
  - Each submodule can be pinned to a specific commit, ensuring reproducible builds
  - Updates to dependencies can be tracked and reviewed through normal Git processes
- **Offline Operation**: No network dependency during test execution
  - Eliminates test failures due to network connectivity issues or GitHub rate limiting
  - Ensures tests can run in isolated CI environments without external dependencies
- **Extensibility**: Easy to add new proto definitions as needed
  - New gRPC services can be added by simply adding a new submodule
  - All tests can immediately benefit from newly added proto definitions

### Considerations

- **Repository Size**: Git submodules will increase the repository size
- **Build Time**: Generating stubs for all protos may increase setup time
- **Compatibility**: Ensuring compatibility between different proto versions
- **Maintenance**: Need to periodically update submodules to incorporate upstream changes

## Conclusion

This design provides a standardized approach for managing third-party gRPC proto definitions and generating client stubs for use in SONiC tests. By using Git submodules and a unified build process, it addresses the limitations of the current ad-hoc approaches while providing a consistent, maintainable solution for all test components.

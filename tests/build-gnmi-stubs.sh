#!/bin/bash

# This script is invoked as part of the pytest session startup hook.
# It is used to generate gRPC stub client code to interact with the gNMI server for SAI validation.

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error
set -o pipefail  # Return the exit status of the last command in the pipeline that failed

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <base_directory>"
    exit 1
fi

BASE_DIR="$1"
COMMON_DIR="$BASE_DIR/common"
TARGET_DIR="$COMMON_DIR/sai_validation/github.com/openconfig"
GENERATED_DIR="$COMMON_DIR/sai_validation/generated"

# Step 0: Create the directory ./common/sai_validation/github.com/openconfig
if [ -d "$TARGET_DIR" ]; then
    echo "Removing existing directory: $TARGET_DIR"
    rm -rf "$TARGET_DIR"
fi
echo "Creating directory: $TARGET_DIR"
mkdir -p "$TARGET_DIR"

# Remove and re-create the GENERATED_DIR
if [ -d "$GENERATED_DIR" ]; then
    echo "Removing existing directory: $GENERATED_DIR"
    rm -rf "$GENERATED_DIR"
fi
echo "Creating directory: $GENERATED_DIR"
mkdir -p "$GENERATED_DIR"

# Step 1: Clone the repository
echo "Cloning https://github.com/openconfig/gnmi.git into $TARGET_DIR"
git clone https://github.com/openconfig/gnmi.git "$TARGET_DIR/gnmi"

# Step 2: Generate gRPC stubs
echo "Generating gRPC stubs..."
cd "$COMMON_DIR/sai_validation"
python -m grpc_tools.protoc \
    --proto_path=. \
    --python_out="$GENERATED_DIR" \
    --grpc_python_out="$GENERATED_DIR" \
    github.com/openconfig/gnmi/proto/gnmi/gnmi.proto \
    github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto

echo "gRPC stubs generated successfully."

# Create empty __init__.py at every level under $GENERATED_DIR/github/
echo "Creating empty __init__.py files under $GENERATED_DIR/github/"
find "$GENERATED_DIR/github/" -type d -exec touch {}/__init__.py \;

# Step 3: Move generated files to correct locations
# This is due to a bug in the gRPC compiler: https://github.com/grpc/grpc/issues/39583
echo "Moving generated files to correct locations..."
mv "$GENERATED_DIR/github.com/openconfig/gnmi/proto/gnmi/gnmi_pb2_grpc.py" \
   "$GENERATED_DIR/github/com/openconfig/gnmi/proto/gnmi/gnmi_pb2_grpc.py"

mv "$GENERATED_DIR/github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext_pb2_grpc.py" \
   "$GENERATED_DIR/github/com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext_pb2_grpc.py"

echo "Files moved successfully."

# Step 4: Remove $GENERATED_DIR/github.com directory
echo "Removing $GENERATED_DIR/github.com directory..."
rm -rf "$GENERATED_DIR/github.com"

echo "$GENERATED_DIR/github.com directory removed successfully."

- [Overview](#overview)
- [Scope](#scope)
- [Test structure](#test-structure)
- [Test cases](#test-cases)
# TestName
UPgrade Service via gNOI

## Overview
The goal of this test is to verify that the Upgrade Service, implemented via gNOI, functions correctly across different deployment environments. This includes validating the gRPC-based upgrade workflow (download → apply → reboot), session tracking, and error handling using both the upgrade-agent and gNOI server.

## Scope
This test targets SONiC systems running in three environments: local Linux VM, KVM-based SONiC, and physical SONiC devices. The purpose is to validate the compatibility and correctness of the upgrade service across these platforms, ensuring consistent behavior and reliability.

### Related DUT Configuration Files
upgrade_gNOI.yaml – YAML config file specifying upgrade parameters (image URL, save path, timeouts, etc.)

### Related APIs
gNOI RPCs: SystemInfo.GetPlatformType, Upgrade.Download, Upgrade.Apply, Upgrade.Status

## Test structure
### Setup Configuration
Deploy gNOI server on the target environment (Linux VM, KVM SONiC, or physical SONiC).
Build and install upgrade-agent on the testbed or control host.
Ensure gRPC port (default: 50051) is reachable from the agent.
Prepare a valid upgrade YAML configuration file.

### Configuration scripts
build_deploy.sh – deploys gNOI server container
upgrade-agent – CLI tool for upgrade operations

## Test cases
### Test case #1 - Local Linux VM Compatibility

#### Test objective

Verify that the upgrade service functions correctly in a local Linux VM environment.
1. Deploy gNOI server locally using build_deploy.sh.
2. Run grpcurl to list services and verify connectivity.
3. Use upgrade-agent download with a test file URL.
4. Use upgrade-agent apply with a dry-run config.
5. Use upgrade-agent status to track session progress.

### Test case #2 - KVM SONiC Compatibility

#### Test objective

Validate upgrade service behavior on a KVM-based SONiC device.
1. Deploy gNOI server and agent on KVM SONiC.
2. Run full upgrade flow: download → apply → reboot.
3. Verify session tracking and post-upgrade state.
4. Simulate failure (e.g., invalid URL) and verify error handling.

### Test case #3 - Physical SONiC Compatibility

#### Test objective

Ensure upgrade service works reliably on physical SONiC hardware.
1. Deploy gNOI server and agent on physical DUT.
2. Run upgrade with a real image and reboot.
3. Validate system health post-upgrade.
4. Test watchdog reboot and missing next-hop scenarios.

### Test case #4 - Negative Scenarios

#### Test objective

Test robustness of the upgrade service under failure conditions.
1. Use unreachable URL in download config.
2. Apply malformed YAML config.
3. Simulate TLS handshake failure.
4. Kill gNOI server mid-upgrade and observe behavior.
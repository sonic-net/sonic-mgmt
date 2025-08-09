- [Overview](#overview)
- [Scope](#scope)
- [Test structure](#test-structure)
- [Test scenario](#test-scenario)
- [Test cases](#test-cases)
# TestName
Upgrade Service via gNOI

## Overview
The goal of this test is to verify that the Upgrade Service, implemented via gNOI, functions correctly across different deployment environments. This includes validating the gRPC-based upgrade workflow (download → apply → reboot), and error handling using both the upgrade-agent and gNOI server.

## Scope
This test targets SONiC systems running in three environments: local Linux VM, KVM-based SONiC, and physical SONiC devices. The purpose is to validate the compatibility and correctness of the upgrade service across these platforms, ensuring consistent behavior and reliability.

### Related DUT Configuration Files
upgrade_gNOI.yaml – YAML config file specifying upgrade parameters (image URL, save path, timeouts, etc.)

### Related APIs
gNOI: System.SetPackage (download), File.TransferToRemote (download), File.Remove (clean up)
gNMI: gNMI.Get (for read operations such as detecting platform types)
Other custom rpc for Platform/Vendor/Version specific operations.

## Test structure
### Setup Configuration
Deploy gNOI server on the target environment (Linux VM, KVM SONiC, or physical SONiC).
Build and install upgrade-agent on the testbed or control host.
Ensure gRPC port is reachable from the agent.
Prepare a valid upgrade YAML configuration file.

### Configuration scripts
build_deploy script – build and deploy gnmi docker
upgrade-agent – CLI tool for upgrade operations

## Test scenario
1. PR testing(sonic-gnmi): This test runs in the sonic-gnmi repository to validate gNOI-related changes in a lightweight local Linux CI environment during pull requests.
2. KVM PR testing(sonic-buildimage) This test runs in the sonic-buildimage repository's pull request pipeline, using a KVM-based SONiC VM. It verifies that gNOI upgrade-related components.
3. Nightly testing(sonic-mgmt): This test is integrated into sonic-mgmt to perform full-system validation of gNOI functionality across physical SONiC devices during nightly regression.
## Test Fixture
### Test Fixture #1 - Local Linux VM Compatibility

#### Test objective

Verify that the upgrade service functions correctly in a local Linux VM environment. (Can run along with sonic-gnmi PR testing)
1. Deploy gNOI server locally using build_deploy.sh.
2. Run grpcurl to list services and verify connectivity.
3. Use upgrade-agent download with a test file URL.
4. Use upgrade-agent apply with a dry-run config.

### Test Fixture #2 - KVM SONiC Compatibility

#### Test objective

Validate upgrade service behavior on a KVM-based SONiC device.
1. Deploy gNOI server on DUT and agent on PTF server.
2. Run full upgrade flow: download → apply → reboot.
3. Verify session tracking and post-upgrade state.
4. Simulate failure (e.g., invalid URL) and verify error handling.

### Test Fixture #3 - Physical SONiC Compatibility

#### Test objective

Ensure upgrade service works reliably on physical SONiC hardware.
1. Deploy gNOI server and agent on PFT server.
2. gNOI server health check and client readiness check.
3. Run upgrade with a real image and reboot.
4. Validate system health post-upgrade.
5. Test watchdog reboot and missing next-hop scenarios.

### Test Fixture #4 - Negative Scenarios

#### Test objective

Test robustness of the upgrade service under failure conditions.
1. Use unreachable URL in download config.
2. Connection timeout.
3. APIs failure.
4. Apply malformed YAML config.
5. Simulate TLS handshake failure.
6. Kill gNOI server mid-upgrade and observe behavior.


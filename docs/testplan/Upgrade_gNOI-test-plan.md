- [Overview](#overview)
- [Background](#background)
- [Scope](#scope)
- [Test structure](#test-structure)
- [Test scenario](#test-scenario)
- [Test cases](#test-cases)
# TestName
Upgrade Service via gNOI

## Overview
The goal of this test is to verify that the Upgrade Service, implemented via gNOI, functions correctly across different deployment environments. This includes validating the gRPC-based upgrade workflow and error handling using both the upgrade-agent and gNOI server.

## Background
**Components:**
- **upgrade-agent(new)** (Client): CLI tool that reads YAML workflows and translates them to gNOI calls
- **gNOI Server(new)** (Server): Containerized gNOI service with mock platform implementations  
- **HTTP Firmware Server**: Serves test firmware files for download validation
- **Test Harness**: Coordinates test scenarios and validates results

## Scope
This test targets upgrades running in three environments: local Linux VM, KVM-based SONiC, and physical SONiC devices. The purpose is to validate the compatibility and correctness of the upgrade service across these platforms, ensuring consistent behavior and reliability.


### Related APIs
Server-side (gNOI)
- `gnoi.system.System.SetPackage`
  - Test individually: unit tests and grpcurl (stream semantics, request validation, error paths) against a mock gNOI server.  
  - Test combined: run with `upgrade-agent` + HTTP firmware server to validate streaming, remote-download → SetPackage flow, checksum verification, session state, and recovery on failures.
- `gnoi.system.System.GetStatus`
  - Test individually: grpcurl/unit tests to verify status payloads and error responses.  
  - Test combined: assert status reflects progress and post-upgrade health in integration runs.
- `gnoi.file.File.TransferToRemote` (file transfer API)  
  - Test individually: grpcurl streaming tests and mock-file-service unit tests (happy/error paths, partial writes).  
  - Test combined: agent-triggered transfers from HTTP server to DUT; verify integrity and resume behavior.
- `gnoi.file.File.Remove`
  - Test individually: grpcurl/unit tests for removal behavior and error codes.  
  - Test combined: cleanup step verification after aborted/failed upgrades.
- `grpc.reflection.v1alpha.ServerReflection`
  - Test individually: grpcurl discovery checks (service listing) as a quick health check.

Agent-side (upgrade-agent / workflow)
- `upgrade-agent apply` (including `--dry-run`)
  - Test individually: unit tests for YAML parsing, sequencing, CLI flags, and dry-run semantics (use `file://` or local stubs).  
  - Test combined: run against real gNOI servers + HTTP firmware server to validate end-to-end workflow execution.

workflow yaml example:
```yaml
# test-download-workflow.yml
apiVersion: sonic.net/v1
kind: UpgradeWorkflow
metadata:
  name: test-download
spec:
  steps:
    - name: download-test-firmware
      type: download
      params:
        url: "http://localhost:8080/test-firmware.bin"
        filename: "/tmp/test-firmware.bin"
        sha256: "d41d8cd98f00b204e9800998ecf8427e"
        timeout: 30
```

## Test structure
### Setup Configuration
1. Deploy gNOI server on Linux local host. (sonic-gnmi PR test only)
2. Build and install upgrade-agent.
3. Ensure gRPC port is reachable from the agent.

### Configuration scripts
upgrade-agent – CLI tool for upgrade operations

## Test scenario
1. PR testing(sonic-gnmi): This test runs in the sonic-gnmi repository to validate gNOI-related changes in a lightweight local Linux CI environment during pull requests.
2. KVM PR testing(sonic-buildimage) This test runs in the sonic-buildimage repository's pull request pipeline, using a KVM-based SONiC VM. It verifies that gNOI upgrade-related components.
3. Nightly testing(sonic-mgmt): This test is integrated into sonic-mgmt to perform full-system validation of gNOI functionality across physical SONiC devices during nightly regression, also test the entire pipeline including gnoi server and carry out an individual upgrade.

### Testbed setup & verification
Provide a reproducible recipe for preparing a testbed, deploying components, and verifying RPCs and post-upgrade state.

Testbed components
- Control host / Test controller (PTF or CI runner) running the workflow engine / `upgrade-agent` and test harness.
- Firmware server (HTTP/HTTPS) hosting test images.
- DUT running SONiC with gNOI server available (container or daemon).

## Setup Instructions

### 1. Deploy gNOI Server Container (Only for Linux local test - sonic-gnmi PR testing)

```bash
# Build and run gNOI server with mock platform support
docker build -t gnoi-server-test -f Dockerfile.test .
docker run -d \
  --name gnoi-test-server \
  -p 50051:50051 \
  -v /tmp/firmware:/firmware \
  -e PLATFORM_MODE=mock \
  gnoi-server-test

# Verify server is running
docker logs gnoi-test-server
# Expected: "gNOI server listening on :50051"
```

### 2. Install upgrade-agent

```bash
# Build upgrade-agent from source
cd cmd/upgrade-agent
go build -o upgrade-agent .
sudo install upgrade-agent /usr/local/bin/

# Verify installation
upgrade-agent version
# Expected: "upgrade-agent version v0.1.0"
```

### 3. Setup Test Firmware Server

```bash
# Create test firmware files
mkdir -p /tmp/firmware-server
echo "mock-firmware-v1.0" > /tmp/firmware-server/test-firmware.bin
echo "d41d8cd98f00b204e9800998ecf8427e" > /tmp/firmware-server/test-firmware.bin.sha256
# Start HTTP server
cd /tmp/firmware-server
python3 -m http.server 8080 &
HTTP_PID=$!

# Verify firmware accessible
curl -f http://localhost:8080/test-firmware.bin
# Expected: "mock-firmware-v1.0"
```

## Test Execution

### 1. Basic Connectivity Test

```bash
# Test gRPC service discovery
grpcurl -plaintext localhost:50051 list
```

Expected output:
```
gnoi.file.File
gnoi.system.System
grpc.reflection.v1alpha.ServerReflection
```

```bash
# Test specific service methods
grpcurl -plaintext localhost:50051 list gnoi.system.System
```

Expected output:
```
gnoi.system.System.SetPackage
gnoi.system.System.GetStatus
```
### 2. YAML Workflow Test

Create test workflow file:

```yaml
# test-download-workflow.yml
apiVersion: sonic.net/v1
kind: UpgradeWorkflow
metadata:
  name: test-download
spec:
  steps:
    - name: download-test-firmware
      type: download
      params:
        url: "http://localhost:8080/test-firmware.bin"
        filename: "/tmp/test-firmware.bin"
        sha256: "d41d8cd98f00b204e9800998ecf8427e"
        timeout: 30
```
Execute workflow test:
```bash
# Test workflow parsing and execution
upgrade-agent apply test-download-workflow.yml --target localhost:50051 --dry-run
```

Expected output:
```
✓ Workflow parsed successfully
✓ Connected to gNOI server at localhost:50051
✓ Dry-run: Would execute download step 'download-test-firmware'
→ URL: http://localhost:8080/test-firmware.bin
→ Target: /tmp/test-firmware.bin
→ Expected SHA256: d41d8cd98f00b204e9800998ecf8427e
```

```bash
# Execute actual workflow
upgrade-agent apply test-download-workflow.yml --target localhost:50051
```

Expected output:
```
✓ Starting workflow 'test-download'
✓ Step 1/1: download-test-firmware
→ Downloading from http://localhost:8080/test-firmware.bin
→ Progress: 15 bytes downloaded
→ SHA256 verification: PASS
→ File saved to /tmp/test-firmware.bin
✓ Workflow completed successfully
```

### 3. Error Condition Testing

```bash
# Test invalid URL
upgrade-agent apply --set url=http://invalid-host/firmware.bin test-download-workflow.yml --target localhost:50051
```

Expected output:
```
✗ Step 1/1: download-test-firmware
→ Error: Failed to download from http://invalid-host/firmware.bin
→ Cause: no such host
✗ Workflow failed
```

```bash
# Test checksum mismatch
upgrade-agent apply --set sha256=invalid-checksum test-download-workflow.yml --target localhost:50051
```

Expected output:
```
✗ Step 1/1: download-test-firmware
→ Downloaded 15 bytes successfully
→ SHA256 verification: FAILED
→ Expected: invalid-checksum
→ Actual: d41d8cd98f00b204e9800998ecf8427e
✗ Workflow failed
```

## Expected Results

### Success Indicators

1. **Service Discovery**: `grpcurl list` returns expected gNOI services
2. **Workflow Parsing**: YAML files parse without syntax errors
3. **Download Success**: Files download with correct checksums
4. **Status Reporting**: Progress updates appear during operations
5. **Error Handling**: Invalid inputs produce clear error messages

## Cleanup 
- Only required for Linux local test (sonic-gnmi PR test)
```bash
# Stop and remove containers
docker stop gnoi-test-server
docker rm gnoi-test-server

# Stop HTTP server
kill $HTTP_PID

# Clean test files
rm -rf /tmp/firmware-server /tmp/test-firmware.bin
```

## Test Fixture
### Test Fixture #1 - Local Linux VM Compatibility

#### Test objective

Verify that the upgrade service functions correctly in a local Linux VM environment. (Can run along with sonic-gnmi PR testing)
1. Deploy gNOI server locally.
2. Run grpcurl to list services and verify connectivity.
3. Use upgrade-agent download with a test file URL.
4. Use upgrade-agent apply with a dry-run config.

### Test Fixture #2 - KVM SONiC Compatibility

#### Test objective

Validate upgrade service behavior on a KVM-based SONiC device.
1. gNOI server health check and client readiness check.
```go
// Illustrative: open a SetPackage stream and send package metadata with SHA256 digest.
stream, err := client.SetPackage(ctx)
if err != nil { return err }

pkg := &system.SetPackageRequest{
 Request: &system.SetPackageRequest_Package{
  Package: &system.Package{
   Filename: "SONiC.bin",
   Version:  "SONiC-2025",
   RemoteDownload: &common.RemoteDownload{
    Path: "https://fw.test/SONiC.bin",
    Protocol: common.RemoteDownload_HTTP,
   },
   Hash: &types.Hash{ Type: types.Hash_SHA256, Value: sha256sum },
  },
 },
}
if err := stream.Send(pkg); err != nil { return err }
// handle responses...
```

2. Run full upgrade flow: download → apply.

### Test Fixture #3 - Physical SONiC Compatibility

#### Test objective

Ensure upgrade service works reliably on physical SONiC hardware.
1. gNOI server health check and client readiness check.
3. Run upgrade with a real image and reboot.
4. Validate system health post-upgrade.
5. Test watchdog reboot and missing next-hop scenarios.

### Test Fixture #4 - Negative Scenarios

#### Test objective

Test robustness of the upgrade service under failure conditions.
1. Use unreachable URL in download config.
2. Connection timeout.
3. APIs failure.

### Antagonist (sad-case) scenarios
Run these negative setups per scenario to validate error handling and robustness. Each antagonist defines: setup, expected behavior, and verification.

1) Low disk space on DUT
- Setup: create a temporary file system to below required threshold.
- Expected: download should fail or agent should detect insufficient space and abort cleanly with explicit error.
- Verify: agent returns ENOSPC-like error; no partial install left behind; logs show clear failure reason.

```sh
# Simulate low disk
fallocate -l 4G /tmp/fillfile
# Disable mgmt interface
ip link set dev eth0 down
# Block firmware server
iptables -A OUTPUT -d ${FW_IP} -j REJECT
# Corrupt image (serve wrong content)
# Kill gNOI server during transfer
pkill -f gnmi-server
```

2) No management interface (e.g., eth0 down)
- Setup: administratively disable DUT management interface.
- Expected: control host cannot open gRPC connection; agent times out with clear connectivity error.
- Verify: grpc connection attempts fail; test harness records timeout; recovery steps are documented.

3) No route to firmware server
- Setup: block firmware server via iptables or remove route on DUT/control host.
- Expected: remote download fails with network error; agent retries according to policy and then errors out.
- Verify: agent error codes indicate network/dns failure; download sessions are cleaned up.

4) Corrupt or tampered image (checksum mismatch)
- Setup: serve an image whose contents do not match provided SHA‑256 digest (or omit digest).
- Expected: server or DUT verifies digest and rejects image; install not performed.
- Verify: checksum mismatch logged; installation not started; proper error returned.

5) TLS / certificate failures
- Setup: present incorrect TLS certs or force TLS mismatch between agent and gNOI server.
- Expected: TLS handshake fails and gRPC connections are rejected.
- Verify: agent logs show TLS errors; no sensitive fallback to plaintext.

6) gNOI server killed mid-upgrade
- Setup: start a normal download, then kill/restart the gNOI server process on DUT during transfer/install.
- Expected: agent detects stream error, marks session incomplete, and records state for resumption where supported.
- Verify: session state is persisted; subsequent attempts either resume or fail with clear diagnostics.

7) Disk corruption / I/O errors
- Setup: emulate I/O errors or remove media during file write.
- Expected: write fails; agent reports I/O error and cleans up partial files.
- Verify: partial files removed; logs include I/O error details.

Notes
- Each scenario should include automation where possible (Ansible or test scripts) so PR-level tests can inject antagonists reliably.
- Add per-scenario timeouts and retries to avoid false positives due to transient lab issues.

### Test examples & code snippets
Practical snippets and checks to include in test cases and automation.

1) gNOI sanity checks (grpcurl)
```sh
# List services (plaintext test)
grpcurl -plaintext DUT:50051 list
# Describe the System service or method
grpcurl -plaintext DUT:50051 describe System.SetPackage
```

2) Go helper: compute SHA‑256
```go
func computeSHA256(path string) ([]byte, error) {
 f, err := os.Open(path); if err!=nil { return nil, err }
 defer f.Close()
 h := sha256.New()
 if _, err := io.Copy(h, f); err!=nil { return nil, err }
 return h.Sum(nil), nil
}
```

3) Verification commands to include in tests
```sh
# Check file integrity on DUT
sha256sum /tmp/SONiC.bin
# Ensure gNOI service lists System and File services
grpcurl -plaintext DUT:50051 list
# Query version/state via gNMI (example)
# gnmi-client get --target DUT --path /sonic/system/version
```
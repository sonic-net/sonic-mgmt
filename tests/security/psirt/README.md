# SONiC Security Property Regression Tests

These tests use standard sonic-mgmt Ansible/pytest DUT fixtures and contain no platform addresses, credentials or device certificate material.

## Database Isolation

`test_database_isolation.py` checks container privilege reduction, host device isolation, added/effective capabilities, namespace isolation and Redis PING without changing configuration. A per-testbed `database_capability_allowlist` can document explicitly approved capabilities with a reason; added capabilities are denied by default.

## Hardware-Free Checks

Adapter initialization and capability detection use synthetic objects without contacting a DUT. Device-path and mapping helpers validate metadata handling without hardware.

## Platform Adapter

Platform security behavior varies across SONiC images. The remaining cases call a separately supplied adapter using:

```text
get_psirt_adapter() -> adapter
adapter.capabilities(duthost) -> {capability: true | explanation}
```

Only advertise supported, non-mutating operations. Missing adapters/capabilities report pytest skips with a `BLOCKED` reason; invalid adapter implementations fail setup. Do not count blocked checks as passes.

Adapter factories and capability discovery must be side-effect-free. Operations must enforce deadlines and close connections and remove temporary resources in `finally` blocks or context managers. The suite does not own the sonic-mgmt DUT fixtures or change their teardown. Use a bounded external test runner; after a timeout, clean up only its specifically named validation container. Missing configured modules and invalid adapter implementations are setup failures, not authorization denials.

The optional capabilities are `security_health` and `broker_policy`:

- `security_health(duthost, ansible_adhoc)` returns a mapping with `status` equal to `pass`, `fail`, or `timeout`, and an optional non-sensitive `reason`. Invoke only the existing authorized device-security health interface without changing security state or exposing identity credentials. Create a separate `ansible_adhoc(become=False, host_pattern=duthost.hostname)` session and verify the caller is non-root. Timeout is reported as `BLOCKED`.
- `broker_policy(duthost)` returns a nonempty mapping of documented, named least-privilege and defense-in-depth configuration checks to Boolean results. Inspect only existing service/socket configuration. Expectations belong to the supported platform design; no common service names, socket modes or privileges are assumed.

## Collection

The isolated unit/collection entry point avoids importing unrelated root-level sonic-mgmt plugins. It does not provide DUT fixtures and must not be used for device execution:

```sh
env PYTHONPATH="$PWD" pytest --confcutdir=tests/security/psirt --collect-only tests/security/psirt
env PYTHONPATH="$PWD" pytest --confcutdir=tests/security/psirt tests/security/psirt -k 'initialization or capability_detection or device_path or mapping'
```

For hardware runs, use the normal sonic-mgmt root `tests/conftest.py`, the existing inventory/testbed, and an approved adapter module:

```sh
pytest tests/security/psirt \
  --psirt-adapter-module=<approved_adapter_module> \
  --inventory=<existing_inventory> \
  --testbed=<existing_testbed> \
  --testbed_file=<existing_testbed_file> \
  --junitxml=<results>/psirt.xml
```

The root sonic-mgmt test environment must have its normal PTF dependencies (including `nnpy`/nanomsg development headers) installed before collection. No dependency is installed on a DUT.

## Security Test Scope and Limitations

This suite provides portable, non-destructive checks of selected security properties and supported platform functionality. It does not attempt to reproduce vulnerabilities through unauthorized cryptographic signing, privileged management mutations, malformed hardware requests, or TPM/PCR state changes.

Arbitrary private-key signing probes, credential registration or permission changes, state-changing administrative probes, PCR extend/reset, malformed live cryptographic requests and deliberate buffer-overflow exploitation on hardware are excluded. These cases are not represented as inactive tests in this suite.

Exploit-oriented negative tests, input-boundary fuzzing, integer-truncation prevention and memory-boundary safety are expected to be validated in isolated component-level environments using mocks, sanitizers or dedicated harnesses.

Passing this suite does not independently establish comprehensive security remediation or replace component-level vulnerability regression testing. Optional health and configuration checks do not imply that all platforms implement the same hardware-security services.

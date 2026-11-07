# SONiC PSIRT Regression Tests

These tests contain no lab addresses, credentials, device certificates, private keys or Cisco-only assumptions. They use the normal sonic-mgmt Ansible/pytest DUT fixtures.

## Database Isolation

`test_database_isolation.py` is the portable MIGSOFTWAR-47503 check. It inspects all running database containers for privileged mode, `/dev`/TPM mappings, added/effective capabilities and host namespaces, then verifies each Redis endpoint responds. A per-testbed `database_capability_allowlist` may document explicitly approved capabilities; the default is deny-all added capabilities. The pure mapping checks require no device.

## Platform Adapter

Platform security behavior varies across SONiC images. The remaining cases call a separately supplied adapter using:

```text
get_psirt_adapter() -> adapter
adapter.capabilities(duthost) -> {capability: true | explanation}
```

Only advertise a capability when the operation is supported and safe. A missing adapter or capability is reported as a pytest skip with a `BLOCKED` reason. Do not send unsupported, malformed, registration, permission, administrative or state-changing TAM operations just to force a result.

Adapter factories and capability discovery must be side-effect-free. Operations must enforce deadlines and close connections and remove temporary resources in `finally` blocks or context managers. The suite does not own the sonic-mgmt DUT fixtures or change their teardown. Use a bounded external test runner; after a timeout, clean up only its specifically named validation container. Missing configured modules and invalid adapter implementations are setup failures, not authorization denials.

The adapter contract covers authorized fixed SUDI health, non-root arbitrary-signing denial, broker/socket sandbox policy, offline missing/malformed/untrusted/mismatched-certificate regressions, safe registration/permissions denial, safe admin denial, isolated PCR length tests, and an optional supported read-only PCR read. For the health request, the test also passes sonic-mgmt's `ansible_adhoc` fixture; the platform adapter must create a separate `ansible_adhoc(become=False, host_pattern=duthost.hostname)` session, verify `id -u` is nonzero, and then send exactly one fixed request. A PCR timeout is `BLOCKED`; this suite never issues PCR extend/reset or malformed live input.

Certificate fault injection and PCR parser/callout unit tests belong in the owning platform/security package test suites; they do not mutate a live DUT. The sonic-mgmt adapter must report those offline results without reading or exporting private keys, credentials, certificates or signatures.

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

## Remaining Hardware Coverage

Code review readiness is separate from complete security remediation. The current qualification still lacks four hardware capabilities:

- Safe direct arbitrary-SUDI-signing authorization denial before backend dispatch.
- Non-mutating registration and permission-change authorization probes.
- Safe direct TAM administrative authorization denial with a positive control.
- A supported bounded read-only PCR operation; the previous read timed out.

Forbidden broker-command rejection is not a substitute for these authorization checks. Offline certificate and PCR regressions do not establish deployed-image inclusion or complete remediation. TAM-library PR #25 remains outside the current image qualification. `BLOCKED` pytest skips must remain separate from successful tests in result summaries.
# [Bug] Testbed health check fails on BMC testbeds due to incorrect critical container defaults

## Description
`.azure-pipelines/testbed_health_check.py` currently defaults critical containers to `syncd`, `swss`, and `bgp`. On BMC testbeds, those containers are not present, so the health check reports false failures even when the BMC system is healthy.

## Current BMC running containers
- `gnmi`
- `pmon`
- `telemetry`
- `sysmgr`
- `redfish`
- `acms`
- `database`

## Steps to Reproduce
1. Run `.azure-pipelines/testbed_health_check.py` against a BMC testbed.
2. Let `check_critical_containers_running()` use default container list.
3. Observe failure logs for missing `syncd/swss/bgp`.

## Expected Result
For BMC testbeds, default critical containers should match the BMC container set.

## Actual Result
Health check fails due to checking SONiC switch containers (`syncd/swss/bgp`) that do not exist on BMC.

## Impact
- False-negative health checks on BMC environments.
- Potential testbed skip/failure in CI despite healthy BMC services.

## Proposed Fix
Detect BMC testbeds (for example by testbed name containing `bmc`) and switch default critical container list to:
- `gnmi`
- `pmon`
- `telemetry`
- `sysmgr`
- `redfish`
- `acms`
- `database`

## Additional Context
A local patch has already validated this direction by adding `is_bmc_testbed` logic and BMC-specific defaults in `.azure-pipelines/testbed_health_check.py`.

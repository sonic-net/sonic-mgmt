# Module Firmware Upgrade Test Plan

## Overview

This test validates invalid firmware installation, firmware downgrade, and firmware upgrade for optical modules and active optical cables. Daily regression selects one physical module for each part number using the existing regression seed, while weekend regression covers every physical module.

## Scope

- All optical modules and active optical cables detected on the DUT. A case is skipped when its part number has no firmware configuration.
- Firmware upgrade, downgrade, and invalid firmware installation.
- Firmware version, module health, and firmware-related error logs.

## Firmware Configuration

Module firmware metadata is stored separately from the existing platform component firmware configuration:

```text
tests/platform_tests/module_fw/module_firmware.json
```

The repository contains an empty configuration:

```json
{}
```

A test environment can provide a populated file with `--module-fw-file <path>`. The file maps each exact vendor part number to its latest and base firmware:

```json
{
  "EXAMPLE-PN": {
    "latest": {
      "version": "2.0.0",
      "path": "/path/to/latest.bin"
    },
    "base": {
      "version": "1.0.0",
      "path": "/path/to/base.bin"
    }
  }
}
```

The test looks up firmware by exact vendor part number and does not infer compatibility from similar part numbers. Before each case, the required files are validated on the test controller, copied to a temporary directory on the DUT, and removed after the case.

Only a part number absent from the configuration causes that module's case to be skipped. Once a part number is configured, missing `version` or `path` properties, unreadable firmware files, invalid JSON, or an invalid field format cause a failure.

The configuration must be updated whenever a new module or firmware version is added; otherwise, the corresponding part number's case is skipped.

## Module Selection

1. Create one parameterized case for each candidate physical port and deduplicate breakout interfaces that share one physical module.
2. Read the vendor part number, serial number, and current firmware version, and select optical modules and active optical cables.
3. Record the DUT, physical port, and part number in the result of each independent module case.
4. Daily regression groups modules by part number and uses the existing regression seed to select one physical module per group. Weekend regression selects all physical modules.

## Test Sequence

For every module with complete firmware configuration, run:

1. Invalid firmware installation
2. Downgrade to the base firmware
3. Upgrade to the latest firmware

Downgrade and upgrade run in the same case. A `finally` block attempts to restore the latest firmware so the module is not left on the base version.

## Test Cases

### Invalid Firmware

1. Record the current firmware version and module state.
2. Select the latest firmware configured for another part number with a different firmware major version. Fail if the target part number is configured but no candidate is available.
3. Copy the firmware to the DUT and attempt installation.
4. Verify that installation fails and the firmware version remains unchanged.
5. Verify that the module remains operational and no new unexpected firmware-related error is logged.

**Expected result:** The invalid firmware is rejected, the original firmware version is unchanged, and the module remains operational.

### Firmware Downgrade and Upgrade

1. Read the current firmware version and install the latest firmware first when a known newer starting point is required.
2. Install the base firmware and verify its version.
3. Verify module health and firmware-related logs.
4. Install the latest firmware and verify its version.
5. Verify module health and firmware-related logs again.
6. Attempt to restore the latest firmware during cleanup regardless of earlier failures, and report the restoration result.

**Expected result:** Downgrade and upgrade succeed, and the module is operational on the latest firmware when the test completes.

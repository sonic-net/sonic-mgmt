# BMC Firmware Upgrade Test Plan

## Related Documents

| **Document Name** | **Link** |
|-------------------|----------|
| SONiC fwutil HLD | [fwutil.md](https://github.com/sonic-net/SONiC/blob/master/doc/fwutil/fwutil.md) |
| Support BMC HLD | [PR #2062](https://github.com/sonic-net/SONiC/pull/2062) |
| BMC High-Level Test Plan | [BMC-high-level-test-plan.md](BMC-high-level-test-plan.md) |
| FWUtil Test Plan (generic) | [FWUtil-test-plan.md](../FWUtil-test-plan.md) |

## Definitions

| **Term** | **Description** |
|----------|-----------------|
| BMC | Baseboard Management Controller |
| fwutil | SONiC firmware CLI utility used to show/install/update platform component firmware |
| .fwpkg | Firmware package file |

## Overview

The Baseboard Management Controller (BMC) runs its own firmware, which can be updated in the field through the standard SONiC `fwutil` interface. During an update, the firmware package is uploaded to the device and validated
before it is applied, and the new firmware takes effect only after a reboot. If the firmware package fails validation or the update cannot be completed, the BMC keeps its previously installed firmware and remains functional,
so the device is never left in an unusable state.

This test plan verifies that `fwutil` correctly performs and reports BMC firmware upgrades, rejects invalid or unauthorized updates, and leaves the device in a safe, unchanged state when an update cannot be completed. It reuses the existing vendor-agnostic fwutil test framework under `tests/platform_tests/fwutil/` by adding BMC as a testable component, and adds BMC-specific cases for behaviors the generic plan does not cover.

## Test Cases

### Test Case 1: BMC Firmware Upgrade via `fwutil install`

**Objective**: Verify `fwutil install` upgrades the BMC firmware from an older version to a newer version, and that the user is informed a reboot is required to activate it.

**Test Steps**
1. Run `fwutil show status` and record the current BMC firmware version.
2. Copy the target BMC firmware package to the DUT.
3. Run `fwutil install chassis component BMC fw <path-to-fwpkg>` and confirm the command completes successfully.
4. Verify the command output informs the user that a reboot is required to activate the new BMC firmware.
5. Reboot the device to activate the firmware, and wait for the BMC to come back online.
6. Run `fwutil show status` again and verify the BMC version now matches the target version.
7. Restore the BMC to its original firmware version.

---

### Test Case 2: BMC Firmware Upgrade via `fwutil update`

**Objective**: Verify `fwutil update` upgrades the BMC firmware to a newer version using the firmware metadata (`platform_components.json`) staged in the SONiC image.

**Test Steps**
1. Run `fwutil show status` and record the current BMC firmware version.
2. Generate a `platform_components.json` describing the target BMC firmware, and stage it together with the firmware package into the current SONiC image on the DUT.
3. Run `fwutil update chassis component BMC fw -y` and confirm the command completes successfully with no errors.
4. Reboot the device to activate the firmware, and wait for the BMC to come back online.
5. Run `fwutil show status` and verify the BMC version now matches the target version.
6. Restore the BMC to its original firmware version.

---

### Test Case 3: BMC Firmware Version Policy (same / older / forced downgrade)

**Objective**: Verify `fwutil` enforces version policy for BMC firmware: it refuses to install the same version, refuses to downgrade to an older version, and allows a downgrade only when the `--force` flag is used.

**Test Steps**
1. Run `fwutil show status` and record the current BMC firmware version.
2. **Same version** - attempt to install the firmware package whose version equals the currently installed version. Verify the command is rejected and the BMC version remains unchanged.
3. **Older version** - attempt to downgrade to a firmware package whose version is older than the currently installed version, without `--force`. Verify the command is rejected and the BMC version remains unchanged.
4. **Forced downgrade** - repeat step 3 with the `--force` flag. Verify the command is accepted, and after the required reboot the BMC reports the older (downgraded) version.
5. Restore the BMC to its original firmware version.

---

### Test Case 4: Reject Invalid BMC Firmware Input

**Objective**: Verify `fwutil` refuses to upgrade the BMC when given invalid firmware, and leaves the installed version unchanged. Three invalid inputs are covered: a file that is not a firmware package, a corrupted firmware package, and a valid package intended for a different device.

**Test Steps**
1. Run `fwutil show status` and record the current BMC firmware version.
2. **Not a firmware package** - provide a non-firmware file (e.g. a text file renamed to `.fwpkg`) and run `fwutil install chassis component BMC fw <path>`. Verify a non-zero exit code and an error indicating the file is not a valid firmware package.
3. **Corrupted package** - take a valid BMC `.fwpkg`, corrupt its contents, and run the install command. Verify a non-zero exit code and a rejection error. After the attempt, verify the BMC is still reachable and its services are up (the failed update did not brick the device).
4. **Mismatched device** - provide a valid firmware package intended for a different BMC flavor/device and run the install command. Verify a non-zero exit code and an error indicating the package does not apply to this device.
5. After each attempt, run `fwutil show status` and verify the BMC firmware version is unchanged from step 1.

---

### Test Case 5: Verify BMC Firmware In Log And Techsupport

**Objective**: Verify that `show techsupport` captures the BMC firmware version both before and after an upgrade, and that the firmware upgrade operation is recorded in the system log.

**Test Steps**
1. Run `fwutil show status` and record the current BMC firmware version.
2. Generate a support dump with `show techsupport` and verify it captures the current BMC firmware version information.
3. Upgrade the BMC firmware to a different version (via `fwutil install` or `fwutil update`) and reboot to activate it.
4. Generate a support dump with `show techsupport` again and verify it now captures the new (upgraded) BMC firmware version information.
5. Check the system log via `show logging` and verify the BMC firmware upgrade operation is recorded.
6. Restore the BMC to its original firmware version.

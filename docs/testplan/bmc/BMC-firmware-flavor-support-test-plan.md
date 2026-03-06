# BMC Firmware Flavor Support Test Plan

## Related Documents

| **Document Name** | **Link** |
|-------------------|----------|
| Support BMC HLD | [PR #2062](https://github.com/sonic-net/SONiC/pull/2062) |
| BMC Flow Support Test Plan | [BMC-flow-support-test-plan.md](BMC-flow-support-test-plan.md) |

## Definitions/Abbreviation

| **Term** | **Description** |
|----------|-----------------|
| BMC | Baseboard Management Controller |
| Flavor | BMC hardware variant (e.g., AST2600, AST2700-A1), each requiring a different firmware package |

## Background

BMC firmware upgrade tests today select firmware packages by chassis SKU from `tests/platform_tests/fwutil/firmware.json`. The goal is to support multiple BMC flavors per SKU: the same chassis (e.g., SN6600_LD) can ship with different BMC chips (AST2600 or AST2700), and each flavor needs a different firmware package. The test plan adds a flavor layer under BMC so the correct package is chosen at runtime.

## Scope

Extend `firmware.json` to support per-flavor BMC firmware definitions, add runtime flavor detection, and update all existing BMC upgrade code paths accordingly. No backward compatibility with the legacy flat-list BMC format.

## Proposed Solution

### Target `firmware.json` Structure

The file is organized by `chassis` (platform/SKU). Under each chassis, `component` holds firmware entries per component type. For BMC, a flavor layer is introduced: each flavor key (e.g. `AST2600`, `AST2700-A1`) maps to a list of firmware items; `[0]` is the latest version, `[1]` the old version for downgrade testing.

Full structure (BMC section expanded to show flavor):

```json
{
    "images": { ... },
    "chassis": {
        "SN6600_LD": {
            "component": {
                "BIOS": [ ... ],
                "ONIE": [ ... ],
                "CPLD2": [ ... ],
                "BMC": {
                    "AST2600": [
                        {
                            "firmware": "http://.../sw_bmc_arm_spc6_ast2600_88.0060.0205.fwpkg",
                            "version": "88.0060.0205",
                            "reboot": ["power off"]
                        },
                        {
                            "firmware": "http://.../sw_bmc_arm_spc6_ast2600_88.0060.0081.fwpkg",
                            "version": "88.0060.0081",
                            "reboot": ["power off"]
                        }
                    ],
                    "AST2700-A1": [
                        {
                            "firmware": "http://.../sw_bmc_arm_spc6_ast2700_a1_xxx.fwpkg",
                            "version": "...",
                            "reboot": ["power off"]
                        },
                        { ... }
                    ]
                }
            }
        }
    },
    "host": { ... }
}
```

Hierarchy: **chassis (platform/SKU)** → **component** → **BMC** → **flavor** → **list of {firmware, version, reboot}**.

### Flavor Detection

Add a helper `get_bmc_flavor()` in `firmware_helper.py`: read BMC IP from the per-platform `bmc.json`, SSH from the DUT to the BMC, run `uname -a`, and parse the flavor from the hostname. The hostname follows the pattern `{platform}-{flavor}-bmc`:

**AST2600:**
```
root@spc6-ast2600-bmc:~# uname -a
Linux spc6-ast2600-bmc 6.12.41-743dcf5-dirty-c737c9a-gc737c9a992b5 #1 SMP Fri Nov 21 19:14:19 UTC 2025 armv7l GNU/Linux
```

**AST2700-A1:**
```
root@spc6-ast2700-a1-bmc:~# uname -a
Linux spc6-ast2700-a1-bmc 6.12.59-dirty-8017a42adc2b-11559-g8017a42adc2b #1 SMP PREEMPT Thu Jan 29 07:37:32 UTC 2026 aarch64 GNU/Linux
```

Extracted flavor: `spc6-ast2600-bmc` → `ast2600`, `spc6-ast2700-a1-bmc` → `ast2700-a1`. Normalize to uppercase (e.g. `AST2600`, `AST2700-A1`) when looking up in `firmware.json`.

### Upgrade Flow

1. Load `firmware.json` via `--fw-pkg`
2. Get chassis name from DUT (`fwutil show status`)
3. SSH to BMC, run `uname -a`, extract flavor from hostname
4. Read `chassis[chassis].component.BMC[flavor]` from firmware.json
5. Select target version, upgrade, and verify version after update

## File Changes

| **File** | **Change** |
|----------|-----------|
| `tests/platform_tests/fwutil/firmware.json` | Add flavor layer under BMC entries for multi-flavor SKUs |
| `tests/common/helpers/firmware_helper.py` | Add `get_bmc_flavor()` and `get_bmc_firmware_list(fw_pkg, chassis, flavor)` to resolve BMC firmware list from `chassis[chassis].component.BMC[flavor]` |
| `tests/platform_tests/api/test_bmc.py` | Update `recover_bmc_firmware` and `test_bmc_firmware_update` to resolve flavor before indexing BMC firmware list |

## Impact on Existing Test Cases

The following existing test cases in `test_bmc.py` require modification to add flavor resolution before accessing the BMC firmware list:

### `test_bmc_firmware_update`

Currently accesses `fw_pkg["chassis"][chassis]["component"]["BMC"][idx]` directly. Insert a flavor resolution step before this access:
- Detect BMC flavor via `get_bmc_flavor()`
- Use `get_bmc_firmware_list()` to get the firmware list for the detected flavor
- Then index into the list as before (`[LATEST_BMC_VERSION_IDX]`, `[OLD_BMC_VERSION_IDX]`)

### `recover_bmc_firmware` fixture

Same change — resolve flavor before reading `fw_pkg["chassis"][chassis]["component"]["BMC"][flavor][0]`.

## New Test Cases

### PLDM Firmware Package Support

In addition to `.fwpkg`, some BMC flavors use PLDM (Platform Level Data Model) firmware packages. The upgrade flow must support both.

- Configure a BMC flavor in `firmware.json` with a PLDM firmware package path
- Run the BMC firmware upgrade test on a device whose flavor uses that PLDM package
- Verify the PLDM package is downloaded and installed and the BMC version is updated correctly

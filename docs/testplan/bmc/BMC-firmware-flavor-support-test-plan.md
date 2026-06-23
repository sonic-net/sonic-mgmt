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

For BMC, a flavor layer is introduced under each chassis: each flavor key (e.g. `AST2600`, `AST2700-A1`) maps to a list of firmware items; `[0]` is the latest version, `[1]` the old version for downgrade testing.

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

Hierarchy: **chassis** → **component** → **BMC** → **flavor** → **list of {firmware, version, reboot}**.

### Flavor Detection

`resolve_bmc_flavor()` resolves the flavor for a given chassis. If only one flavor is defined in `firmware.json`, it returns directly. If multiple flavors exist, it SSHes from the DUT to the BMC, runs `uname -a`, and parses the flavor from the hostname pattern `{platform}-{flavor}-bmc` (e.g. `spc6-ast2600-bmc` → `AST2600`).

### Upgrade Flow

1. Load `firmware.json`, get chassis name from DUT
2. Call `get_bmc_firmware_list(fw_pkg, chassis, duthost, bmc_ip)` — internally resolves flavor and returns the firmware list
3. Select target version, upgrade, and verify version after update

## File Changes

| **File** | **Change** |
|----------|-----------|
| `tests/platform_tests/fwutil/firmware.json` | Convert BMC entries from flat list to flavor-keyed dict |
| `tests/common/helpers/firmware_helper.py` | Add flavor detection and resolution helpers; update existing BMC info lookup to require flavor |
| `tests/platform_tests/api/test_bmc.py` | Use flavor-aware helper to get BMC firmware list instead of direct dict access |
| `ngts/tests/nightly/sanity_checker/test_sanity_checker.py` | Add flavor resolution to BMC version check flow |

## New Test Cases

### PLDM Firmware Package Support

In addition to `.fwpkg`, some BMC flavors use PLDM (Platform Level Data Model) firmware packages. The upgrade flow must support both.

- Configure a BMC flavor in `firmware.json` with a PLDM firmware package path
- Run the BMC firmware upgrade test on a device whose flavor uses that PLDM package
- Verify the PLDM package is downloaded and installed and the BMC version is updated correctly

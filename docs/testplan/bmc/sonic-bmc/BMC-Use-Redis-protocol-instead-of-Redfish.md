# Switch-host and SONiC BMC to use Redis protocol instead of Redfish Test Plan

---

## Background

The SONiC running on the Switch-Host needs to read identity and status
information from the BMC - model, serial number, EEPROM contents and health
state. The original BMC design assumed the BMC runs **OpenBMC** and
reached it through the **Redfish RESTful API**.

When the BMC runs **SONiC BMC** instead, the **Redis DB is the source of truth**, so the Switch-Host reads the platform data from the **Redis DB on the BMC** instead.

Because the same BMC hardware may be install as sonic bmc or openbmc, the
Switch-Host cannot determine the correct path on its own. A configuration field
is introduced to select it explicitly, together with a pair of CLI commands to get
and set that field.

``` bash
admin@sonic:~$ sudo config bmc os sonic
BMC OS set to sonic

admin@sonic:~$ show platform bmc os
sonic

admin@sonic:~$ sudo show runningconfiguration all | jq .DEVICE_METADATA.bmc
{
  "os": "sonic"
}
```



---

## Test Cases

This test plan covers the feature. It verifies two areas:
- Group A: the new cases added for this feature.
- Group B: the existing BMC platform API cases that must be adapted to run correctly on SONiC BMC.

---

### Group A - New Test Cases

**File**: `tests/platform_tests/api/test_bmc_os.py` (new module)

#### Test Case #1: test_bmc_os_cli

**Objective**: Verifies the `show platform bmc os` and `config bmc os` CLI commands: the default
value, the accepted values, input validation, consistency with CONFIG_DB, and
persistence across `config reload`.

**Test Steps**:
1. **Default value** - remove only the `os` field from the `DEVICE_METADATA|bmc`
   entry in CONFIG_DB and run `show platform bmc os`. It should return the default
   value `sonic`. The rest of the entry is left alone: on some platforms it also
   carries the host-to-BMC link parameters.
2. **Valid values** - for each of `sonic` and `openbmc`: run
   `config bmc os <value>`, then verify that both `show platform bmc os` and the
   `DEVICE_METADATA|bmc` `os` field in CONFIG_DB return exactly that value.
3. **CONFIG_DB consistency** - write the `os` field directly to CONFIG_DB,
   bypassing the CLI, and verify `show platform bmc os` reports the written value.
   Guards against the CLI serving a cached or hard-coded default.
4. **Invalid values** - run `config bmc os` with an unknown word and an empty
   string. Each invocation is rejected with a non-zero return code and a message
   naming the accepted values, and the stored value is left untouched. A value
   differing only in case is normalized, so CONFIG_DB never holds an unnormalized
   value.

---

#### Test Case #2: test_bmc_eeprom_matches_bmc_redis

**Objective**: Verifies the correctness of the data returned by `get_eeprom()` on SONiC BMC by
comparing it against the source table read directly on the BMC. The existing
`test_get_eeprom` case only proves the Switch-Host returns a well-formed
dictionary consistent with its own CLI output; it cannot prove those values
actually originate from the BMC. This case closes that gap.

**Test Steps**:
1. **Read eeprom on BMC** - From the Switch-Host, read the `EEPROM_INFO` table out of
   the BMC STATE_DB over the host-to-BMC link: `redis-cli -h <bmc_addr> -n 6`, with
   `<bmc_addr>` taken from `bmc.json`. Check `EEPROM_INFO|State` reports the table is
   initialized before reading it.
2. **Read eeprom on Switch-Host** - Run `show platform bmc eeprom` on switch.
3. **Compare** - each field must match the TLV it is served from:

   | Switch-Host field | Source on the BMC                                                                    |
   |-------------------|--------------------------------------------------------------------------------------|
   | `Model`           | `EEPROM_INFO` TLV `0x21`                                                             |
   | `PartNumber`      | `EEPROM_INFO` TLV `0x22`                                                             |
   | `SerialNumber`    | `EEPROM_INFO` TLV `0x23`                                                             |
   | `Manufacturer`    | `EEPROM_INFO` TLV `0x2b`                                                             |
   | `Revision`        | `EEPROM_INFO` TLV `0x27`, reported by `get_eeprom()` but not printed by the CLI       |
   | `PowerState`      | Not held in the EEPROM - derived from BMC reachability, so it is excluded from the comparison |

---

### Group B - Existing Test Cases

**File**: `tests/platform_tests/api/test_bmc.py` (existing cases)

Run the existing BMC platform API cases on SONiC BMC.

#### 1. Supported on SONiC BMC - data served over Redis

| Test case            | API / CLI under test                                             | On SONiC BMC     |
|----------------------|------------------------------------------------------------------|------------------|
| `test_get_name`      | `get_name()`                                                     | Assertion kept   |
| `test_get_presence`  | `get_presence()`                                                 | Assertion kept   |
| `test_get_status`    | `get_status()`                                                   | Assertion kept   |
| `test_is_replaceable`| `is_replaceable()`                                               | Assertion kept   |
| `test_get_model`     | `get_model()`, cross-checked against `show platform bmc eeprom`  | Assertion kept   |
| `test_get_serial`    | `get_serial()`, cross-checked against `show platform bmc summary`| Assertion kept   |
| `test_get_eeprom`    | `get_eeprom()` and `show platform bmc eeprom`                    | Assertion kept   |
| `test_get_revision`  | `get_revision()`                                                 | **Assertion must be updated** |

`test_get_revision` currently asserts the revision is `N/A`, which is what the Redfish path
returns because it has no revision to report. Over Redis the revision is served from the
EEPROM Label Revision TLV (`0x27`), so the case has to expect the value `get_eeprom()`
reports and keep the `N/A` expectation for OpenBMC only.



#### 2. Not applicable on SONiC BMC - need skip them

| Test case                             | API / CLI under test                                                            |
|---------------------------------------|----------------------------------------------------------------------------------|
| `test_get_version`                    | `get_version()`, and the `FirmwareVersion` field of `show platform bmc summary`   |
| `test_reset_root_password`            | `reset_root_password()`                                                          |
| `test_reset_root_password_cli`        | `config bmc reset-root-password`                                                 |
| `test_bmc_dump`                       | `trigger_bmc_debug_log_dump()`, `get_bmc_debug_log_dump()`                       |
| `test_bmc_firmware_update`            | `update_firmware()`, `config platform firmware install chassis component BMC fw` |
| `test_bmc_session_open_close`         | `config bmc open-session`, `config bmc close-session`                            |
| `test_bmc_commands_on_non_bmc_switch` | `config bmc` command family; the case targets platforms with no BMC at all       |

`test_bmc_commands_on_non_bmc_switch` needs no change: it is already skipped wherever a BMC
is present, regardless of which OS that BMC runs. The other six need an explicit skip when
the BMC OS is `sonic`.


#### 3. OpenBMC regression
The same testcases should run on OpenBMC platform, where every case must keep passing with its original assertions.


---

## Refer

The following design documents are referenced by this test plan:

- BMC Design Document (updated for SONiC BMC): https://github.com/sonic-net/SONiC/pull/2453
- BMC Design Document (base): https://github.com/sonic-net/SONiC/blob/master/doc/bmc/bmc_hld.md
- BMC High-Level Test Plan: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/bmc/BMC-high-level-test-plan.md

# Switch-host and SONiC BMC to use Redis protocol instead of Redfish Test Plan

---

## Background

The SONiC running on the Switch-Host needs to read identity and status
information from the BMC - model, serial number, EEPROM contents and health
state. The original BMC design assumed the BMC runs **OpenBMC** and
reached it through the **Redfish RESTful API**.

When the BMC runs **SONiC BMC** instead, the **Redis DB is the source of truth**, so the Switch-Host reads the platform data from the **Redis DB on the BMC** instead.

Because the same BMC hardware may be installed with SONiC BMC or OpenBMC, the BMC OS
is defined per HwSKU by a `bmc_os.json` file in the HwSKU directory on the Switch-Host.
The file is part of the image. There is no CONFIG_DB entry and no config command for it.

- **File**: `/usr/share/sonic/device/<platform>/<hwsku>/bmc_os.json`
- **Field**: `os`, with value `sonic` or `openbmc`
- **Default**: `sonic`, when the file is missing or holds an invalid value

`sonic_py_common.device_info.get_bmc_os()` reads the file, and the BMC platform API and
CLIs use Redis or Redfish according to its value. The read-only `show platform bmc os`
command displays it.

``` bash
admin@sonic:~$ cat /usr/share/sonic/device/x86_64-nvidia_sn6600_ld-r0/Mellanox-SN6600_LD-P64O128C2/bmc_os.json
{
    "os": "sonic"
}

admin@sonic:~$ show platform bmc os
sonic
```



---

## Test Cases

This test plan covers the feature. It verifies two areas:
- Group A: the new cases added for this feature.
- Group B: the existing BMC platform API cases that must be adapted to run correctly on SONiC BMC.

---

### Group A - New Test Cases

**File**: `tests/platform_tests/api/test_bmc_os.py` (new module)

#### Test Case #1: test_bmc_os_file

**Objective**: Verifies that `get_bmc_os()` and `show platform bmc os` follow `bmc_os.json`
in the HwSKU directory, and fall back to `sonic` when the file is missing, malformed or invalid.

**Setup / Teardown**: Runs only on a Switch-Host with a BMC. A fixture saves the original
`bmc_os.json` (content, owner and mode, or that it is absent) and restores it on every exit,
including failures. After the restore, `show platform bmc os` reports the value recorded at the start.

**Test Steps**:
1. For each row below, write the content to `bmc_os.json` (or remove the file). Without restarting
   any service, verify that `device_info.get_bmc_os()` on the Switch-Host and `show platform bmc os`
   both return the expected value.
2. Before each Missing, Malformed and Invalid row, write `{"os": "openbmc"}` and verify that both
   return `openbmc`.

| Category  | `bmc_os.json` content                     | Expected  |
|-----------|-------------------------------------------|-----------|
| Valid     | `{"os": "sonic"}`                         | `sonic`   |
| Valid     | `{"os": "openbmc"}`                       | `openbmc` |
| Missing   | File removed                              | `sonic`   |
| Malformed | Empty file                                | `sonic`   |
| Malformed | Truncated JSON: `{"os": "openbmc"`        | `sonic`   |
| Malformed | JSON that is not an object: `["openbmc"]` | `sonic`   |
| Invalid   | `{"os": "foo"}`                           | `sonic`   |
| Invalid   | `{"os": "OpenBMC"}` (case differs)        | `sonic`   |
| Invalid   | `{"os": ""}`                              | `sonic`   |
| Invalid   | `{}` (no `os` field)                      | `sonic`   |

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
2. **Read eeprom through the platform API** - Call `get_eeprom()` of the BMC platform API on
   the Switch-Host.
3. **Read eeprom through the CLI** - Run `show platform bmc eeprom` on the Switch-Host.
4. **Compare** - `get_eeprom()` must match the BMC for every field below. A field whose TLV is
   absent on the BMC must be absent from `get_eeprom()` as well. The CLI output must match
   `get_eeprom()` for the fields the CLI displays:

   | Field          | Source on the BMC                                | `get_eeprom()` vs BMC | CLI vs `get_eeprom()`    |
   |----------------|--------------------------------------------------|-----------------------|--------------------------|
   | `Model`        | `EEPROM_INFO` TLV `0x21`                         | Compared              | Compared                 |
   | `PartNumber`   | `EEPROM_INFO` TLV `0x22`                         | Compared              | Compared                 |
   | `SerialNumber` | `EEPROM_INFO` TLV `0x23`                         | Compared              | Compared                 |
   | `Manufacturer` | `EEPROM_INFO` TLV `0x2b`                         | Compared              | Compared                 |
   | `Revision`     | `EEPROM_INFO` TLV `0x27`                         | Compared              | Not displayed by the CLI |
   | `PowerState`   | Not in the EEPROM, derived from BMC reachability | Excluded              | Excluded                 |

---

### Group B - Existing Test Cases

**File**: `tests/platform_tests/api/test_bmc.py` (existing cases)

Run the existing BMC platform API cases on SONiC BMC.

#### 1. Run on SONiC BMC

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
| `test_get_version`   | `get_version()`, cross-checked against `show platform bmc summary`| **Assertion must be updated** |

`test_get_revision` currently asserts the revision is `N/A`, which is what the Redfish path
returns because it has no revision to report. Over Redis the revision is served from the
EEPROM Label Revision TLV (`0x27`), so the case has to expect the value `get_eeprom()`
reports and keep the `N/A` expectation for OpenBMC only.

`test_get_version` only checks that the version is not `None` and appears in
`show platform bmc summary`. When the BMC OS is `sonic`, `get_version()` returns `N/A` and the
summary shows `FirmwareVersion: N/A`, so the case would pass without checking anything. It has
to expect `N/A` on SONiC BMC and keep its original assertion for OpenBMC.



#### 2. Not applicable on SONiC BMC - need skip them

| Test case                             | API / CLI under test                                                            |
|---------------------------------------|----------------------------------------------------------------------------------|
| `test_reset_root_password`            | `reset_root_password()`                                                          |
| `test_reset_root_password_cli`        | `config bmc reset-root-password`                                                 |
| `test_bmc_dump`                       | `trigger_bmc_debug_log_dump()`, `get_bmc_debug_log_dump()`                       |
| `test_bmc_firmware_update`            | `update_firmware()`, `config platform firmware install chassis component BMC fw` |
| `test_bmc_session_open_close`         | `config bmc open-session`, `config bmc close-session`                            |
| `test_bmc_commands_on_non_bmc_switch` | `config bmc` command family; the case targets platforms with no BMC at all       |

`test_bmc_commands_on_non_bmc_switch` is already skipped wherever a BMC is present, regardless
of which OS that BMC runs. Its assertion must be updated for platforms without a BMC: they are
not a Switch-Host, so `config bmc open-session` and `close-session` now fail with
`Error: Operation only supported on Switch-Host` on stderr, instead of printing
`BMC is not available on this platform` on stdout. The other five need an explicit skip when
the BMC OS is `sonic`.


#### 3. OpenBMC regression
The same testcases should run on OpenBMC platform, where every case must keep passing with its original assertions.


---

## Refer

The following design documents are referenced by this test plan:

- BMC Design Document (updated for SONiC BMC): https://github.com/sonic-net/SONiC/pull/2453
- BMC Design Document (base): https://github.com/sonic-net/SONiC/blob/master/doc/bmc/bmc_hld.md
- BMC High-Level Test Plan: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/bmc/BMC-high-level-test-plan.md

The feature is implemented by the following PRs:

- Define the BMC OS per HwSKU (`bmc_os.json`): https://github.com/sonic-net/sonic-buildimage/pull/29206
- Get the BMC EEPROM from Redis: https://github.com/sonic-net/sonic-platform-common/pull/747
- Align BMC CLIs to use the per-HwSKU BMC OS: https://github.com/sonic-net/sonic-utilities/pull/4807

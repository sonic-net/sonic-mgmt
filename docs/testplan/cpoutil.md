# cpoutil platform tests

## Purpose and references

`tests/platform_tests/cpo/test_cpoutil.py` tests the common CPO CLI through
the DUT shell, following the `test_sfputil.py` platform-test pattern. The
test uses real platform APIs and EEPROM access, without mocking the DUT.

- [cpoutil HLD, revision supplied for this test](https://github.com/KroosMicas/SONiC/blob/1d3c61dbe91ebc70cc40919905cc4b2afccd8101/doc/cpo/cpoutil/CPO-cpoutil-CLI-HLD.md)
- [sfputil reference tests](https://github.com/sonic-net/sonic-mgmt/blob/master/tests/platform_tests/sfp/test_sfputil.py)
- [sonic-utilities #4864](https://github.com/sonic-net/sonic-utilities/pull/4864): common CLI
- [sonic-platform-common #763](https://github.com/sonic-net/sonic-platform-common/pull/763): platform hooks and endpoint APIs
- [sonic-buildimage #29676](https://github.com/sonic-net/sonic-buildimage/pull/29676): topology and endpoint integration

The implementation contract was checked on 2026-10-26 against utilities
`b4eb783e33fc352246b1496fb3f50bed80c1aaca`, common
`e6e5c03614f346de9e888f648492f9b7bed18ea9` and buildimage
`34c814f66de3226ccae7faac9c250781fd42b3ca`.

The code has evolved since the HLD. Tests use `show interface presence`
(including the associated ELS identifier), `tx-disable` with a hyphen,
`show interface speed application`, and `true`/`false` for the interface Tx
setter. OE input-power, ELS output-power, ELS presence and endpoint
Tx-disable commands are not part of the current CLI; their rejection is
checked. Interface low-power and reset commands are also covered.

## Prerequisites

- A physical single-ASIC DUT, any testbed topology, with the three changes
  above or equivalent support installed. Multi-ASIC namespaces and ganged
  CPO ports are explicitly skipped by this initial suite.
- The installed platform's `cpo.json` must use `devices` and
  `interfaces.associated_devices`, with OE `asic_lanes` and `max_banks`.
  No platform name, resource count, port name or physical index is hardcoded.
- Use a stable, provisioned testbed. All active CPO interfaces are queried;
  transceiver read errors are failures. Unpopulated modules can be checked
  with the presence/DOM cases selected individually.
- For disruptive cases, use a maintenance testbed on which every port
  sharing the selected OE/ELS can be shut down. The first interface or
  endpoint in sorted inventory is selected for each control case. Other
  endpoints remain covered by the read tests.
- An optional EEPROM write requires a platform-approved scratch location
  and a test pattern different from the existing bytes. The suite supplies
  no default writable address. Do not choose status, read-clear, control,
  password, firmware or identity registers as a scratch area.

## Coverage and expected results

| Test | Coverage | Expected result |
| --- | --- | --- |
| Interface queries | map, presence, DOM, low power, Tx-disable, Application, lane status; bulk and every single port; table and JSON | Exact CPO inventory and mapping, typed values, lane counts, complete DOM sections; presence and low-power agree with independent platform-object reads |
| Endpoint queries | OE/ELS status, temperature, low power; bulk and every unique endpoint; table and JSON | No duplicate endpoints; valid fields; low-power agrees with platform hooks |
| EEPROM ranges | Direct endpoint vs mapped interface; lower memory, every mapped OE bank on page 10h; joint-mode ELS identity on B0/B4 | Exactly four bytes per range; the two addressing paths agree |
| Full EEPROM dumps | All OE/ELS dumps | Every unique endpoint has a hexdump heading |
| Invalid arguments | Bad port/index/mode, zero length, page overflow, cross-page range, wrong bank, incomplete range, malformed hex, removed commands | Return code 3, diagnostic on stderr, no traceback |
| Coexistence | Ordinary SFP ports in a mixed platform | Excluded from bulk CPO output; explicit query directs the user to sfputil |
| Concurrency | Four independent mapping or OE temperature CLI processes | Complete mapping JSON and valid sensor records |
| Low power | Interface controller and OE/ELS endpoint hooks | Toggle, bounded readback, restore original mode |
| Tx-disable | One physical port, including all breakout siblings | Toggle and verify every sibling, then restore; mixed initial per-lane states are skipped because the setter cannot restore them |
| Reset | Interface controller and OE/ELS endpoint hooks | Reset, restore power mode, admin reprovision, recover links, presence, Application and Tx state |
| EEPROM write | Explicit scratch range on one OE or ELS, endpoint and mapped interface access | Save bytes, write different pattern, read back, restore through the endpoint even after failure, verify restoration |
| State guard | Every test | Active PORT table and container ID/StartedAt/RestartCount unchanged |

The mapping oracle derives ownership from topology ASIC lane slices and
active PORT lanes. It does not import the CLI or its mapping parser.
The read-only `files/cpo_probe.py` executes in host Python and uses
`Platform().get_chassis().get_cpo(index)` for independent presence and
power-mode values. Presence remains the CPO object's result; it is not
assumed equivalent to physical ELS presence on every platform.

Precise HLD laser mapping keys are one-based; displayed API laser IDs are
zero-based. Empty precise maps do not imply sequential wiring. Whole-port
fallback `platform_data.interfaces.*.laser_ids` can be checked, while
breakout children retain unresolved (`null`) laser associations. This suite
does not prove actual laser-to-ASIC wiring, perform live breakout, or claim
new speed/traffic validation.

Only an explicit CLI `not implemented` error with return code 3 is eligible
for an optional-feature skip. Missing CLI, traceback, I2C/read error, empty
JSON or invalid records fail. If the original low-power state cannot be
read, its control/reset test skips before changing hardware. ELS
low-power/reset support must not be inferred from generic ELSFP software
helpers or from successful OE controls.

Low-power and reset cases require an initially full-power controller,
because xcvrd can clear low power during reprovisioning. Reset additionally
requires all affected ports to be admin-up so that xcvrd can restore their
Applications. Application and Tx state are compared after reprovisioning.
Control cleanup uses `finally`. The isolation helper saves admin and DOM
polling settings for **every affected port**, disables polling, shuts ports
down, and restores each setting even after failure. Previously up links
must recover within 180 seconds. No pmon restart or config reload is used.
Reset can return hardware to defaults; admin reprovision is required.
Recovery/readback failures fail the test and retain diagnostic output.

The initial tests do not cover throughput, CPU/memory limits, warm/fast
reboot, firmware commands, persistent configurations, physical module
removal or partial multi-controller writes. Those need separate testbed scenarios or
remain covered by CLI unit tests. This is not a claim of full HLD coverage.

## Run

From the sonic-mgmt `tests` directory, use normal inventory/testbed options:

```sh
./run_tests.sh -n <testbed> -d <dut> -i <inventory> \
  -c platform_tests/cpo/test_cpoutil.py -u -l info
```

Enable shared-controller control cases:

```sh
./run_tests.sh -n <testbed> -d <dut> -i <inventory> \
  -c platform_tests/cpo/test_cpoutil.py -u -l info -e '--cpo-disruptive'
```

For a scratch write, add `--cpo-eeprom-write` to the pytest arguments with
a JSON object containing exactly `target` (`oe` or `els`), integer `index`,
`bank`, `page`, `offset`, and hexadecimal `data`. Numbers in JSON are
decimal. Obtain an approved address from the platform owner first.

Select presence/DOM only for an unpopulated-module scenario with
`-k 'interface_queries and (presence or dom)'`. Hardware control skips
are expected without the explicit options, and are not hardware PASS.

## Validation status

2026-10-26: 48 parametrized cases collect in isolation; 26 local helper and
failure-path simulations pass. Python compilation and flake8 pass. These
checks do not load the full sonic-mgmt/Ansible testbed environment. Hardware execution in a sonic-mgmt
testbed has not been performed for this change. Prior results on the
dependency PRs are context and are not results for this suite.

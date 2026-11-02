# Basic cpoutil platform tests

Updated 2026-11-02. This suite follows the functional integration scope of
[sfputil tests](https://github.com/sonic-net/sonic-mgmt/blob/master/tests/platform_tests/sfp/test_sfputil.py).
The CLI contract is merged sonic-utilities #4864 at
`f113917d357d224be51c55860c35bc0b71127696`.

## Scope

There are 12 test functions, producing 16 cases for one DUT:

| Function | Cases | Checks |
| --- | ---: | --- |
| `test_cpoutil_map` | 1 | Public OE/ELS fields, PORT lanes, OE bank and topology association; table headers/resources; one selected port |
| `test_cpoutil_presence` | 1 | Connected ports are present, associated ELS matches the map; table and selected-port output |
| `test_cpoutil_dom` | 1 | Presence, OE/ELS info/DOM/threshold dictionary structure, read errors; selected-port text sections |
| `test_cpoutil_endpoint_status` | 2 | OE/ELS module state, finite temperature, boolean low-power mode; common table headers and selected-resource output |
| `test_cpoutil_application` | 1 | Public Application fields, Host/Media interface keys and lane counts; table headers/resources |
| `test_cpoutil_tx_disable_query` | 1 | Boolean lane values and lane count; table headers/resources |
| `test_cpoutil_eeprom_read` | 2 | One OE/ELS endpoint and its interface alias: recognized hexdump heading and nonempty bytes |
| `test_cpoutil_basic_arguments` | 1 | Root help and four representative incomplete read-option checks |
| `test_cpoutil_low_power` | 2 | Toggle a representative OE/ELS, read back and restore power mode |
| `test_cpoutil_tx_disable` | 1 | Toggle one physical port, check its logical siblings and restore TX |
| `test_cpoutil_reset` | 2 | Reset one OE/ELS; restore power mode, presence, Application, TX and previously up links |
| `test_cpoutil_lane_status` | 1 | Explicitly skipped at the user's request; no lane-status command executes |

Default execution attempts 15 functional cases, including hardware controls;
lane-status is the only deliberately deferred case. Unsupported platform
capabilities and unmet connection/restoration prerequisites can cause extra skips.

The former exhaustive argument/help/permission matrix, synthetic I/O fault
matrix, concurrency checks, whole-inventory EEPROM dumps and successful
EEPROM scratch writes are outside this basic hardware suite. Complete
scratch-write coverage and all-command acceptance are not claimed.

## DUT and ports

Each test selects its DUT directly from `duthosts` and
`enum_rand_one_per_hwsku_frontend_hostname`. The named
`connected_cpo_ports` fixture intersects:

- the DUT's `conn_graph_facts.device_conn` entries;
- configured PORT entries and their ASIC lanes;
- Optical Engine lane ownership from the platform's `cpo.json`.

This selects connected CPO ports, excluding ordinary SFP ports. Connection
graph metadata supplies the test ports; the suite does not independently
validate actual cabling or peer traffic.

Requirements: physical single-ASIC, non-ganged DUT; valid CPO topology;
installed common cpoutil and matching platform support. Missing CPO topology
or connected CPO ports skips the module. A missing/broken CLI on an otherwise
eligible DUT fails. Queries validate connected ports in bulk output and
representative selected-port/resource paths, without repeating every CLI
syntax on every port.

## Output checks and privacy

Assertions use public cpoutil fields and types, never a required vendor,
model, serial number, port count or resource count. Resource IDs and lane
counts come from PORT/topology or the mapping query. Map checks independently
cross-check topology/PORT ownership; other basic checks use the public CLI
contract, not a second platform API probe.

Each test shows its command and corresponding assertions directly.
`run_cpoutil` has one transport step into the DUT output filter.
The output filter returns:

- redacted JSON, with DOM identity values suppressed;
- whitelisted public table headers and resource row identifiers;
- DOM presence and OE/ELS section names;
- EEPROM headings and byte counts, without raw bytes;
- fixed error categories, without raw platform diagnostics.

Text checks validate common headers/resources, not every displayed cell.
DOM checks do not assert a vendor-specific sensor list or all threshold values.
EEPROM checks establish readable, parseable output, not byte-for-byte hardware
correctness. Installed Click usage errors return 2; callback validation errors
return 1. Unsupported optional operations skip only for an explicit
`not implemented` diagnostic, not general read/I/O failures.

## Controls and restoration

Controls use the first connected port to select a representative endpoint or
physical port. Isolation includes all mapped ports sharing that endpoint,
including unconnected siblings. Tx-disable uses physical PORT index ownership.

The explicit module marker invokes `preserve_device_state` once around
the module, checking PORT configuration and container ID/StartedAt/RestartCount.
There is no autouse environment fixture or per-case platform probe.

Controls save state, disable DOM polling, shut down affected interfaces and
restore DOM/admin settings in `finally`. Previously up links must recover.
All interface restoration commands are attempted even when an earlier
restoration fails. Explicitly unsupported setters are skipped after cleanup.
Low-power/TX/reset prerequisites prevent controls whose initial state cannot
be safely restored through reprovisioning.

## Run

From the sonic-mgmt `tests` directory:

```sh
./run_tests.sh -n <testbed> -d <dut> -i <inventory> \
  -c platform_tests/cpo/test_cpoutil.py -u -l info
```

Low-power, Tx-disable and reset execute by default when their prerequisites
are met. They can interrupt all ports sharing the selected controller.
The old `--cpo-eeprom-write` option is no longer part of this suite.

## Validation

2026-11-02:

- 16 integration cases collect in isolation.
- 35 focused local checks pass, covering actual test bodies, real merged CLI
  table formatters, public JSON/header errors, Jinja-safe transport, identity
  filtering, connection selection and recovery/guard failure paths.
- The actual integration module runs against an explicitly synthetic testbed:
  default 15 passed/1 skipped, including the five hardware-control cases.
  Lane-status remains skipped. These are local synthetic results, not DUT PASS.
- The previous exhaustive local matrix remains in the separate work package;
  all 499 checks still pass against its pinned CLI/test snapshot. Those checks
  are not added back to this hardware suite and do not validate this refactor.
- Python lint and diff checks are required before submission.
- A fresh sonic-mgmt/Ansible testbed run of this refactor is pending. Prior
  473-case runs are historical results, not results for these 16 cases.

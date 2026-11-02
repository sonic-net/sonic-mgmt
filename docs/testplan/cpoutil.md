# Basic cpoutil platform tests

Updated 2026-11-02. This suite follows the functional integration scope of
[sfputil tests](https://github.com/sonic-net/sonic-mgmt/blob/master/tests/platform_tests/sfp/test_sfputil.py).
The CLI contract is merged sonic-utilities #4864 at
`f113917d357d224be51c55860c35bc0b71127696`.
The lane-status assertions follow the two-table output in
[sonic-utilities #5012](https://github.com/sonic-net/sonic-utilities/pull/5012)
at `8383e122ba046346dd3fc1fc98dfbda364d181f6`.

## Scope

There are 12 test functions, producing 16 cases for one DUT:

| Function | Cases | Checks |
| --- | ---: | --- |
| `test_cpoutil_map` | 1 | Public OE/ELS fields, PORT lanes, OE bank and topology association; table headers/resources; every connected port selector |
| `test_cpoutil_presence` | 1 | All connected ports are present, associated ELS matches the map; bulk and every selected-port output |
| `test_cpoutil_dom` | 1 | Connected-port OE/ELS info/DOM/threshold structure, presence and read errors; text sections for every connected port |
| `test_cpoutil_endpoint_status` | 2 | State, finite temperature, boolean low-power, headers and selected-resource output for every associated OE/ELS |
| `test_cpoutil_application` | 1 | Nonempty Host/Media strings, selection display types and exact logical-port lane keys; text headers, lane rows and cell presence |
| `test_cpoutil_tx_disable_query` | 1 | Boolean lane values and lane count; table headers/resources |
| `test_cpoutil_eeprom_read` | 2 | Every connected interface alias and each associated OE/ELS directly once: recognized hexdump heading and nonempty bytes |
| `test_cpoutil_basic_arguments` | 1 | Root help and four representative incomplete read-option checks |
| `test_cpoutil_low_power` | 2 | Toggle each distinct eligible OE/ELS, read back and restore before the next endpoint |
| `test_cpoutil_tx_disable` | 1 | Toggle each eligible connected physical port once, check all logical siblings and restore TX |
| `test_cpoutil_reset` | 2 | Reset each distinct eligible OE/ELS; restore power, presence, Application, TX and previously up links |
| `test_cpoutil_lane_status` | 1 | Exactly two tables: OE datapath and ELS lane headers/resources, bulk and every connected port selector |

Default execution attempts all 16 functional cases, including lane-status and
hardware controls. Unsupported platform capabilities and unmet
connection/restoration prerequisites can cause skips.

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
eligible DUT fails. Basic queries validate every connected CPO port in bulk
output. Map, presence, DOM and lane-status also traverse every connected-port
selector; endpoint queries traverse every associated OE/ELS selector.
Direct EEPROM reads are deduplicated by OE/ELS identifier, while every connected
interface alias is read separately, preserving its OE bank path. This does not
claim coverage of unconnected independent endpoints or all page/range options.
The argument-parser smoke check still uses one valid OE: parser behavior is not
repeated for each hardware endpoint.

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
- whitelisted public table headers and resource row identifiers; Application
  lane numbers and cell-presence flags without raw cell text;
- DOM presence and OE/ELS section names;
- EEPROM headings and byte counts, without raw bytes;
- fixed error categories, without raw platform diagnostics.

Text checks validate common headers/resources. Application additionally checks
exact lane rows and that both configured/active cells are populated. It does not
validate the hardware meaning of every displayed cell.
Application expected lane keys are derived from the OE bank's ordered ASIC lanes
in cpo.json and the logical port's active PORT lanes, independently of the
Application response. This catches a breakout subport displaying a sibling's
same-size lane set, the whole parent bank or global rather than bank-local lane
indices, in both JSON and text. Host/Media descriptions must be nonempty strings;
N/A is an allowed display string. Selections may be integers or the CLI's
null/N/A placeholders. The test does not require selections to match the
advertisement, configured to equal active, a specific interface type or speed.
It checks breakout ports already present in the testbed; it does not create or
change a breakout configuration.
The lane-status test expects exactly two tables: Interface/Lane/Data
Path State and Interface/ELS/Laser/ELS Lane State/Shared. It checks connected
port rows in each table and every connected-port query. It does not request JSON
or check ELS module status. It runs by default and skips only when the platform
explicitly reports that the query is not implemented.
DOM checks do not assert a vendor-specific sensor list or all threshold values.
EEPROM checks establish readable, parseable output, not byte-for-byte hardware
correctness. Installed Click usage errors return 2; callback validation errors
return 1. Unsupported optional operations skip only for an explicit
`not implemented` diagnostic, not general read/I/O failures.

## Controls and restoration

Controls traverse endpoints associated with the connected ports. Low-power and
reset deduplicate by OE/ELS identifier; Tx-disable deduplicates by physical PORT
index. Each object is restored before advancing to the next object. Isolation
includes all mapped ports sharing that endpoint or physical port, including
unconnected siblings.

The explicit module marker invokes `preserve_device_state` once around
the module, checking PORT configuration and container ID/StartedAt/RestartCount.
There is no autouse environment fixture or per-case platform probe.

Controls save state, disable DOM polling, shut down affected interfaces and
restore DOM/admin settings in `finally`. Previously up links must recover.
All interface restoration commands are attempted even when an earlier
restoration fails. Explicitly unsupported setters are skipped after cleanup.
Low-power/TX/reset prerequisites prevent controls whose initial state cannot
be safely restored through reprovisioning. Ineligible objects are logged with
their reasons and do not stop checks of later objects. Each control test logs
the tested objects and excluded objects. If none can be tested, the case skips;
otherwise it covers the eligible objects only. Real command/read failures and
failed restoration fail the case rather than being converted into exclusions.

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
- 99 focused local checks pass, covering actual test bodies, real merged CLI
  formatters and the follow-up lane tables, public JSON/header errors, Jinja-safe
  transport, identity filtering, connection selection and recovery/guard failure paths.
- The lane-status body is called directly in local checks against the
  new CLI formatter. Missing/extra tables, wrong headers, missing per-table port
  rows and an unexpected selected-port row are rejected.
- Traversal checks use five connected CPO logical ports, two OEs, two ELSs,
  three physical ports and an unconnected shared sibling. They verify complete
  traversal, deduplication, later-object progress after an exclusion, skip when
  no eligible object remains, and restoration after a later endpoint fails.
- Application checks cover unsplit and bank-1 breakout fixtures, sibling/parent/
  global lane errors, missing/duplicate text rows, empty text cells, invalid
  field/value types, allowed placeholders and output filtering. These are local
  synthetic display checks, not hardware breakout validation.
- The actual integration module runs against an explicitly synthetic testbed:
  default 16 passed, including lane-status and the five hardware-control cases.
  These are local synthetic results, not DUT PASS.
- The previous exhaustive local matrix remains in the separate work package;
  all 499 checks still pass against its pinned CLI/test snapshot. Those checks
  are not added back to this hardware suite and do not validate this refactor.
- Python lint and diff checks are required before submission.
- A fresh sonic-mgmt/Ansible testbed run of this refactor is pending. Prior
  473-case runs are historical results, not results for these 16 cases.

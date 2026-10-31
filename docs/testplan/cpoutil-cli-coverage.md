# cpoutil command and rejection coverage

Contract: merged sonic-utilities #4864,
`f113917d357d224be51c55860c35bc0b71127696`. Audited 2026-10-29.

The merged Click tree contains 23 leaf commands and 35 help paths including
the root. The following table maps every leaf to a positive test entry and
its additional negative coverage. These are declared test paths, not a report
of successful DUT execution. See [the test plan](cpoutil.md) for prerequisites,
run options, privacy and validation status.

Every row also has unknown-option rejection, `--help`, and non-root rejection
cases. Interface reads check bulk/selected port JSON and table output;
endpoint reads check bulk/selected endpoint JSON and table output.

| Command after `cpoutil` | Positive test entry | Additional negative coverage |
| --- | --- | --- |
| `show interface map` | `test_interface_queries[map]` | Invalid/missing port value, legacy positional port |
| `show interface presence` | `test_interface_queries[presence]` | Same port errors; ordinary SFP redirection |
| `show interface dom` | `test_interface_queries[dom]` | Same port errors; DOM identities projected before transport |
| `show interface tx-disable` | `test_interface_queries[tx-disable]` | Same port errors |
| `show interface speed application` | `test_interface_queries[speed application]` | Same port errors |
| `show interface lane-status` | `test_interface_queries[lane-status]` | Same port errors |
| `show oe status` | `test_endpoint_queries[status-oe]` | Invalid index |
| `show oe temperature` | `test_endpoint_queries[temperature-oe]` | Invalid/negative index |
| `show oe lpmode` | `test_endpoint_queries[lpmode-oe]` | Invalid index |
| `show els status` | `test_endpoint_queries[status-els]` | Invalid index |
| `show els temperature` | `test_endpoint_queries[temperature-els]` | Invalid/negative index |
| `show els lpmode` | `test_endpoint_queries[lpmode-els]` | Invalid index |
| `config interface tx-disable` | `test_tx_disable_control` | Missing port/state, invalid port/state; false/I/O/timeout/unsupported hook and partial completion |
| `config oe lpmode` | `test_low_power_control[oe]` | Missing index/mode, invalid index/mode; false/I/O/timeout/unsupported hook |
| `config oe reset` | `test_reset_control[oe]` | Missing/invalid index; false/I/O/timeout/unsupported hook |
| `config els lpmode` | `test_low_power_control[els]` | Missing index/mode, invalid index/mode; false/I/O/timeout/unsupported hook |
| `config els reset` | `test_reset_control[els]` | Missing/invalid index; false/I/O/timeout/unsupported hook |
| `read-eeprom interface` | `test_eeprom_reads`, `test_selected_eeprom_full_dump` | Both OE/ELS targets: partial range options, missing values, invalid numbers/ranges, target conflicts, simulated read failures |
| `read-eeprom oe` | `test_eeprom_reads[oe]`, full-dump cases | Partial options, missing values, bad numbers/banks/ranges, undeclared pages, simulated read failures |
| `read-eeprom els` | `test_eeprom_reads[els]`, full-dump cases | Partial options, missing values, bad numbers/banks/ranges, undeclared pages, simulated read failures |
| `write-eeprom interface` | `test_eeprom_write[interface]` with each approved OE/ELS scratch target | Missing required fields/values, invalid hex/numbers/ranges, target conflicts, simulated write failures |
| `write-eeprom oe` | `test_eeprom_write[endpoint]` with approved OE scratch target | Missing fields/values, invalid hex/numbers/banks/ranges, undeclared page, simulated write failures |
| `write-eeprom els` | `test_eeprom_write[endpoint]` with approved ELS scratch target | Missing fields/values, invalid hex/numbers/banks/ranges, undeclared page, simulated write failures |

`read-eeprom` without a subcommand is additionally covered by
`test_eeprom_full_dump[all]` and the root guard. Successful controls require
`--cpo-disruptive`. Successful EEPROM writes require the explicit approved
scratch option; OE and ELS scratch writes require separate runs with their
respective approved targets. Platform-specific unsupported operations skip
under the documented conditions; these skips do not establish hardware PASS.

## Range arguments and required fields

The byte-count option is `-s/--size`. `--length` is rejected. For each of
`read-eeprom oe`, `read-eeprom els`, `read-eeprom interface --oe`, and
`read-eeprom interface --els`, all six nonempty proper subsets below must
return code 1 with `must be supplied together` (24 cases):

| Given range options | Result |
| --- | --- |
| page only | Reject |
| offset only | Reject |
| size only | Reject |
| page + offset | Reject |
| page + size | Reject |
| offset + size | Reject |
| None | Valid full-dump form, checked separately |
| All three | Valid range form, checked with short decimal and long hexadecimal options |

Write tests enumerate all 15 proper subsets of the four required fields
(selector, page, offset, data) for the same four access paths: 60 rejection
cases. Read/write boundaries include negative/overflow page and offset,
nonzero-page lower-half addressing, and crossing the page boundary. Reads
also reject nonpositive sizes. Hex data covers empty, odd-length and nonhex
payloads. Endpoint bank/index options include missing values and invalid
numbers; bank bounds and shared-page bank selection are checked.

## Failure simulation and limits

`files/cpo_faults.py` replaces initialization, lookup, page/offset resolution
and endpoints only within its process, then calls the installed CLI's actual
callbacks and error handlers through the installed `cli` entry. Simulations assert return code 1, no traceback,
the expected failure category and exact read/write/control call counts.
Only booleans and counters return to the test controller.

- Four read paths: `None`, short result, I/O error, timeout,
  `NotImplementedError`, `AttributeError` (24 cases).
- Four write paths: false result, I/O error, timeout,
  `NotImplementedError`, `AttributeError` (20 cases).
- Five control paths: false result, I/O error, timeout and
  `NotImplementedError` (20 cases).
- Multi-target Tx-disable: first target succeeds and second fails; the CLI
  must identify partial completion (1 case).

The suite collects 473 integration cases. Review of a subsequent testbed run
found 150 passed, 315 failed at incorrect exit-code expectations, and 8 skipped.
The 2026-10-31 correction distinguishes Click usage errors (2) from callback
validation errors (1); it requires a fresh testbed run. Earlier local checks
used the internal `main()` wrapper and did not validate the installed entry's
exit codes. See the test plan for verification details and limits.
This matrix establishes command coverage and the enumerated error scenarios,
not complete branch coverage or every possible hardware failure. Physical
removal, unavailable/restarting services, bus contention, traffic and actual
multi-controller rollback remain outside these simulations.

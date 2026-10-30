# cpoutil platform tests

## Contract and references

`tests/platform_tests/cpo/test_cpoutil.py` tests the installed common CLI
against real CPO platform objects and EEPROM access. The contract was
updated on 2026-10-29 to the merged [sonic-utilities #4864](https://github.com/sonic-net/sonic-utilities/pull/4864),
merge commit `f113917d357d224be51c55860c35bc0b71127696`.

- [Merged CLI source](https://github.com/sonic-net/sonic-utilities/blob/f113917d357d224be51c55860c35bc0b71127696/cpoutil/main.py)
- [Merged mapping source](https://github.com/sonic-net/sonic-utilities/blob/f113917d357d224be51c55860c35bc0b71127696/cpoutil/mapping.py)
- [sfputil reference tests](https://github.com/sonic-net/sonic-mgmt/blob/master/tests/platform_tests/sfp/test_sfputil.py)
- Related platform support: [platform-common #763](https://github.com/sonic-net/sonic-platform-common/pull/763),
  [buildimage #29676](https://github.com/sonic-net/sonic-buildimage/pull/29676).
  These remain separate platform-support changes, not merged CLI prerequisites
  for every platform.

Front-panel selectors use `-p/--port`; OE/ELS selectors retain positional
indices. Interface scope provides Tx-disable only. Low-power mode and reset
are tested at OE/ELS scope. Removed interface low-power/reset commands and
legacy positional port arguments are negative cases. The root guard returns
1 for an unprivileged operation, while top-level help remains available.
Invalid commands/resources return 3.

## Prerequisites

- A physical, single-ASIC, non-ganged CPO DUT with the merged CLI and matching
  installed platform/common support. Missing CPO topology skips the suite;
  missing CLI on a configured CPO DUT fails.
- HLD `cpo.json` with `devices`, `interfaces.associated_devices`, OE
  `asic_lanes` and `max_banks`. Inventory comes from active PORT lanes and
  physical indices; no platform name or port/resource count is hardcoded.
- Public CPO presence/Tx-disable hooks, OE/ELS APIs and their memory maps.
  Missing or explicitly unimplemented optional controls are distinguished
  from I2C/read failures. The latter fail.
- A stable testbed. Every active CPO port is queried; presence/DOM cases
  can be selected separately for unpopulated modules.
- The root-guard test uses the standard unprivileged `nobody` account.
- Control cases require `--cpo-disruptive` and a maintenance testbed where
  every port sharing the selected resource can be shut down.
- Actual EEPROM writes additionally require `--cpo-eeprom-write` with an
  approved scratch location and a different test pattern. There is no default
  writable address. The selected page and memory half must be declared by
  the endpoint. Identity, firmware, password, status/read-clear and control
  registers must not be used as scratch locations.

## Coverage

| Case | Expected result |
| --- | --- |
| Interface map/presence/DOM/Tx-disable/Application/lane-status | Bulk and each selected port in JSON and table form; exact mapping/inventory, typed fields and lane counts. Presence and Tx-disable agree with independent CPO hooks. Empty threshold dictionaries are allowed. |
| OE/ELS status, temperature and low power | Unique endpoint inventory, single selectors, valid JSON fields and table resource rows; low power agrees with endpoint hooks. |
| EEPROM ranges | Compare byte count and digest through direct and interface paths, using ranges from the selected endpoint's actual memory map. Include mapped OE-local banks when page 10h is declared. No ELS page-zero alias or fixed base page is assumed. |
| Full EEPROM dumps | OE, ELS and combined dumps, plus individually selected endpoint/interface dumps with all range options omitted, have the expected headings and nonempty byte content. |
| EEPROM page guard | Both reads and writes reject an undeclared page before EEPROM access. These rejection cases do not write hardware. |
| Invalid syntax/resources | 300 generated cases cover all 23 leaf commands: unknown options, missing fields/values, bad selectors/modes/numbers, range boundaries and invalid hex. Additional removed-command and undeclared-page guards remain. See the [command matrix](cpoutil-cli-coverage.md). |
| Synthetic I/O failures | 65 process-local fault cases run installed CLI callbacks against synthetic endpoints: missing/short EEPROM reads, failed writes, I/O exceptions/timeouts, unsupported APIs, missing attributes and partial Tx-disable completion. No platform is initialized or hardware written by these simulations. |
| Help/root privileges | All 35 group/leaf help paths succeed; all 23 leaf actions and the default combined dump reject an unprivileged user with code 1. Top-level help is public. |
| Coexistence | Ordinary SFP ports are omitted from CPO bulk output and explicit selection directs the user to sfputil. |
| Concurrency | Four independent mapping or temperature CLI processes return complete records. |
| OE/ELS low power | Toggle one endpoint, verify readback and restore the original full-power state. |
| Interface Tx-disable | Use the CPO hook to toggle all lanes of the selected OE bank, including breakout siblings; restore original state. Initially disabled or mixed lane states are skipped to avoid changing them during reprovisioning. |
| OE/ELS reset | Restore power mode, reprovision affected ports and recover original presence, Application, Tx state and previously up links. |
| Approved scratch write | Endpoint/interface write paths run backup, write, readback and finally restoration on the DUT; only outcome flags are returned. Partial-write/readback failures still attempt restoration. |
| State guard | PORT configuration and container ID/StartedAt/RestartCount remain unchanged after every case. |

The mapping oracle derives ownership from topology ASIC lane slices and
active PORT lanes without importing cpoutil. Precise laser mapping keys are
one-based and public API laser IDs are zero-based. Empty precise maps do not
imply sequential wiring; unresolved breakout associations remain unresolved.

The independent probe returns only presence, Tx flags, power mode and
declared page metadata. It uses CPO presence directly and does not assume
equivalence with physical ELS presence.

## Recovery and output privacy

Only an explicit `not implemented` error with return code 3 is eligible for
an optional-feature skip. Missing CLI, malformed output, read errors and
invalid records fail. Control/reset cases skip before mutation if their
original state cannot be read. Low-power/reset cases require initial full
power; reset requires all affected ports admin-up for xcvrd reprovisioning.

The isolation helper saves admin and DOM polling settings for every affected
port, disables polling, shuts the ports down, and attempts all restoration
steps on exit. Previously up links must recover within 180 seconds. No pmon
restart or config reload is used. A failure to restore state fails the case.

`files/cpo_runner.py` captures CLI output on the DUT before returning anything
to Ansible. DOM identity values are redacted there, and DOM tables return only
presence headers. Other table cases return resource rows; values are checked
through JSON. EEPROM ranges return lengths/digests, full dumps return headings
and total size, and scratch backups remain on the DUT. Raw stderr and
incidental platform diagnostics are reduced to fixed error categories. Test
logs record command families and exit codes. The probe similarly suppresses
incidental platform import/getter diagnostics. Test examples use synthetic
identity values only.

Before a scratch write, a root-only recovery file (0600) is saved on the DUT.
It is deleted after successful restoration and retained if restoration fails.
The failure reports its path, never its contents. This preserves recovery
information without putting original EEPROM bytes in controller logs.

## Run

From the sonic-mgmt `tests` directory:

```sh
./run_tests.sh -n <testbed> -d <dut> -i <inventory> \
  -c platform_tests/cpo/test_cpoutil.py -u -l info
```

Default execution performs queries, negative cases and process-local failure
simulations, including EEPROM writes that must be rejected by validation.
Successful hardware control operations require:

```sh
./run_tests.sh -n <testbed> -d <dut> -i <inventory> \
  -c platform_tests/cpo/test_cpoutil.py -u -l info -e '--cpo-disruptive'
```

For scratch writes, add `--cpo-eeprom-write` to pytest arguments with a JSON
object containing exactly `target` (`oe` or `els`), integer `index`, `bank`,
`page`, `offset`, and hexadecimal `data`. JSON numbers are decimal. Supply
a platform-approved address; this document intentionally gives no address.

Use `-k 'interface_queries and (presence or dom)'` for presence/DOM only.
Unsupported/disabled control cases are skips, not hardware PASS.

## Validation status and limits

2026-10-29: 473 parametrized integration cases collect in isolation. 498 local
checks pass, including all 300 argument cases through the actual merged CLI
callbacks with hardware dependencies replaced, all 65 synthetic I/O failure
cases through the merged error handlers, command inventory, help/root handling,
page validators, mapping/format parsing, output privacy and failure restoration.
Parser-only checks stub hardware callbacks; failure/argument checks retain the
merged callbacks and replace topology/endpoint dependencies. Invalid-input
checks assert no EEPROM read/write or page lookup occurs. Compilation, flake8
and diff checks pass.

2026-10-30: the shared container snapshot now queries container IDs, avoiding
Docker Go-template braces that conflict with Ansible/Jinja parsing. An empty
container inventory returns an empty snapshot without invoking `docker inspect`
with no arguments. Eight local transport/state-guard regressions pass through
the Jinja parser, including container replacement, start-time/restart changes
and PORT configuration changes. These checks are not a full Ansible/DUT run.

A supplied execution summary records 473 cases as `broken`. The subsequent
failure details confirm `RunAnsibleModuleFail` caused by the shared snapshot's
Docker Go template: Jinja rejects it with `unexpected '.'` before the CLI
assertion is reached. This matches the independently reproduced defect.
The corrected revision still requires a testbed rerun; no passing DUT result
is claimed. Start with the help subset and stop after the first failure:

```sh
./run_tests.sh -n <testbed> -d <dut> -i <inventory> \
  -c platform_tests/cpo/test_cpoutil.py -u -l info \
  -e '-k test_command_help -x --tb=short --setup-show'
```

Full sonic-mgmt/Ansible execution of this revision remains unverified.
Dependency PR results are not results for this suite. Traffic, live breakout,
multi-ASIC/ganged ports, physical removal, reboot/firmware, CPU/memory limits,
partial multi-controller writes and actual laser wiring are outside this
suite; it does not claim complete HLD or hardware acceptance coverage.

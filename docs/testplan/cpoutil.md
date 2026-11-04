# Basic cpoutil hardware tests

The suite follows the basic functional scope of
[test_sfputil.py](../../tests/platform_tests/sfp/test_sfputil.py).
The CLI contract is merged sonic-utilities #4864; lane-status requires the
two-table output in sonic-utilities #5012 at
`8383e122ba046346dd3fc1fc98dfbda364d181f6`.

## Selection and checks

There are 10 test functions / 13 collected cases. Hardware traversal stays
inside each case. DUT selection is explicit; `connected_cpo_ports` intersects
connection-graph ports, current PORT lanes and cpo.json optical-engine lanes.
The scope is physical single-ASIC, non-ganged CPO devices.

Only the mapping case executes `show interface map`. Other cases derive
OE/ELS ownership and shared banks directly from cpo.json and PORT. Parent
interface names in cpo.json need not match current breakout subport names:
the current PORT lanes select the declared OE bank.

Every cpoutil query uses its default text output, including the initial
configuration snapshot, inverted-state readback, restoration readback and reset
recovery. No cpoutil query requests JSON or compares per-port selector output
with bulk output. Required selectors in config commands still identify targets.

The DUT filter parses simple-table column boundaries and DOM section headings.
It returns public identifiers, numeric/boolean values and cell-validity flags;
raw status, Application descriptions and DOM identity strings stay on the DUT.
The filter's JSON transport envelope and cpo.json/PORT configuration inputs are
separate from the cpoutil text output being tested.

| Cases | Checks |
| --- | --- |
| Map | Public fields, configured OE/ELS association, OE bank/PORT lanes and common text columns |
| Presence | Every connected CPO port must be present; absence fails |
| DOM | Detected, no Read errors, OE/ELS sections with displayed fields and monitor/threshold headings |
| OE / ELS status | Nonempty non-N/A state, finite temperature and On/Off low-power cells; actual OE/ELS headers/resources |
| Application | Exact bank-local subport lane rows and nonempty configured/active cells; AppSel/Host/Media display syntax or N/A placeholders |
| TX query | true/false lane cells, PORT lane count and public text columns |
| OE / ELS low-power | Snapshot all associated endpoints, invert all supported modes, verify, restore and verify |
| TX control | Snapshot all associated OE banks and their siblings, invert supported/restorable banks, verify, restore and verify |
| OE / ELS reset | Command success, module becomes readable, connected interfaces present and prior up links recover |
| Lane status | Exactly the OE datapath and ELS lane tables, public headers and connected-port rows |

Application checks current breakout configuration without creating breakout.
The default table displays selected Application descriptions; the JSON-only
Advertisement dictionary is outside this text test. It does not compare
configured/active AppSel equality, advertisement membership,
specific interface types or actual link speed. There are no EEPROM read/write,
EEPROM argument or help smoke cases.

## Controls and restoration

Low-power and TX cases first read all initial states before any mutation.
They disable DOM polling and shut down all affected shared interfaces,
including unconnected siblings. They then write all inverted values before
checking readback. `finally` attempts restoration of every attempted object,
even after a later write or an earlier restoration fails. Each restored value
is checked; DOM/admin configuration and previously up shared links are restored.
After interface restoration, the control state is checked again, followed by
connected-port presence and recovery of connected links which were up before
the test. An initially down port is not required to become up.

Low-power starts from either boolean value. TX deduplicates by (OE, bank),
because the setter affects that bank, including all breakout siblings; it
does not deduplicate by physical PORT index. Uniform true or false states are
supported. A bank with mixed lane states is excluded before writing because
the boolean bank-wide setter cannot restore a mixed lane mask exactly.

An explicitly unsupported setter is recorded after checking that its state
remains unchanged; later objects are still exercised. A case skips if no
supported/restorable objects remain. General I/O, command, readback, presence
and recovery errors fail. Exclusions are logged and are not hardware PASS.

Reset follows sfputil's command/presence/recovery approach, once per distinct
associated OE/ELS. It waits up to 60 seconds for a nonempty, non-N/A module
status and for presence. DOM/admin restoration runs even on reset failure.
It does not require initial full power or all shared ports admin-up, compare
Application/TX snapshots, force a generic low-power transition, require a
specific module state or require an observable link-down edge. Unlike sfputil's
admin-up link check, only previously oper-up links must recover, so an existing
down link is not attributed to reset. These checks establish CLI success and
recovery; they do not independently prove an electrical reset pulse occurred.

An explicit module marker invokes `preserve_device_state` around the suite,
checking PORT configuration and container identity/start/restart state.
The DUT output filter suppresses DOM identities and incidental diagnostics
before Ansible receives output; public assertions do not require a vendor,
model or serial number.

## Run and validation

From the sonic-mgmt `tests` directory:

```sh
./run_tests.sh -n <testbed> -d <dut> -i <inventory> \
  -c platform_tests/cpo/test_cpoutil.py -u -l info
```

Controls run by default and can interrupt all interfaces sharing the selected
OE/ELS or OE bank. There is no separate disruptive-control switch.

2026-11-04: 73 local synthetic checks passed, including all 13 retained case
bodies, default text parsing, actual table formatters, On/Off controls, the
distinct OE/ELS status headings, malformed/duplicate/missing rows and cells,
non-finite temperature, DOM error/section checks, identity suppression and
topology-based breakout selection. The actual module with a synthetic testbed
and module guard passed 13/13. Collection, flake8 and whitespace checks passed.
These are local synthetic results. A fresh Ansible/DUT run remains pending;
the PR stays draft.

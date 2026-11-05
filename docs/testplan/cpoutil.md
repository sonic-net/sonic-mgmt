# Basic cpoutil hardware tests

The suite follows the basic functional scope of
[test_sfputil.py](../../tests/platform_tests/sfp/test_sfputil.py).
The CLI contract is merged sonic-utilities #4864; lane-status requires the
two-table output in sonic-utilities #5012 at
`8383e122ba046346dd3fc1fc98dfbda364d181f6`.

## Selection and checks

There are 11 test functions / 15 collected cases. Hardware traversal stays
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
| Map | Command success, common headers/connected-port rows; OE/ELS association and OE bank versus cpo.json, lanes versus current PORT; laser selection when precisely mapped |
| Presence | Every connected CPO port must be present; absence fails |
| DOM | Detected, no Read errors, OE/ELS sections with displayed fields and monitor/threshold headings |
| OE / ELS status | Exact ModuleReady state, finite temperature and On/Off low-power cells; actual OE/ELS headers/resources |
| Application | Exact bank-local subport lane rows and nonempty configured/active cells; AppSel/Host/Media display syntax or N/A placeholders |
| TX query | true/false lane cells, PORT lane count and public text columns |
| OE / ELS EEPROM read | rc=0, matching target heading and at least one hexdump data row; no byte-content comparison |
| OE / ELS low-power | Snapshot all associated endpoints, invert all supported modes, verify, restore and verify |
| TX control | Snapshot all associated OE banks and their siblings, invert supported/restorable banks, verify, restore and verify |
| OE / ELS reset | Command success, module becomes readable, connected interfaces present and prior up links recover |
| Lane status | Exactly the OE datapath and ELS lane tables, public headers and connected-port rows |

The map case parses default text and checks each connected port. OE/ELS must
exist with their expected device types, and the OE/bank/ELS tuple must appear
in cpo.json associations. Displayed ASIC lanes must equal current PORT lanes
and belong to the configured OE bank, including after breakout. OE bank bounds
and bank lane ranges are checked; an optional displayed ELS bank is not compared.

If the ELS declares laser_to_asic_lane_mapping, select lasers whose mapped ASIC
lanes overlap this port, normalize one-based JSON laser IDs to zero-based CLI
IDs, and require the exact displayed laser set. The map must cover PORT lanes.
Without that precise mapping, accept the actual CLI placeholder
`N/A (needs laser_to_asic_lane_mapping)` or `N/A`, a numeric laser list for a
full port, or empty when no lasers are declared. No subport laser assignment
is inferred. Malformed/duplicate lane and laser lists still fail; unresolved
laser selection does not disable OE/ELS/bank/lane checks or skip the case.

Application checks current breakout configuration without creating breakout.
The default table displays selected Application descriptions; the JSON-only
Advertisement dictionary is outside this text test. It does not compare
configured/active AppSel equality, advertisement membership,
specific interface types or actual link speed.

EEPROM sanity has two cases, OE and ELS. It reads each distinct associated
endpoint once and each connected port's interface alias. The CLI selects its
default pages; this test does not choose a universal page, bank or fixed read
length. It only requires rc=0, the expected target heading and at least one
actual hexdump data row. The DUT filter returns a heading and a boolean, never
raw EEPROM bytes or ASCII. There are no writes or EEPROM argument/help matrices.

## Controls and restoration

Low-power and TX cases first read all initial states before any mutation.
They write all inverted values before checking readback. `finally` attempts
restoration of every attempted object, even after a later write or an earlier
restoration fails. Each restored value is checked, followed by connected-port
presence and recovery of connected links which were up before the test.
An initially down port is not required to become up.

The endpoint status case requires every associated connected OE/ELS to display
the exact public state `ModuleReady`. ModuleLowPwr, transitional/fault states,
empty/N/A and arbitrary nonempty text fail. The DUT filter returns ready
resource IDs rather than raw status strings. This is a readiness assertion for
the endpoint case; reset recovery retains its independent readable-state check.

Like sfputil lpmode, the low-power case does not shut down/start up interfaces
or change DOM polling. It changes only the endpoint low-power configuration;
that hardware transition can still interrupt every interface sharing it.
An unsupported setter therefore does not cause an artificial admin flap.
TX and reset retain DOM/admin isolation of all affected shared interfaces,
including unconnected siblings, and restore those settings and prior up shared
links. TX checks control state again after interface restoration.

DOM polling is configured on the unsplit/primary subport of each affected
physical PORT index. Secondary breakout children are still isolated, but are
not passed to the DOM config CLI, which accepts only subport 0/1 (or absent).
Owners are found in the full PORT table even when the connected/affected port
is a secondary child. Missing owners fail before mutation. Cleanup restores
only attempted admin/DOM changes, with admin restoration before DOM restoration;
a preparation failure does not restart untouched ports.

Low-power starts from either boolean value. TX deduplicates by (OE, bank),
because the setter affects that bank, including all breakout siblings; it
does not deduplicate by physical PORT index. Uniform true or false states are
supported. A bank with mixed lane states is excluded before writing because
the boolean bank-wide setter cannot restore a mixed lane mask exactly.

An explicitly unsupported low-power or TX setter is recorded after checking
that its state remains unchanged; later objects are still exercised.
A low-power or TX case skips if no
supported/restorable objects remain. General I/O, command, readback, presence
and recovery errors fail. Exclusions are logged and are not hardware PASS.

Reset follows sfputil's command/presence/recovery approach, once per distinct
associated OE/ELS. It waits up to 60 seconds for a nonempty, non-N/A module
status and for presence. DOM/admin restoration runs even on reset failure.
A supported reset must return rc=0. An explicit rc=1/not-implemented response
excludes that endpoint after isolation cleanup and presence/link checks; later
endpoints are still tested. If every selected reset is unsupported, the case
skips. Other command, readback, connection or cleanup failures still fail.
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

2026-11-04: 73 local synthetic checks passed, including the 13 text/control case
bodies, default text parsing, actual table formatters, On/Off controls, the
distinct OE/ELS status headings, malformed/duplicate/missing rows and cells,
non-finite temperature, DOM error/section checks, identity suppression and
topology-based breakout selection. Collection, flake8 and whitespace checks passed.
An additional nine checks reproduce secondary-subport DOM rejection and verify
owner selection, partial preparation cleanup, unchanged admin-down children,
missing-owner failure and restoration order.
These are local synthetic results. A fresh Ansible/DUT run remains pending;
the PR stays draft.

EEPROM sanity adds ten focused local checks for traversal/deduplication,
title-only output, wrong targets, invalid data rows, failed commands and output
privacy. The full module collected and passed 15/15 with a synthetic CLI that
rejects DOM requests for secondary breakout children, including the module state
guard. Hardware execution remains pending.

2026-11-05: map scope was reduced to rc=0, common headers and connected-port
rows. Eight focused checks passed, including the actual CLI formatter's
unresolved placeholder and arbitrary/empty map cells. The obsolete four map
value-comparison checks were excluded; the other 69 text/control checks passed.
The full module passed 15/15 on the synthetic breakout testbed. These are local
results; a new DUT run is still pending.

The subsequent low-power revision removes DOM/admin isolation from that case
while retaining snapshot, inversion, restoration and presence/link checks.
Reset skips explicitly unsupported endpoints after cleanup and recovery checks,
matching the low-power capability policy. Targeted local fault checks cover
these paths; hardware execution of this revision remains pending.

The subsequent map revision restores topology/PORT comparisons and handles the
actual unresolved-laser placeholder. Local checks use the CLI mapping logic
and formatter at the documented contract revision, covering full/breakout
ports with and without precise laser mapping. Hardware execution is pending.

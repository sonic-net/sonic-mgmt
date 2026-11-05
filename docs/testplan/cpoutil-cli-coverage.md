# cpoutil basic command coverage

Updated 2026-11-05. Contract: merged sonic-utilities #4864; lane-status uses
sonic-utilities #5012 at `8383e122ba046346dd3fc1fc98dfbda364d181f6`.
There are 15 cases; this is not exhaustive command/argument acceptance.

| Command after cpoutil | Basic test | Output/result checks |
| --- | --- | --- |
| show interface map | test_cpoutil_map | rc=0, common table headers and connected-port rows; no OE/ELS/bank/lane/laser content checks |
| show interface presence | test_cpoutil_presence | Every connected CPO interface present; absent means failure |
| show interface dom | test_cpoutil_dom | Detected, no Read errors, OE/ELS sections, displayed fields and monitor/threshold headings |
| show interface tx-disable | test_cpoutil_tx_disable_query | true/false text cells, PORT lane count and common columns/resources |
| show interface speed application | test_cpoutil_application | Exact subport lane rows, populated configured/active cells and public AppSel/Host/Media display syntax or N/A |
| show interface lane-status | test_cpoutil_lane_status | Exactly two public tables, headers and connected-port rows |
| show oe status / show els status | test_cpoutil_endpoint_status | Nonempty non-N/A cell; OE Module State / ELS Status columns and resource rows |
| show oe temperature / show els temperature | test_cpoutil_endpoint_status | Finite numeric value and common column |
| show oe lpmode / show els lpmode | test_cpoutil_endpoint_status | On/Off text value and common column |
| config interface tx-disable | test_cpoutil_tx_disable | All associated restorable OE banks: save all, invert all, verify, restore all, verify, presence/link recovery |
| config oe lpmode / config els lpmode | test_cpoutil_low_power | All associated supported endpoints: save all, invert all, verify, restore all, verify, presence/link recovery |
| config oe reset / config els reset | test_cpoutil_reset | Deduplicated endpoints: rc=0, readable module, present interfaces and environment/link recovery |
| read-eeprom oe / els | test_cpoutil_eeprom_read | Each distinct associated endpoint once: rc=0, correct heading and nonempty hexdump |
| read-eeprom interface --oe / --els | test_cpoutil_eeprom_read | Each connected interface alias: rc=0, correct port/endpoint heading and nonempty hexdump |
| write-eeprom and EEPROM option matrices | Excluded | No writes, byte-content assertions or range/bank combinations |

Only the map case calls CLI map. Other cases obtain resource associations
directly from cpo.json and current PORT lanes, including breakout children.
All cpoutil queries use default text, including control snapshots, inverted
and restored readbacks, and reset recovery. No cpoutil JSON query is issued.
Required config selectors remain. Configuration files and the safe transport
envelope still use JSON; neither substitutes for the rendered CLI cells.

The default Application table renders selected descriptions rather than a
standalone Advertisement dictionary. Only displayed lane/cell syntax is tested;
the JSON-only advertisement fields are excluded. Raw DOM identities and cell
descriptions never cross the DUT output filter.

Controls restore their original values and require previously up links to recover.
Low-power leaves interface admin and DOM settings unchanged, following sfputil
lpmode; TX and reset retain DOM/admin isolation and restoration.
Low-power supports either initial boolean. TX controls an entire OE bank:
uniform true or false can be inverted/restored; mixed lane states are excluded
because the setter has no per-lane mask. Unsupported low-power/TX setters are
logged; general failures fail. No supported/restorable objects means a
low-power/TX case skip. Reset also skips explicitly unsupported endpoints after
isolation cleanup and presence/link checks; all unsupported means a case skip.
Command, readback, connection and cleanup failures are not capability skips.

Reset uses the sfputil command/presence/recovery model without requiring
Application/TX snapshot equality or initial full-power/admin-up prerequisites.
Only previously oper-up links are required up afterward. CLI recovery is not
independent proof of a hardware reset pulse.

No test asserts vendor/model/serial identities, complete sensor semantics,
physical cabling or traffic. EEPROM sanity uses default CLI page selection;
only headings and a data-present flag leave the DUT. Writes, option matrices,
fault matrices and live breakout are excluded. See [test plan](cpoutil.md) for restoration and limits.
A fresh real testbed run of this revision is pending.

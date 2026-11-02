# cpoutil basic command coverage

Contract: merged sonic-utilities #4864 at
`f113917d357d224be51c55860c35bc0b71127696`.
Scope updated 2026-11-02 to follow the sfputil functional integration tests.
There are 16 cases; this is not an exhaustive command/argument acceptance suite.

| Command after cpoutil | Basic test | Output/result checks |
| --- | --- | --- |
| show interface map | test_cpoutil_map | Public map fields, topology association, OE bank/PORT lanes, table columns/resources, one selected port |
| show interface presence | test_cpoutil_presence | Connected interfaces present, associated ELS, JSON/table and selected port |
| show interface dom | test_cpoutil_dom | Presence and OE/ELS info/DOM/threshold structures; no read errors; selected text sections |
| show interface tx-disable | test_cpoutil_tx_disable_query | Boolean lane values and lane count, public table columns/resources |
| show interface speed application | test_cpoutil_application | Public advertisement fields, Host/Media interface keys, control/active lane counts, table columns/resources |
| show interface lane-status | test_cpoutil_lane_status | Explicitly skipped; no command execution |
| show oe status / show els status | test_cpoutil_endpoint_status | Nonempty state, JSON/table and selected resource |
| show oe temperature / show els temperature | test_cpoutil_endpoint_status | Finite numeric value and common temperature column |
| show oe lpmode / show els lpmode | test_cpoutil_endpoint_status | Boolean value and common low-power column |
| read-eeprom oe / read-eeprom els | test_cpoutil_eeprom_read | One selected endpoint, recognizable heading, parseable nonempty hexdump |
| read-eeprom interface --oe / --els | test_cpoutil_eeprom_read | First connected interface, target heading and parseable nonempty hexdump |
| config interface tx-disable | test_cpoutil_tx_disable | Physical-port siblings, toggle/readback/finally restoration |
| config oe lpmode / config els lpmode | test_cpoutil_low_power | Shared ports, toggle/readback/finally restoration |
| config oe reset / config els reset | test_cpoutil_reset | Shared ports, presence/Application/TX/power/link recovery |
| --help and representative missing read options | test_cpoutil_basic_arguments | Root help groups; three incomplete ranges return 1; missing option value returns 2 |
| write-eeprom interface / oe / els | Outside basic scope | No successful hardware writes or scratch-address option in this suite |

All 19 non-deferred read/control leaf commands have a functional check.
The lane-status leaf is deferred and the three write leaves are outside scope.
The root combined EEPROM dump, all help subtrees, non-root permission matrix,
all malformed argument combinations, simulated faults and traffic are also
outside this basic suite. Root help listing write-eeprom does not establish
write coverage.

JSON checks use common fields and dynamically discovered ports/resources.
Text checks validate whitelisted public headers, resource rows and DOM
sections. They do not establish correctness of every rendered table cell or
every sensor/threshold value. No vendor, model, serial number or fixed resource
count is required.

Default: 15 functional cases, including controls, plus the lane-status skip;
unsupported operations and unmet prerequisites can cause additional skips.
Skipped checks are not hardware PASS.

See [test plan](cpoutil.md) for selection, recovery, privacy, execution options
and validation limits. A fresh real testbed run of this refactor is pending.

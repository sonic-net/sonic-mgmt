# Transceiver EEPROM — Failure-Scenario Matrix (DUT-side negative-path validation)

Purpose: prove each test actually **fails when fed a fault** (no "always-green"
tests with dead assertions), per az-pz's review ask. Most tests are
attribute-vs-actual comparisons, so the cleanest fault is to perturb one
inventory value to a known-wrong one, run that one test, confirm it fails with
the expected message, then revert.

All paths below are relative to the repo root (`/var/AzDevOps/sonic-mgmt`).
The two helper scripts live in `tests/transceiver/eeprom/negative_testing/`:

| Script | Role |
|---|---|
| `perturb_inventory.py` | Safe `set` / `del` / `revert` / `status` of an inventory value (backs up file to `<file>.neg.bak`, restores byte-for-byte). Stdlib only. |
| `verify_injections_offline.py` | **Already run, all green.** Proves each perturbation below reaches the merged value the test compares, with no DUT. De-risks this session: only the DUT-vs-merged comparison is left to confirm live. |

> **Inventory is untracked lab data** (`git status` shows the whole
> `ansible/files/transceiver/inventory/` dir as `??`), so git cannot revert it —
> that's why every injection goes through the backup/restore helper. Run
> `python perturb_inventory.py status` between cases to confirm nothing is left
> perturbed.

## Procedure for each row

```bash
# 0. set your run command once (single-test form shown):
RUN='./run_tests.sh -n <testbed> -i <inv> -u -e "--skip_sanity --skip_yang" -d arista_sw2'
# (the matrix uses -k <func> to narrow to one test)

# 1. inject the fault
python tests/transceiver/eeprom/negative_testing/perturb_inventory.py set <FILE> <KEY> <VALUE>

# 2. run ONLY the target test, expect it to FAIL with the message in the table
eval "$RUN -e \"-k <TEST_FUNC>\""

# 3. revert (always)
python tests/transceiver/eeprom/negative_testing/perturb_inventory.py revert <FILE>
```

---

## Matrix — clean inventory injections (offline-verified ✓)

Files (abbreviated below):
- **CAT** = `ansible/files/transceiver/inventory/attributes/eeprom/eeprom.json`
- **PN**  = `ansible/files/transceiver/inventory/attributes/eeprom/transceivers/vendors/PINEWAVE/part_numbers/T-OH8CNT-NMT/eeprom.json`
- **DUT** = `ansible/files/transceiver/inventory/dut_info/arista_sw2.json`

| # | Test (`-k`) | File | `perturb_inventory.py` command | Expected failure (verbatim substring) |
|---|---|---|---|---|
| 1 | `test_eeprom_content_verification_via_sfputil` | DUT | `set DUT "Ethernet0:7.vendor_sn" '"BADSN000000"'` | `'Vendor SN': expected 'BADSN000000', got '...'` under `EEPROM verification failures:` |
| 2 | `test_eeprom_content_verification_via_sfputil` | DUT | `set DUT "<E0-config-key>.vendor_rev" '"BADREV"'` | `'Vendor Rev': expected 'BADREV', got '1A'` |
| 3 | `test_eeprom_content_verification_via_show_cli` | PN | `set PN cmis_revision '"9.9"'` | `'CMIS Rev': expected '9.9', got '5.2'` |
| 4 | `test_identifier_byte_verification_via_sfputil` | CAT | `set CAT transceivers.deployment_configurations.8x100G_DR8.sff8024_identifier 17` | `identifier byte mismatch: expected 0x11 (17), got 0x19 (25)` under `Identifier byte verification failures:` |
| 5 | `test_vdm_supported_consistency` | CAT | `set CAT defaults.vdm_supported false` | `vdm_supported mismatch — configured=False, STATE_DB=True` |
| 6 | `test_cdb_background_mode_support_test` | CAT | `set CAT defaults.cdb_background_mode_supported false` | `CDB background mode mismatch: expected bit 5 = 0 ... got bit 5 = 1` |
| 7 | `test_serial_number_pattern_validation_for_breakout_ports` | CAT | `set CAT defaults.breakout_stem_serial_number_pattern '".*-ZZZ$"'` | `serial number pattern mismatch (stem port): serial number '...' does not match pattern '.*-ZZZ$'` |
| 8 | `test_cdb_background_mode_stress_test` | CAT | `del CAT defaults.cdb_stress_iteration_count` | `cdb_stress_iteration_count is not defined in the inventory for this port` |

`<E0-config-key>` is the long comma-joined key beginning `Ethernet0,Ethernet16,...` — it contains no `.` so it is a single path segment for the helper.

### Scope caveats (read before running)
- **#4 `sff8024_identifier`** is also consumed by `classify()` in `test_hexdump.py` and the non-CMIS / CDB tests, so changing it shifts the module family those tests assume. Run it scoped to the identifier-byte test only (`-k test_identifier_byte_verification_via_sfputil`).
- **#6 flip to `false`** also drops the port out of the stress test's scope (`_stress_port_in_scope` requires `cdb_background_mode_supported=True`). That's fine when running only the support test.
- **#8** requires the port to reach stress scope (`cmis_active_optical=True` + `cdb_background_mode_supported=True`), which holds for these PINEWAVE ports.

---

## ⚠ Anti-pattern (offline-verified): do NOT inject via `vendor_pn` / `vendor_name`

Changing `vendor_pn` (or `vendor_name`) changes the *normalized* PN/vendor, so
the per-PN attribute block (`T-OH8CNT-NMT`) stops resolving. The **mandatory**
field `dual_bank_supported` lives only in that per-PN shard, so it goes missing
and `AttributeManager` raises at fixture-build time:

```
AttributeMergeError: Port Ethernet0: category 'eeprom' missing mandatory fields ['dual_bank_supported'].
```

That fails **every** eeprom test as a collection/setup error, not one targeted
assertion. Use `vendor_sn` / `vendor_rev` (rows 1–2) or `cmis_revision` (row 3)
to exercise the field-mismatch assertion cleanly.

---

## DUT-touching / structural cases (not single-value inventory flips)

| Test | Fault | Expect | How |
|---|---|---|---|
| `test_absence_message_verification` | Treat a populated port as absent: remove `Ethernet0` from **both** its config-group key and its `Ethernet0:7` SN-group key in DUT | populated port reports `Present` / EEPROM content where absence message expected → fail | Multi-key edit: `perturb_inventory.py` backs up DUT, hand-edit out the port, run, `revert`. (Not a single dotted key.) |
| `test_transceiver_presence_sfputil` / `_show_cli` | Mark an empty cage as present (add a new port-spec to DUT with `vendor_pn=T-OH8CNT-NMT` + valid `transceiver_configuration`), **or** physically pull a module | expected `Present`, hardware `Not present` → fail | Structural DUT add, or manual hardware pull |
| `test_cdb_background_mode_stress_test` (I²C path) | Inject synthetic kernel I²C errors over threshold | dmesg scan detects > `STRESS_TEST_I2C_ERROR_THRESHOLD` (3) → fail | On DUT: `echo "i2c i2c-1: TEST error -110" | sudo tee /dev/kmsg` (repeat > 3×); needs DUT sudo. Optionally lower the threshold to make it deterministic. |

---

## Still on you (the human) for this session
1. **Green baseline** — full suite PASS, report kept (attributable failures).
2. **The run command** — fill in `RUN` above (testbed `-n`, inventory `-i`, `-d arista_sw2`).
3. **Confirm** I may edit inventory via the backup/restore helper (untracked lab data).
4. **Decide** the two DUT-touching cases: presence (hardware pull vs faked-present) and the kmsg I²C injection (OK to `sudo tee /dev/kmsg`, or skip).

Everything in the first table is proven to reach the merged value the test
reads; what remains is confirming the live DUT comparison flips to a failure.

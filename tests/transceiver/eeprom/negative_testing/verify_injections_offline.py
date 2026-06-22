#!/usr/bin/env python3
"""Offline proof that each inventory perturbation reaches the merged value a
test compares -- WITHOUT a DUT.

The Failure-scenario matrix works by flipping one inventory value to a known-
wrong one and confirming the test fails.  A test fails on the DUT only if the
perturbation actually changes the *merged* attribute the test reads.  That
merge (dut_info -> category defaults -> deployment -> per-PN, via the priority
resolver in AttributeManager) is pure Python and needs no hardware, so we can
prove the inventory half here: for each scenario we perturb the real file with
perturb_inventory.py, rebuild port_attributes_dict exactly as the conftest
fixture does, assert the resolved value changed as intended for a sample stem
port, then revert and confirm the file is byte-for-byte restored.

What this does and does not prove
  PROVES   : the perturbation lands on the merged attribute the test compares,
             the helper's set/del/revert round-trips cleanly, and the matrix's
             file+key mapping is correct.
  LEAVES   : the DUT-side comparison (merged value vs hardware) for the live run
             -- that is the half that needs the switch.

Run from anywhere:  python verify_injections_offline.py
Exit code 0 = all scenarios resolved as expected AND inventory left clean.
"""
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, *([os.pardir] * 4)))
sys.path.insert(0, _REPO_ROOT)

from tests.transceiver.attribute_parser.dut_info_loader import DutInfoLoader  # noqa: E402
from tests.transceiver.attribute_parser.attribute_manager import AttributeManager  # noqa: E402
from tests.transceiver.attribute_parser.attribute_keys import (  # noqa: E402
    BASE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)

DUT_NAME = "arista_sw2"
# Placeholder platform/hwsku: arista is not the sn5640 that the per-PN
# platform_hwsku_overrides target, so those overrides correctly do not apply.
PLATFORM = "x86_64-arista_placeholder-r0"
HWSKU = "arista-placeholder-hwsku"
SAMPLE_PORT = "Ethernet0"   # a stem port carrying the PINEWAVE T-OH8CNT-NMT

_HELPER = os.path.join(_HERE, "perturb_inventory.py")
_INV = os.path.join(_REPO_ROOT, "ansible", "files", "transceiver", "inventory")
_CAT_EEPROM = os.path.join(_INV, "attributes", "eeprom", "eeprom.json")
_PN_EEPROM = os.path.join(
    _INV, "attributes", "eeprom", "transceivers", "vendors",
    "PINEWAVE", "part_numbers", "T-OH8CNT-NMT", "eeprom.json",
)
_DUT_INFO = os.path.join(_INV, "dut_info", "arista_sw2.json")

# Big comma-joined port spec key in dut_info that carries Ethernet0's vendor_pn.
_E0_CONFIG_KEY = (
    "Ethernet0,Ethernet16,Ethernet64,Ethernet80,Ethernet128,Ethernet144,"
    "Ethernet352,Ethernet368,Ethernet416,Ethernet432,Ethernet480,Ethernet496"
)


def build_dict():
    """Replicate the port_attributes_dict fixture for arista_sw2."""
    loader = DutInfoLoader(_REPO_ROOT)
    base = loader.build_base_port_attributes(DUT_NAME)
    mgr = AttributeManager(_REPO_ROOT, base)
    return mgr.build_port_attributes(DUT_NAME, PLATFORM, HWSKU)


def helper(*argv):
    res = subprocess.run(
        [sys.executable, _HELPER, *argv],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"perturb_inventory.py {argv} failed:\n{res.stdout}\n{res.stderr}")
    return res.stdout


# Sentinel: this perturbation is expected to break the merge entirely and raise
# AttributeMergeError at fixture-build time (NOT a clean per-field mismatch).
class RAISES:
    def __init__(self, substr):
        self.substr = substr


# Each scenario: (matrix row, file, op, dotted-key, value-or-None,
#                 category_key, attr, expected-outcome)
# expected-outcome is a resolved value, "<absent>" (for 'del'), or RAISES(substr).
SCENARIOS = [
    # --- Clean per-field mismatches (resolve fine; one value flips) -----------
    ("eeprom_content: wrong vendor_rev (base field)", _DUT_INFO, "set",
     f"{_E0_CONFIG_KEY}.vendor_rev", '"BADREV"',
     BASE_ATTRIBUTES_KEY, "vendor_rev", "BADREV"),
    ("eeprom_content: wrong vendor_sn (base field)", _DUT_INFO, "set",
     "Ethernet0:7.vendor_sn", '"BADSN000000"',
     BASE_ATTRIBUTES_KEY, "vendor_sn", "BADSN000000"),
    ("eeprom_content: wrong cmis_revision (per-PN)", _PN_EEPROM, "set",
     "cmis_revision", '"9.9"',
     EEPROM_ATTRIBUTES_KEY, "cmis_revision", "9.9"),
    ("hexdump: wrong sff8024_identifier (deployment)", _CAT_EEPROM, "set",
     "transceivers.deployment_configurations.8x100G_DR8.sff8024_identifier", "17",
     EEPROM_ATTRIBUTES_KEY, "sff8024_identifier", 17),
    ("vdm_consistency: flip vdm_supported (defaults)", _CAT_EEPROM, "set",
     "defaults.vdm_supported", "false",
     EEPROM_ATTRIBUTES_KEY, "vdm_supported", False),
    ("cdb support: flip cdb_background_mode_supported (defaults)", _CAT_EEPROM, "set",
     "defaults.cdb_background_mode_supported", "false",
     EEPROM_ATTRIBUTES_KEY, "cdb_background_mode_supported", False),
    ("breakout_serial: non-matching stem regex (defaults)", _CAT_EEPROM, "set",
     "defaults.breakout_stem_serial_number_pattern", '".*-ZZZ$"',
     EEPROM_ATTRIBUTES_KEY, "breakout_stem_serial_number_pattern", ".*-ZZZ$"),
    ("cdb stress: remove cdb_stress_iteration_count (defaults)", _CAT_EEPROM, "del",
     "defaults.cdb_stress_iteration_count", None,
     EEPROM_ATTRIBUTES_KEY, "cdb_stress_iteration_count", "<absent>"),
    # --- Cascade caveat: vendor_pn is NOT a clean injection vector ------------
    # Changing vendor_pn changes normalized_vendor_pn, so the per-PN block stops
    # resolving and mandatory 'dual_bank_supported' (defined only there) goes
    # missing -> the fixture raises at build time, failing ALL eeprom tests as a
    # setup error rather than one targeted assertion. Same is true for
    # vendor_name. Documented here so the matrix steers wrong-PN testing toward
    # vendor_rev / vendor_sn / cmis_revision instead.
    ("eeprom_content: wrong vendor_pn CASCADES to fixture error", _DUT_INFO, "set",
     f"{_E0_CONFIG_KEY}.vendor_pn", '"WRONG-PN-XYZ"',
     BASE_ATTRIBUTES_KEY, "vendor_pn", RAISES("dual_bank_supported")),
]


def main():
    baseline = build_dict()
    if SAMPLE_PORT not in baseline:
        sys.exit(f"FATAL: {SAMPLE_PORT} not in baseline port_attributes_dict")

    print(f"Baseline built: {len(baseline)} ports for DUT '{DUT_NAME}'.")
    print(f"Verifying {len(SCENARIOS)} inventory perturbations against '{SAMPLE_PORT}'.\n")

    passed, failed = 0, 0
    for label, fpath, op, key, value, cat, attr, expected in SCENARIOS:
        before = baseline[SAMPLE_PORT].get(cat, {}).get(attr, "<absent>")
        raised = None
        after = None
        try:
            if op == "set":
                helper("set", fpath, key, value)
            else:
                helper("del", fpath, key)
            try:
                after = build_dict()[SAMPLE_PORT].get(cat, {}).get(attr, "<absent>")
            except Exception as e:  # AttributeMergeError / DutInfoError
                raised = str(e)
        finally:
            helper("revert", fpath)

        restored = build_dict()[SAMPLE_PORT].get(cat, {}).get(attr, "<absent>")
        reverted_ok = (restored == before)

        if isinstance(expected, RAISES):
            ok = reverted_ok and raised is not None and expected.substr in raised
            outcome = f"RAISED ({raised.splitlines()[0]!r})" if raised else f"no-raise, value={after!r}"
            exp_str = f"raise containing {expected.substr!r}"
        else:
            ok = reverted_ok and raised is None and after == expected
            outcome = f"perturbed={after!r}" if raised is None else f"UNEXPECTED raise: {raised!r}"
            exp_str = repr(expected)

        status = "PASS" if ok else "FAIL"
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
        print(f"[{status}] {label}")
        print(f"        {cat}.{attr}: baseline={before!r} -> {outcome} "
              f"(expected {exp_str}) -> reverted={restored!r}")

    # Final cleanliness gate.
    print()
    stat = subprocess.run(
        [sys.executable, _HELPER, "status"], capture_output=True, text=True
    )
    print(stat.stdout.strip())

    print(f"\nResult: {passed} passed, {failed} failed.")
    sys.exit(0 if failed == 0 and stat.returncode == 0 else 1)


if __name__ == "__main__":
    main()

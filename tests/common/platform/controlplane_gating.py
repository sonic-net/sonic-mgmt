import os
import re
import json
import logging
import pytest


def controlplane_gating(reboot_timing_dict):
    THRESHOLDS_FILE = os.path.join(os.path.dirname(__file__), 'hwsku_session_thresholds.json')
    LACP_WIGGLE_ROOM = 10.0  # seconds
    BGP_WIGGLE_ROOM = 10.0   # seconds

    def _get_float(d, key):
        val = d.get(key)
        try:
            return float(val) if val is not None and str(val).strip() != "" else None
        except (ValueError, TypeError):
            return None

    def _extract_version(val):
        m = re.search(r"(\d{6})", str(val))
        return m.group(1) if m else None

    hwsku = reboot_timing_dict.get("HwSku")

    try:
        with open(THRESHOLDS_FILE, 'r') as f:
            thresholds = json.load(f)
    except Exception:
        thresholds = {}

    if hwsku not in thresholds:
        logging.warning(
            "HwSku=%s not found in thresholds file. Skipping controlplane gating.",
            hwsku
        )
        return []

    lacp_val = _get_float(reboot_timing_dict, "lacp_session_max_wait")
    bgp_val = _get_float(reboot_timing_dict, "bgp")
    base_version = _extract_version(reboot_timing_dict.get("BaseImage"))
    target_version = _extract_version(reboot_timing_dict.get("TargetImage"))

    try:
        lacp_avg = float(thresholds[hwsku][base_version][target_version]["LACP"]["AVG"])
    except Exception:
        lacp_avg = None
    try:
        bgp_avg = float(thresholds[hwsku][base_version][target_version]["BGP"]["AVG"])
    except Exception:
        bgp_avg = None

    if lacp_avg is None or bgp_avg is None:
        logging.warning(
            "No thresholds found for HwSku=%s, BaseImage=%s, TargetImage=%s. "
            "Skipping controlplane gating.", hwsku, base_version, target_version
        )
        return []

    checks = [
        ("LACP", lacp_val, lacp_avg, LACP_WIGGLE_ROOM),
        ("BGP", bgp_val, bgp_avg, BGP_WIGGLE_ROOM),
    ]
    gating_failures = []
    for label, val, avg, wiggle in checks:
        if val is not None and avg is not None and val > (avg + wiggle):
            gating_failures.append(
                f"{label} session recovery {val:.2f}s exceeded allowed threshold "
                f"(AVG + wiggle room): {avg:.2f}s + {wiggle:.2f}s "
                f"for {hwsku} {base_version}->{target_version}"
            )
            logging.info("Gating failure: %s", gating_failures[-1])
            pytest.fail(f"{label} threshold exceeded: {val:.2f}s > {avg:.2f}s + {wiggle:.2f}s")
    return gating_failures

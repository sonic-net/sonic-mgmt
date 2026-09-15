"""Manage the DMA-only golden input for the combined minigraph/TSA test."""

import json
import posixpath
import sys
from contextlib import contextmanager
from pathlib import Path


def _set_maintenance_state(config):
    if not isinstance(config, dict):
        raise ValueError("Golden configuration must be a dictionary")

    bgp_device_global = config.get("BGP_DEVICE_GLOBAL")
    if not isinstance(bgp_device_global, dict):
        raise ValueError("Golden configuration must contain BGP_DEVICE_GLOBAL")

    state = bgp_device_global.get("STATE")
    if not isinstance(state, dict) or "tsa_enabled" not in state:
        raise ValueError("Golden BGP_DEVICE_GLOBAL.STATE must contain tsa_enabled")

    state["tsa_enabled"] = "true"


def _update_maintenance_golden(path):
    with open(path) as source:
        config = json.load(source)
    _set_maintenance_state(config)
    with open(path, "w") as destination:
        json.dump(config, destination, indent=4)


@contextmanager
def temporary_dma_maintenance_golden(duthost, topology, source_path):
    """Yield reload arguments for an owned remote copy; never retrieve golden data."""
    if topology not in ("uma", "lma"):
        yield {}
        return

    program = Path(__file__).read_text(encoding="utf-8")
    temporary_path = duthost.tempfile(
        state="file",
        path=posixpath.dirname(source_path),
        prefix="traffic_shift_golden_",
        suffix=".json",
        verbose=False
    )["path"]
    try:
        duthost.copy(src=source_path, dest=temporary_path, remote_src=True, mode="0600", verbose=False)
        duthost.command(argv=["python3", "-c", program, temporary_path], verbose=False)
        yield {"golden_config_path": temporary_path}
    finally:
        duthost.file(path=temporary_path, state="absent", verbose=False)


if __name__ == "__main__":
    _update_maintenance_golden(sys.argv[1])

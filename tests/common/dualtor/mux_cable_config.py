"""
Utilities and fixtures for applying prober_type / neighbor_mode to the
MUX_CABLE stanza in the running golden config on dualtor testbeds.

Note: dualtor topologies are single-ASIC only, so multi-ASIC handling is
not needed here.
"""

import copy
import json
import logging
import pytest

from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

GOLDEN_CONFIG_PATH = "/etc/sonic/running_golden_config.json"
GOLDEN_CONFIG_BACKUP_PATH = "/etc/sonic/running_golden_config.json.mux_combo_bak"

VALID_PROBER_TYPES = ("hardware", "software")
VALID_NEIGHBOR_MODES = ("host-route", "prefix-route")

MUX_COMBO_ALL = [
    {"prober_type": pt, "neighbor_mode": nm}
    for pt in VALID_PROBER_TYPES
    for nm in VALID_NEIGHBOR_MODES
]


def _read_golden_config(duthost, path=GOLDEN_CONFIG_PATH):
    """Read and parse a JSON golden config file from the DUT."""
    result = duthost.shell("cat {}".format(path), module_ignore_errors=True)
    if result["rc"] != 0:
        logger.warning("Could not read %s on %s: %s", path, duthost.hostname, result.get("stderr", ""))
        return None
    try:
        return json.loads(result["stdout"])
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Failed to parse %s on %s: %s", path, duthost.hostname, exc)
        return None


def _write_golden_config(duthost, config_data, path=GOLDEN_CONFIG_PATH):
    """Write a JSON golden config file to the DUT."""
    duthost.copy(content=json.dumps(config_data, indent=4), dest=path)


def inject_mux_cable_fields(config_data, prober_type=None, neighbor_mode=None):
    """
    Inject ``prober_type`` and/or ``neighbor_mode`` into every entry under
    the ``MUX_CABLE`` table of *config_data* (mutates in-place).

    Either parameter can be None — only non-None values are written.
    Returns True if any modification was made.
    """
    mux_cable = config_data.get("MUX_CABLE")
    if not mux_cable:
        return False

    modified = False
    for intf_name, intf_cfg in mux_cable.items():
        if prober_type is not None:
            intf_cfg["prober_type"] = prober_type
            modified = True
        if neighbor_mode is not None:
            intf_cfg["neighbor_mode"] = neighbor_mode
            modified = True
    return modified


def apply_mux_combo_to_dut(duthost, prober_type=None, neighbor_mode=None):
    """
    Apply prober_type and/or neighbor_mode to the running golden config on a
    single DUT (single-ASIC only).

    Steps:
      1. Backup current golden config.
      2. Modify MUX_CABLE entries with whichever fields were provided.
      3. Write modified config back.
      4. ``config reload`` from running_golden_config.
      5. ``config save -y``.
    """
    logger.info(
        "Applying MUX_CABLE combo prober_type=%s neighbor_mode=%s on %s",
        prober_type, neighbor_mode, duthost.hostname,
    )

    main_cfg = _read_golden_config(duthost)
    if main_cfg is None:
        logger.info(
            "running_golden_config.json not found on %s — generating from live CONFIG_DB",
            duthost.hostname,
        )
        duthost.shell("sonic-cfggen -d --print-data > {}".format(GOLDEN_CONFIG_PATH))
        main_cfg = _read_golden_config(duthost)
        if main_cfg is None:
            logger.error("Failed to generate running_golden_config.json on %s, skipping MUX combo", duthost.hostname)
            return

    # backup
    _write_golden_config(duthost, main_cfg, GOLDEN_CONFIG_BACKUP_PATH)

    # modify
    main_cfg_mod = copy.deepcopy(main_cfg)
    inject_mux_cable_fields(main_cfg_mod, prober_type, neighbor_mode)
    _write_golden_config(duthost, main_cfg_mod, GOLDEN_CONFIG_PATH)

    # reload + save
    config_reload(duthost, config_source="running_golden_config", safe_reload=True)
    duthost.shell("config save -y")
    logger.info("MUX_CABLE combo applied and saved on %s", duthost.hostname)


def revert_mux_combo_on_dut(duthost):
    """
    Restore the original running golden config from backup and reload.
    """
    logger.info("Reverting MUX_CABLE combo on %s", duthost.hostname)

    # check backup exists
    result = duthost.shell("test -f {}".format(GOLDEN_CONFIG_BACKUP_PATH), module_ignore_errors=True)
    if result["rc"] != 0:
        logger.warning("No MUX combo backup found on %s, skipping revert", duthost.hostname)
        return

    # restore original config
    duthost.shell("cp {} {}".format(GOLDEN_CONFIG_BACKUP_PATH, GOLDEN_CONFIG_PATH))
    duthost.shell("rm -f {}".format(GOLDEN_CONFIG_BACKUP_PATH))

    # reload + save to restore original state
    config_reload(duthost, config_source="running_golden_config", safe_reload=True)
    duthost.shell("config save -y")
    logger.info("MUX_CABLE combo reverted on %s", duthost.hostname)


@pytest.fixture(scope="session", autouse=True)
def apply_mux_cable_combo(request, duthosts, tbinfo):
    """
    Session-scoped autouse fixture for dualtor_io suites.

    When at least one of ``--prober_type`` or ``--neighbor_mode`` is provided,
    this fixture will:

    * **Setup**: Modify the running golden config on every DUT with the
      requested field(s), then config reload + config save.
    * **Teardown**: Restore the original golden config and reload + save.

    If neither option is provided, this fixture is a no-op.
    """
    prober_type = request.config.getoption("--prober_type", default=None)
    neighbor_mode = request.config.getoption("--neighbor_mode", default=None)

    # Only activate for dualtor topologies
    topo_name = tbinfo.get("topo", {}).get("name", "")
    if "dualtor" not in topo_name:
        logger.info("Topology '%s' is not dualtor — MUX combo fixture is a no-op", topo_name)
        yield
        return

    # No-op if neither parameter is given
    if prober_type is None and neighbor_mode is None:
        logger.info("MUX combo fixture inactive — no --prober_type or --neighbor_mode given")
        yield
        return

    logger.info(
        "===== MUX CABLE COMBO: prober_type=%s, neighbor_mode=%s =====",
        prober_type, neighbor_mode,
    )

    # --- Setup: apply combo to all DUTs ---
    for duthost in duthosts:
        apply_mux_combo_to_dut(duthost, prober_type, neighbor_mode)

    yield

    # --- Teardown: revert on all DUTs ---
    for duthost in duthosts:
        revert_mux_combo_on_dut(duthost)

"""Shared prerequisite check primitives for transceiver tests.

Each function returns a result dict (with ``'passed'`` and ``'details'`` keys);
the caller decides whether to ``pytest.skip``, ``pytest.fail``, or assert.
"""
import logging

from tests.common.platform.interface_utils import get_dut_interfaces_status
from tests.transceiver.attribute_parser.attribute_keys import (
    CDB_FW_UPGRADE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)
from tests.transceiver.utils.cli_parser_helper import parse_eeprom

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Transceiver presence check
# ──────────────────────────────────────────────────────────────────────

CMD_SHOW_PRESENCE = "show interface transceiver presence"
CMD_SFPUTIL_PRESENCE = "sfputil show presence"


def _check_presence_common(presence_map, expected_ports, label):
    """Shared result-building logic for presence checks.

    Args:
        presence_map: dict {port_name: presence_status_string}
        expected_ports: set of port names to verify
        label: human-readable label for log/details (e.g. "sfputil", "show CLI")

    Returns:
        dict with 'passed', 'present', 'missing', 'details'
    """
    present = []
    missing = []
    for port in sorted(expected_ports):
        status = presence_map.get(port, "")
        if status.strip().lower() == "present":
            present.append(port)
        else:
            missing.append(port)
            logger.warning("Port %s: expected Present (%s), got '%s'", port, label, status)

    passed = len(missing) == 0
    total = len(expected_ports)
    if passed:
        details = f"{len(present)}/{total} transceivers present ({label})"
    else:
        details = (
            f"{len(missing)}/{total} transceivers NOT present ({label}): "
            + ", ".join(missing)
        )
    logger.info("Presence check (%s): %s", label, details)
    return {"passed": passed, "present": present, "missing": missing, "details": details}


def check_presence_show_cli(duthost, port_attributes_dict):
    """Verify every port in *port_attributes_dict* reports transceiver Present.

    Uses ``show interface transceiver presence`` CLI.

    Returns:
        dict: {'passed': bool, 'present': [str], 'missing': [str], 'details': str}
    """
    expected_ports = set(port_attributes_dict.keys())
    if not expected_ports:
        return {
            "passed": True,
            "present": [],
            "missing": [],
            "details": "no ports to verify (port_attributes_dict is empty)",
        }

    result = duthost.show_and_parse(CMD_SHOW_PRESENCE)
    presence_map = {}
    for entry in result:
        port = entry.get("port")
        if not port:
            continue
        presence_map[port] = entry.get("presence", "").strip()

    return _check_presence_common(presence_map, expected_ports, "show CLI")


def check_presence_sfputil(duthost, port_attributes_dict):
    """Verify every port in *port_attributes_dict* reports Present via sfputil.

    Uses ``sfputil show presence`` CLI.  The output format is a fixed-width
    table::

        Port        Presence
        ----------  ----------
        Ethernet0   Present
        Ethernet4   Present

    Returns:
        dict: {'passed': bool, 'present': [str], 'missing': [str], 'details': str}
    """
    expected_ports = set(port_attributes_dict.keys())
    if not expected_ports:
        return {
            "passed": True,
            "present": [],
            "missing": [],
            "details": "no ports to verify (port_attributes_dict is empty)",
        }

    output = duthost.command(CMD_SFPUTIL_PRESENCE, module_ignore_errors=True)
    if output.get("rc", 1) != 0:
        return {
            "passed": False,
            "present": [],
            "missing": sorted(expected_ports),
            "details": f"sfputil command failed: {output.get('stderr', '')}",
        }

    presence_map = _parse_sfputil_presence(output.get("stdout_lines", []))

    return _check_presence_common(presence_map, expected_ports, "sfputil")


def _parse_sfputil_presence(stdout_lines):
    """Parse the fixed-width table output of ``sfputil show presence``.

    Returns:
        dict: {port_name: presence_status}
    """
    presence = {}
    for line in stdout_lines:
        stripped = line.strip()
        # Skip header/separator lines
        if not stripped or stripped.startswith("Port") or stripped.startswith("---"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            # presence value can be multi-word (e.g. "Not present")
            presence[parts[0]] = " ".join(parts[1:])
    return presence


# ──────────────────────────────────────────────────────────────────────
# Gold firmware check
# ──────────────────────────────────────────────────────────────────────

CMD_SHOW_TRANSCEIVER_INFO = "show interfaces transceiver info"
CLI_KEY_ACTIVE_FIRMWARE = "Active Firmware"


def check_gold_firmware(duthost, port_attributes_dict):
    """Verify every CMIS active-optical transceiver runs its gold firmware.

    A port is in scope iff ``EEPROM_ATTRIBUTES.cmis_active_optical`` is True.
    For every in-scope port:

      * ``CDB_FW_UPGRADE_ATTRIBUTES.gold_firmware_version`` MUST be defined -
        a missing value is a failure (inventory gap).
      * the active firmware reported by the CLI MUST equal that value -
        otherwise the port is a failure (FW mismatch).

    Each failure entry is a self-describing string carrying the port and the
    reason. Ports that are not CMIS active-optical are out of scope and
    recorded under ``'skipped'`` (no expectation to compare against).

    Returns:
        dict: ``{'passed': bool, 'matched': [str], 'failures': [str],
                 'skipped': [str], 'details': str}``
    """
    expected_ports = set(port_attributes_dict.keys())
    if not expected_ports:
        return {
            "passed": True,
            "matched": [], "failures": [], "skipped": [],
            "details": "no ports to verify (port_attributes_dict is empty)",
        }

    # Identify in-scope (CMIS active-optical) ports up front so we can avoid
    # the CLI round-trip + parse when nothing is in scope.
    in_scope = [
        port for port in sorted(expected_ports)
        if port_attributes_dict[port].get(EEPROM_ATTRIBUTES_KEY, {}).get("cmis_active_optical")
    ]
    in_scope_set = set(in_scope)
    skipped = [port for port in sorted(expected_ports) if port not in in_scope_set]

    if not in_scope:
        details = f"no CMIS active-optical ports in scope; {len(skipped)} out-of-scope port(s) skipped"
        logger.info("Gold firmware check: %s", details)
        return {
            "passed": True,
            "matched": [], "failures": [], "skipped": skipped,
            "details": details,
        }

    output = duthost.command(CMD_SHOW_TRANSCEIVER_INFO, module_ignore_errors=True)
    if output.get("rc", 1) != 0:
        return {
            "passed": False,
            "matched": [],
            "failures": [f"'{CMD_SHOW_TRANSCEIVER_INFO}' failed: {output.get('stderr', '')}"],
            "skipped": skipped,
            "details": f"'{CMD_SHOW_TRANSCEIVER_INFO}' failed: {output.get('stderr', '')}",
        }
    parsed = parse_eeprom(output.get("stdout_lines", []))

    matched = []
    failures = []
    for port in in_scope:
        cdb_fw_attrs = port_attributes_dict[port].get(CDB_FW_UPGRADE_ATTRIBUTES_KEY, {})
        expected_fw = cdb_fw_attrs.get("gold_firmware_version")
        if not expected_fw:
            failures.append(f"{port}: gold_firmware_version not configured")
            logger.warning("Port %s: cmis_active_optical=True but gold_firmware_version missing", port)
            continue
        actual_fw = parsed.get(port, {}).get(CLI_KEY_ACTIVE_FIRMWARE, "").strip()
        if actual_fw == expected_fw:
            matched.append(port)
        else:
            failures.append(f"{port}: actual={actual_fw or 'N/A'}, expected={expected_fw}")
            logger.warning("Port %s: active FW '%s' != gold FW '%s'", port, actual_fw, expected_fw)

    passed = not failures
    if passed:
        details = (
            f"{len(matched)} CMIS active-optical port(s) running gold firmware, "
            f"{len(skipped)} out-of-scope port(s) skipped"
        )
    else:
        details = (
            f"{len(failures)} CMIS active-optical port(s) failed gold-firmware check: "
            + "; ".join(failures)
        )
    logger.info("Gold firmware check: %s", details)
    return {
        "passed": passed,
        "matched": matched,
        "failures": failures,
        "skipped": skipped,
        "details": details,
    }


# ──────────────────────────────────────────────────────────────────────
# Link-up check
# ──────────────────────────────────────────────────────────────────────


def check_links_up(duthost, port_attributes_dict):
    """Verify every port in *port_attributes_dict* is admin-up and oper-up.

    Uses :func:`tests.common.platform.interface_utils.get_dut_interfaces_status`
    to retrieve admin/oper state for every interface on the DUT. Ports missing
    from that mapping are treated as failures.

    Returns:
        dict: ``{'passed': bool, 'up': [str], 'down': [str], 'details': str}``
    """
    expected_ports = set(port_attributes_dict.keys())
    if not expected_ports:
        return {
            "passed": True,
            "up": [], "down": [],
            "details": "no ports to verify (port_attributes_dict is empty)",
        }

    intf_status = get_dut_interfaces_status(duthost)

    up = []
    down = []
    for port in sorted(expected_ports):
        status = intf_status.get(port)
        if status and status.get("admin") == "up" and status.get("oper") == "up":
            up.append(port)
        else:
            admin = status.get("admin", "missing") if status else "missing"
            oper = status.get("oper", "missing") if status else "missing"
            down.append(f"{port}(admin={admin}, oper={oper})")
            logger.warning("Port %s not up: admin=%s oper=%s", port, admin, oper)

    passed = len(down) == 0
    total = len(expected_ports)
    if passed:
        details = f"{len(up)}/{total} transceiver ports admin-up and oper-up"
    else:
        details = (
            f"{len(down)}/{total} transceiver port(s) NOT up: "
            + "; ".join(down)
        )
    logger.info("Link-up check: %s", details)
    return {"passed": passed, "up": up, "down": down, "details": details}

"""Port Configuration tests for transceivers (CONFIG_DB validation).

Implements the 7 test cases in
``docs/testplan/transceiver/port_config_test_plan.md``.  Every test is a
read-only CONFIG_DB query that compares the running per-port configuration
against the expected values resolved from the transceiver inventory
(``BASE_ATTRIBUTES`` / ``PORT_CONFIG_ATTRIBUTES`` in ``port_attributes_dict``).

All tests follow the suite-wide pattern: iterate ports, aggregate per-port
failures, and raise a single ``pytest.fail`` at the end so one run surfaces
every offending port instead of stopping at the first.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    PORT_CONFIG_ATTRIBUTES_KEY,
)
from tests.transceiver.port_config.utils import port_config_constants as const
from tests.transceiver.port_config.utils.port_config_db_reader import get_port_config
from tests.transceiver.port_config.utils.port_config_field_mapper import (
    config_db_speed_to_gbps,
    group_ports_by_physical_index,
    owns_first_host_lane,
)

logger = logging.getLogger(__name__)


def _base_attrs(port_attributes_dict, port):
    """Return BASE_ATTRIBUTES for a port (empty dict if absent)."""
    return port_attributes_dict.get(port, {}).get(BASE_ATTRIBUTES_KEY, {})


def _port_config_attrs(port_attributes_dict, port):
    """Return PORT_CONFIG_ATTRIBUTES for a port (empty dict if absent)."""
    return port_attributes_dict.get(port, {}).get(PORT_CONFIG_ATTRIBUTES_KEY, {})


# ──────────────────────────────────────────────────────────────────────
# TC1: Port admin status validation
# ──────────────────────────────────────────────────────────────────────


def test_port_admin_status_in_config_db(transceiver_ports, config_db_port_table):
    """TC1: every transceiver port has ``admin_status == "up"`` in CONFIG_DB.

    A port found admin-down is a misconfiguration (the transceiver under test
    is expected to be administratively enabled), reported per-port.
    """
    all_failures = []
    for port in transceiver_ports:
        port_config = get_port_config(config_db_port_table, port)
        if not port_config:
            all_failures.append("{}: not present in CONFIG_DB PORT table".format(port))
            continue
        admin_status = port_config.get(const.PORT_FIELD_ADMIN_STATUS)
        if admin_status != const.ADMIN_STATUS_UP:
            all_failures.append(
                "{}: admin_status={!r}, expected {!r}".format(
                    port, admin_status, const.ADMIN_STATUS_UP
                )
            )
        else:
            logger.debug("Port %s admin_status=up", port)

    if all_failures:
        pytest.fail("Port admin status validation failures:\n" + "\n".join(all_failures))


# ──────────────────────────────────────────────────────────────────────
# TC2: Port speed validation
# ──────────────────────────────────────────────────────────────────────


def test_port_speed_in_config_db(transceiver_ports, config_db_port_table, port_attributes_dict):
    """TC2: CONFIG_DB ``speed`` (Mbps) matches ``speed_gbps`` from BASE_ATTRIBUTES.

    ``speed_gbps`` is mandatory in ``dut_info``; a port missing it is a
    configuration gap and is reported rather than skipped.
    """
    all_failures = []
    for port in transceiver_ports:
        expected_gbps = _base_attrs(port_attributes_dict, port).get(const.ATTR_SPEED_GBPS)
        if expected_gbps is None:
            all_failures.append(
                "{}: '{}' missing in BASE_ATTRIBUTES (mandatory in dut_info)".format(
                    port, const.ATTR_SPEED_GBPS
                )
            )
            continue

        port_config = get_port_config(config_db_port_table, port)
        if not port_config:
            all_failures.append("{}: not present in CONFIG_DB PORT table".format(port))
            continue

        actual_gbps, err = config_db_speed_to_gbps(port_config)
        if err:
            all_failures.append("{}: {}".format(port, err))
            continue
        if actual_gbps != expected_gbps:
            all_failures.append(
                "{}: speed {}G in CONFIG_DB, expected {}G".format(port, actual_gbps, expected_gbps)
            )
        else:
            logger.debug("Port %s speed=%dG matches", port, actual_gbps)

    if all_failures:
        pytest.fail("Port speed validation failures:\n" + "\n".join(all_failures))


# ──────────────────────────────────────────────────────────────────────
# TC3: FEC configuration validation (ports >= 200G)
# ──────────────────────────────────────────────────────────────────────


def test_fec_config_in_config_db(transceiver_ports, config_db_port_table, port_attributes_dict):
    """TC3: ports >= 200 Gbps must have ``fec == "rs"`` in CONFIG_DB.

    Ports below the threshold are skipped per-port (FEC mode is not pinned for
    them by this plan).
    """
    all_failures = []
    checked = 0
    for port in transceiver_ports:
        expected_gbps = _base_attrs(port_attributes_dict, port).get(const.ATTR_SPEED_GBPS)
        if expected_gbps is None:
            all_failures.append(
                "{}: '{}' missing in BASE_ATTRIBUTES (mandatory in dut_info)".format(
                    port, const.ATTR_SPEED_GBPS
                )
            )
            continue
        if expected_gbps < const.FEC_REQUIRED_MIN_SPEED_GBPS:
            logger.debug("Port %s speed %dG < %dG, skipping FEC check",
                         port, expected_gbps, const.FEC_REQUIRED_MIN_SPEED_GBPS)
            continue

        port_config = get_port_config(config_db_port_table, port)
        if not port_config:
            all_failures.append("{}: not present in CONFIG_DB PORT table".format(port))
            continue

        fec = port_config.get(const.PORT_FIELD_FEC)
        if fec is None:
            all_failures.append(
                "{}: no 'fec' field for {}G port (>= {}G requires '{}')".format(
                    port, expected_gbps, const.FEC_REQUIRED_MIN_SPEED_GBPS, const.FEC_MODE_RS
                )
            )
        elif fec != const.FEC_MODE_RS:
            all_failures.append(
                "{}: fec={!r} for {}G port, expected {!r}".format(
                    port, fec, expected_gbps, const.FEC_MODE_RS
                )
            )
        else:
            checked += 1
            logger.debug("Port %s (%dG) fec=rs", port, expected_gbps)

    logger.info("FEC validation checked %d high-speed port(s)", checked)
    if all_failures:
        pytest.fail("FEC configuration validation failures:\n" + "\n".join(all_failures))


# ──────────────────────────────────────────────────────────────────────
# TC4: MTU configuration validation (optional attribute)
# ──────────────────────────────────────────────────────────────────────


def test_mtu_config_in_config_db(transceiver_ports, config_db_port_table, port_attributes_dict):
    """TC4: CONFIG_DB ``mtu`` matches ``expected_mtu`` from PORT_CONFIG_ATTRIBUTES.

    ``expected_mtu`` is optional; a port without it is skipped (not failed) per
    the plan, so this test only runs where the inventory pins an MTU.
    """
    all_failures = []
    any_checked = False
    for port in transceiver_ports:
        expected_mtu = _port_config_attrs(port_attributes_dict, port).get(const.ATTR_EXPECTED_MTU)
        if expected_mtu is None:
            logger.debug("Port %s: expected_mtu not configured, skipping", port)
            continue

        port_config = get_port_config(config_db_port_table, port)
        if not port_config:
            all_failures.append("{}: not present in CONFIG_DB PORT table".format(port))
            continue

        actual_mtu = port_config.get(const.PORT_FIELD_MTU)
        if actual_mtu is None:
            all_failures.append("{}: no 'mtu' field in CONFIG_DB PORT entry".format(port))
            continue
        any_checked = True
        # CONFIG_DB stores mtu as a string; compare on int to avoid "9100" != 9100.
        try:
            if int(str(actual_mtu).strip()) != int(expected_mtu):
                all_failures.append(
                    "{}: mtu={!r} in CONFIG_DB, expected {!r}".format(port, actual_mtu, expected_mtu)
                )
            else:
                logger.debug("Port %s mtu=%s matches", port, actual_mtu)
        except (TypeError, ValueError):
            all_failures.append(
                "{}: non-integer mtu (CONFIG_DB={!r}, expected={!r})".format(
                    port, actual_mtu, expected_mtu
                )
            )

    if not any_checked and not all_failures:
        pytest.skip("No ports define 'expected_mtu'; skipping MTU validation")
    if all_failures:
        pytest.fail("MTU configuration validation failures:\n" + "\n".join(all_failures))


# ──────────────────────────────────────────────────────────────────────
# TC5: Auto-negotiation setting validation (optional attribute)
# ──────────────────────────────────────────────────────────────────────


def test_autoneg_config_in_config_db(transceiver_ports, config_db_port_table, port_attributes_dict):
    """TC5: CONFIG_DB ``autoneg`` matches ``expected_autoneg`` from PORT_CONFIG_ATTRIBUTES.

    ``expected_autoneg`` ("on"/"off") is optional; ports without it are skipped.
    A DAC cable with autoneg incorrectly enabled is a typical failure surfaced
    here when the inventory pins the expected value.
    """
    all_failures = []
    any_checked = False
    for port in transceiver_ports:
        expected_autoneg = _port_config_attrs(port_attributes_dict, port).get(
            const.ATTR_EXPECTED_AUTONEG
        )
        if expected_autoneg is None:
            logger.debug("Port %s: expected_autoneg not configured, skipping", port)
            continue

        port_config = get_port_config(config_db_port_table, port)
        if not port_config:
            all_failures.append("{}: not present in CONFIG_DB PORT table".format(port))
            continue

        actual_autoneg = port_config.get(const.PORT_FIELD_AUTONEG)
        if actual_autoneg is None:
            all_failures.append("{}: no 'autoneg' field in CONFIG_DB PORT entry".format(port))
            continue
        any_checked = True
        if str(actual_autoneg).strip().lower() != str(expected_autoneg).strip().lower():
            all_failures.append(
                "{}: autoneg={!r} in CONFIG_DB, expected {!r}".format(
                    port, actual_autoneg, expected_autoneg
                )
            )
        else:
            logger.debug("Port %s autoneg=%s matches", port, actual_autoneg)

    if not any_checked and not all_failures:
        pytest.skip("No ports define 'expected_autoneg'; skipping autoneg validation")
    if all_failures:
        pytest.fail("Auto-negotiation validation failures:\n" + "\n".join(all_failures))


# ──────────────────────────────────────────────────────────────────────
# TC6: DOM polling enabled validation (first subport of breakout group only)
# ──────────────────────────────────────────────────────────────────────


def test_dom_polling_enabled_in_config_db(
    transceiver_ports, config_db_port_table, port_attributes_dict
):
    """TC6: first subports (and non-breakout ports) must not have DOM polling disabled.

    Only the first subport of a breakout group owns the physical transceiver's
    DOM data, so the plan validates DOM polling on the port that owns the first
    host lane (``host_lane_mask`` includes bit 0); other subports are skipped.

    The ``dom_polling`` field absent => enabled (SONiC default) => pass.  Only an
    explicit ``"disabled"`` is a failure (DOM data won't populate STATE_DB).
    """
    all_failures = []
    checked = 0
    for port in transceiver_ports:
        host_lane_mask = _base_attrs(port_attributes_dict, port).get(const.ATTR_HOST_LANE_MASK)
        if not owns_first_host_lane(host_lane_mask):
            logger.debug("Port %s does not own first host lane (mask=%r), skipping DOM polling",
                         port, host_lane_mask)
            continue

        port_config = get_port_config(config_db_port_table, port)
        if not port_config:
            all_failures.append("{}: not present in CONFIG_DB PORT table".format(port))
            continue

        raw = port_config.get(const.PORT_FIELD_DOM_POLLING)
        normalized = "" if raw is None else str(raw).strip().lower()
        if normalized == const.DOM_POLLING_DISABLED:
            all_failures.append(
                "{}: dom_polling is 'disabled' (DOM data will not populate STATE_DB)".format(port)
            )
        elif normalized in ("", const.DOM_POLLING_ENABLED):
            checked += 1
            logger.debug("Port %s dom_polling=%s", port, raw if raw is not None else "<default>")
        else:
            all_failures.append(
                "{}: dom_polling has unexpected value {!r} (expected absent/'enabled')".format(
                    port, raw
                )
            )

    logger.info("DOM polling validation checked %d first-subport(s)", checked)
    if all_failures:
        pytest.fail("DOM polling validation failures:\n" + "\n".join(all_failures))


# ──────────────────────────────────────────────────────────────────────
# TC7: subport field validation (breakout vs non-breakout grouping)
# ──────────────────────────────────────────────────────────────────────


def test_subport_field_in_config_db(
    transceiver_ports, config_db_port_table, physical_index_by_port
):
    """TC7: ``subport`` is absent/"0" for non-breakout ports and present for breakout subports.

    Logical ports are grouped by physical index:
      * a group of exactly 1 logical port (non-breakout): ``subport`` absent or "0".
      * a group of >1 logical ports (breakout): every member must carry ``subport``.
    """
    all_failures = []

    groups, unknown_ports = group_ports_by_physical_index(transceiver_ports, physical_index_by_port)
    for port in unknown_ports:
        all_failures.append("{}: no resolvable physical port index".format(port))

    for pindex, members in sorted(groups.items()):
        is_breakout = len(members) > 1
        for port in members:
            port_config = get_port_config(config_db_port_table, port)
            if not port_config:
                all_failures.append("{}: not present in CONFIG_DB PORT table".format(port))
                continue
            subport = port_config.get(const.PORT_FIELD_SUBPORT)

            if is_breakout:
                if subport is None:
                    all_failures.append(
                        "{} (phy index {}, breakout group of {}): 'subport' missing".format(
                            port, pindex, len(members)
                        )
                    )
                else:
                    logger.debug("Port %s breakout subport=%s", port, subport)
            else:
                if subport is not None and str(subport).strip() != const.SUBPORT_NON_BREAKOUT:
                    all_failures.append(
                        "{} (phy index {}, non-breakout): subport={!r}, expected absent or {!r}".format(
                            port, pindex, subport, const.SUBPORT_NON_BREAKOUT
                        )
                    )
                else:
                    logger.debug("Port %s non-breakout subport=%r", port, subport)

    if all_failures:
        pytest.fail("Subport field validation failures:\n" + "\n".join(all_failures))

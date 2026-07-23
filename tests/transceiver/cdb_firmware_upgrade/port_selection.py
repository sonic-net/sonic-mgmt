"""Port-selection helpers shared across the CDB firmware-upgrade test suite.

"""
import logging

from tests.common.platform.interface_utils import (
    get_physical_to_logical_port_mapping,
    is_first_subport,
)
from tests.transceiver.attribute_parser.attribute_keys import (
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)

logger = logging.getLogger(__name__)


def resolve_ports_under_test(lport_to_pport, port_attributes_dict):
    """Resolve the set of logical ports the check should run on.

    ``ports_under_test`` is an optional DUT-level CDB attribute. When it is
    absent or empty the check runs on every qualifying port. When it is
    present the physical indices are mapped to their logical ports and only
    those logical ports are returned.

    Returns:
        set[str] | None: the logical ports to test, or ``None``
    """
    if not port_attributes_dict:
        return None
    cdb_attrs = next(iter(port_attributes_dict.values())).get(
        CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {}
    )
    ports_under_test = cdb_attrs.get("ports_under_test")
    if not ports_under_test:
        return None
    ports_under_test = set(ports_under_test)
    pport_to_lport_mapping = get_physical_to_logical_port_mapping(lport_to_pport)
    resolved_ports = set()
    for pindex in ports_under_test:
        resolved_ports.update(pport_to_lport_mapping.get(pindex, []))
    return resolved_ports


def get_qualifying_ports(port_attributes_dict, lport_to_first_subport, ports_under_test):
    """Return the logical ports the CDB firmware checks should run on.

    A port qualifies only when it has attributes, is the first breakout sub-port
    of its group, and is a non-DAC CMIS module (``cmis_active_optical``).

    Args:
        port_attributes_dict: ``{port: {attr_block: {...}}}`` inventory map.
        lport_to_first_subport: first-sub-port mapping fixture.
        ports_under_test: set of logical ports to restrict to.

    Returns:
        list[str]: the qualifying logical port names.
    """
    qualifying_ports = []
    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue
        if ports_under_test is not None and port not in ports_under_test:
            logger.debug("Port %s is not in ports_under_test, skipping", port)
            continue
        if not is_first_subport(port, lport_to_first_subport):
            logger.debug("Port %s is not the first breakout sub-port, skipping", port)
            continue

        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
        if not eeprom_attrs.get("cmis_active_optical"):
            logger.debug("Port %s: cmis_active_optical is not True, skipping", port)
            continue

        qualifying_ports.append(port)
    return qualifying_ports

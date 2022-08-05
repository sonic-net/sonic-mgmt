"""DualToR related common utilities for other modules."""
import json
import pytest


__all__ = [
    'cable_type',
    'CableType',
    'mux_config',
    'active_standby_ports',
    'active_active_ports'
]


class CableType(object):
    """Dualtor cable type."""
    active_active = "active-active"
    active_standby = "active-standby"
    default_type = "active-standby"


@pytest.fixture(params=[CableType.active_standby, CableType.active_active])
def cable_type(request, active_active_ports, active_standby_ports):
    """Dualtor cable type."""
    cable_type = request.param
    has_enable_active_active_marker = bool([_ for _ in request.node.iter_markers() if _.name == "enable_active_active"])
    if ((not has_enable_active_active_marker) and (cable_type == CableType.active_active)):
        pytest.skip("Skip cable type 'active-active'")

    if cable_type == CableType.active_active and not active_active_ports:
        pytest.skip("Skip as no mux ports of 'active-active' cable type")
    elif cable_type == CableType.active_standby and not active_standby_ports:
        pytest.skip("Skip as no mux ports of 'active-standby' cable type")

    return cable_type


@pytest.fixture(scope="session")
def mux_config(duthosts, tbinfo):
    if 'dualtor' not in tbinfo['topo']['name']:
        return {}

    # NOTE: assume both ToRs have the same mux config
    duthost = duthosts[0]
    cmd = 'show mux config --json'
    return json.loads(duthost.shell(cmd)['stdout'])["MUX_CABLE"]["PORTS"]


@pytest.fixture(scope="session")
def active_active_ports(mux_config, tbinfo):
    if 'dualtor' not in tbinfo['topo']['name']:
        return []

    active_active_ports = []
    for port, port_config in mux_config.items():
        if port_config["SERVER"].get("cable_type", CableType.default_type) == CableType.active_active:
            active_active_ports.append(port)

    return active_active_ports


@pytest.fixture(scope="session")
def active_standby_ports(mux_config, tbinfo):
    if 'dualtor' not in tbinfo['topo']['name']:
        return []

    active_standby_ports = []
    for port, port_config in mux_config.items():
        if port_config["SERVER"].get("cable_type", CableType.default_type) == CableType.active_standby:
            active_standby_ports.append(port)

    return active_standby_ports

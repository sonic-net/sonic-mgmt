"""DualToR related common utilities for other modules."""
import json
import pytest


__all__ = [
    'cable_type',
    'CableType',
    'mux_config'
]


class CableType(object):
    """Dualtor cable type."""
    active_active = "active-active"
    active_standby = "active-standby"
    default_type = "active-standby"


@pytest.fixture(params=[CableType.active_standby])
def cable_type(request):
    """Dualtor cable type."""
    return request.param


@pytest.fixture(scope="session")
def mux_config(duthosts, tbinfo):
    if 'dualtor' not in tbinfo['topo']['name']:
        return {}

    # NOTE: assume both ToRs have the same mux config
    duthost = duthosts[0]
    cmd = 'show mux config --json'
    return json.loads(duthost.shell(cmd)['stdout'])["MUX_CABLE"]["PORTS"]

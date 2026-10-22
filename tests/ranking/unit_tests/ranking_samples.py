import pytest

from tests.ranking.cases.tools.generate_manifest import build_manifest


@pytest.fixture
def manifest():
    return build_manifest(
        ['sairoute.RouteA', 'saivlan.VlanA', 'sairoute.RouteB'],
        {'repo': 'SAI', 'commit': 'a' * 40},
        {},
    )


@pytest.fixture
def inputs():
    config_db = {'PORT': {
        'Ethernet8': {'lanes': '8,9,10,11', 'index': '3', 'speed': '400000'},
        'Ethernet40': {'lanes': '40,41,42,43', 'index': '11', 'speed': '400000'},
    }, 'DEVICE_METADATA': {'localhost': {'hostname': 'dut-a'}}}
    ptf_ports = {
        'Ethernet8': {'id': 7, 'interface': 'eth7'},
        'Ethernet40': {'id': 18, 'interface': 'eth18'},
    }
    return config_db, ['Ethernet40', 'Ethernet8'], ptf_ports

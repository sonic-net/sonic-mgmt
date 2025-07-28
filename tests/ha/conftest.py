import pytest
from pathlib import Path
from common.ha.smartswitch_ha_io import SmartSwitchHaTrafficTest


@pytest.fixture(scope="module")
def deploy_files(ptfhost):
    current_path = Path(__file__).resolve()
    tcp_server_path = current_path.parent.parent.joinpath("common", "ha", "tcp_server.py")
    tcp_client_path = current_path.parent.parent.joinpath("common", "ha", "tcp_client.py")

    ptfhost.copy(src=str(tcp_server_path), dest='/root')
    ptfhost.copy(src=str(tcp_client_path), dest='/root')


@pytest.fixture(scope="module")
def setup_SmartSwitchHaTrafficTest(duthost, ptfhost, ptfadapter, vmhost, tbinfo):
    activehost = duthost
    standbyhost = duthost
    io_ready = None

    ha_io = SmartSwitchHaTrafficTest(activehost, standbyhost, ptfhost,
                                     ptfadapter, vmhost, tbinfo, io_ready, namespace="ns1")
    return ha_io


@pytest.fixture(scope="module")
def setup_namespaces_with_routes(ptfhost, duthosts):
    # TODO: Implement the fixture to set up namespaces with routes
    pass


@pytest.fixture(scope="module")
def setup_ha_config():
    # TODO: Implement the fixture to set up HA configuration
    pass

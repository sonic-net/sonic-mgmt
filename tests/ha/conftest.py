import pytest
from common.ha.smartswitch_ha_helper import PtfTcpTestAdapter
from common.ha.smartswitch_ha_io import SmartSwitchHaTrafficTest


@pytest.fixture(scope="module")
def copy_files(ptfhost):
    ptfhost.copy(src="/data/tests/ha/tcp_server.py", dest='/root')
    ptfhost.copy(src="/data/tests/ha/tcp_client.py", dest='/root')


@pytest.fixture(scope='module')
def tcp_adapter(ptfadapter):
    return PtfTcpTestAdapter(ptfadapter)


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

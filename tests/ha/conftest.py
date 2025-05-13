import pytest
from ha_helper import PtfTcpTestAdapter
from common.ha.ha_tor_io import HaDualTorIO


@pytest.fixture(scope="module")
def copy_files(ptfhost):
    ptfhost.copy(src="/data/tests/ha/tcp_server.py", dest='/root')
    ptfhost.copy(src="/data/tests/ha/tcp_client.py", dest='/root')

@pytest.fixture(scope='module')
def tcp_adapter(ptfadapter):
    return PtfTcpTestAdapter(ptfadapter)


@pytest.fixture(scope="module")
def setup_HaDualTorIO(duthost,ptfhost,ptfadapter,vmhost,tbinfo):
    activehost = duthost
    standbyhost = duthost
    io_ready = None

    ha_io = HaDualTorIO(activehost, standbyhost, ptfhost, ptfadapter, vmhost, tbinfo, io_ready,namespace="ns1")
    return ha_io

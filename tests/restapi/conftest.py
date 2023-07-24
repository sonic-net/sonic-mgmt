import logging
import pytest
import urllib3
from six.moves.urllib.parse import urlunparse

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.restapi_helper import generate_cert, apply_cert_config, RESTAPI_CONTAINER_NAME

@pytest.fixture(scope="module", autouse=True)
def setup_restapi_server(duthosts, rand_one_dut_hostname, localhost):
    '''
    Create RESTAPI client certificates and copy the subject names to the config DB
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Check if RESTAPI is enabled on the device
    pyrequire(check_container_state(duthost, RESTAPI_CONTAINER_NAME, should_be_running=True),
              "Test was not supported on devices which do not support RESTAPI!")

    # Generate the certificate
    generate_cert(duthost, localhost)

    apply_cert_config(duthost)
    urllib3.disable_warnings()

    yield
    # Perform a config load_minigraph to ensure config_db is not corrupted
    config_reload(duthost, config_source='minigraph')

@pytest.fixture
def construct_url(duthosts, rand_one_dut_hostname):
    def get_endpoint(path):
        duthost = duthosts[rand_one_dut_hostname]
        RESTAPI_PORT = "8081"
        netloc = duthost.mgmt_ip+":"+RESTAPI_PORT
        try:
            tup = ('https', netloc, path, '', '', '')
            endpoint = urlunparse(tup)
        except Exception:
            logging.error("Invalid URL: "+endpoint)
            return None
        return endpoint
    return get_endpoint


@pytest.fixture
def vlan_members(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    VLAN_INDEX = 0
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if mg_facts["minigraph_vlans"] != {}:
        vlan_interfaces = list(mg_facts["minigraph_vlans"].values())[
            VLAN_INDEX]["members"]
        if vlan_interfaces is not None:
            return vlan_interfaces
    return []

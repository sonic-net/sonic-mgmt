import pytest
import logging
import random

from tests.zmq.gnmi_zmq_utils import gnmi_set, enable_zmq_fixture, cleanup_zmq_fixture

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


@pytest.fixture
def enable_zmq(duthost):
    """Fixture to enable ZMQ with management VRF enabled."""
    initial_mgmt_vrf_enabled, subtype = enable_zmq_fixture(duthost, enable_mgmt_vrf=True)

    yield

    cleanup_zmq_fixture(duthost, initial_mgmt_vrf_enabled, subtype, enable_mgmt_vrf=True)


def test_gnmi_zmq(duthosts,
                  rand_one_dut_hostname,
                  ptfhost,
                  enable_zmq):
    duthost = duthosts[rand_one_dut_hostname]

    command = 'ps -auxww | grep "/usr/sbin/telemetry -logtostderr --noTLS --port 8080"'
    gnmi_process = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.debug("gnmi_process: {}".format(gnmi_process))

    file_name = "vnet.txt"
    vnet_key = "Vnet{}".format(random.randint(0, 1000))
    text = "{\"" + vnet_key + "\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE:@/root/%s" % (file_name)]
    gnmi_set(duthost, ptfhost, [], update_list, [])

    command = 'sonic-db-cli APPL_DB keys "*" | grep "DASH_VNET_TABLE:{}"'.format(vnet_key)
    appl_db_key = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.debug("appl_db_key: {}".format(appl_db_key))
    assert appl_db_key == "DASH_VNET_TABLE:{}".format(vnet_key)

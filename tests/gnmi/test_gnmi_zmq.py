import pytest
import logging
import random

from .helper import gnmi_capabilities, gnmi_set, add_gnmi_client_common_name, del_gnmi_client_common_name
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health
]


@pytest.fixture
def enable_zmq(duthost):
    command = 'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" subtype'
    subtype = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.warning("subtype: {}".format(subtype))

    def _check_process_ready(process_name):
        pid = duthost.shell("pgrep {}".format(process_name), module_ignore_errors=True)["stdout"]
        logger.warning("_check_orchagent_ready: {} PID {}".format(process_name, pid))
        return pid != ""

    if subtype == "SmartSwitch":
        yield
        return

    # enable ZMQ
    command = 'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" subtype SmartSwitch'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.warning("set subtype subtype: {}".format(result))

    duthost.shell("sudo config save -y", module_ignore_errors=True)
    duthost.shell("sudo config reload -y", module_ignore_errors=True)
    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "orchagent"),
                  "The orchagent not start after change subtype")
    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "telemetry"),
                  "The telemetry not start after change subtype")

    yield

    # revert change
    command = 'sonic-db-cli CONFIG_DB hdel "DEVICE_METADATA|localhost" subtype'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.warning("revert subtype subtype: {}".format(result))

    duthost.shell("sudo config save -y", module_ignore_errors=True)
    duthost.shell("sudo config reload -y", module_ignore_errors=True)

    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "orchagent"),
                  "The orchagent not start after change subtype")

    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "telemetry"),
                  "The telemetry not start after change subtype")


def test_gnmi_zmq(duthosts,
                    rand_one_dut_hostname,
                    ptfhost,
                    enable_zmq):
    duthost = duthosts[rand_one_dut_hostname]

    file_name = "vnet.txt"
    key = "Vnet{}".format(random.randint(0, 1000))
    text = "{\"{" + key + "}\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE:@/root/%s" % (file_name)]
    msg = ""
    try:
        gnmi_set(duthost, ptfhost, [], update_list, [])
    except Exception as e:
        logger.info("Failed to set: " + str(e))
        msg = str(e)

    logger.warning("Failed: " + msg)
    command = 'sonic-db-cli APPL_DB keys "*" | grep "DASH_VNET_TABLE:{}"'.format(key)
    appl_db_key = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.warning("appl_db_key:{}".format(appl_db_key))
    assert appl_db_key == "DASH_VNET_TABLE:{}".format(key)

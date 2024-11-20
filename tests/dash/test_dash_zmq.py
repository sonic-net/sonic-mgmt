import logging
import pytest
import random

from gnmi_utils import apply_gnmi_file
from dash_utils import render_template_to_host
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('dpu'),
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
        pid = duthost.shell("pgrep {}".format(process_name))["stdout"]
        logger.warning("_check_orchagent_ready: {} PID {}".format(process_name, pid))
        return pid != ""

    if subtype == "SmartSwitch":
        yield
        return

    # enable ZMQ
    command = 'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" subtype SmartSwitch'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.warning("set subtype subtype: {}".format(result))
    duthost.shell("docker restart swss")
    duthost.shell("docker restart gnmi")

    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "orchagent"),
                  "The orchagent not start after change subtype")

    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "telemetry"),
                  "The telemetry not start after change subtype")

    yield

    # revert change
    command = 'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" subtype ""'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.warning("revert subtype subtype: {}".format(result))
    duthost.shell("docker restart swss")
    duthost.shell("docker restart gnmi")

    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "orchagent"),
                  "The orchagent not start after revert subtype")

    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "telemetry"),
                  "The telemetry not start after revert subtype")


def test_dash_zmq(ptfadapter, localhost, duthost, ptfhost, dash_config_info, enable_zmq):
    """
    The test is to verify that GNMI ZmqProducer table will write data to APPL_DB
    """
    key = "test_{}".format(random.randint(0, 1000))
    dest_path = "/tmp/dash_zmq_test.json"
    render_template_to_host("dash_zmq_test.j2", duthost, dest_path, dash_config_info, test_key=key)
    apply_gnmi_file(localhost, duthost, ptfhost, dest_path)
    # verify APPL_DB updated by GNMI
    if duthost.shell("netstat -na | grep -w 8100", module_ignore_errors=True)['rc'] == 0:
        command = 'sonic-db-cli APPL_DB keys "*" | grep "DASH_TEST_TABLE:{}"'.format(key)
        appl_db_key = duthost.shell(command, module_ignore_errors=True)["stdout"]
        logger.warning("appl_db_key:{}".format(appl_db_key))
        assert appl_db_key == "DASH_TEST_TABLE:{}".format(key)
    else:
        logger.warning("test_dash_zmq: test failed because ZMQ not enabled")
        assert False

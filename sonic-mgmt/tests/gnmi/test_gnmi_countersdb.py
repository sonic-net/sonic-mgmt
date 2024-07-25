import logging
import pytest
import re

from .helper import gnmi_get, gnmi_subscribe_polling, gnmi_subscribe_streaming_sample
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_gnmi_queue_buffer_cnt(duthosts, rand_one_dut_hostname, ptfhost):
    """
    Check number of queue counters
    """
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    logger.info('start gnmi output testing')
    iface = "Ethernet0"
    # Get UC for Ethernet0
    dut_command = "show queue counters %s" % iface
    result = duthost.shell(dut_command, module_ignore_errors=True)
    uc_list = re.findall(r"UC(\d+)", result["stdout"])
    for i in uc_list:
        # Read UC
        path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS_QUEUE_NAME_MAP/" + iface + ":" + str(i)]
        msg_list = gnmi_get(duthost, ptfhost, path_list)
        result = msg_list[0]
        pytest_assert("oid" in result, result)
    # Read invalid UC
    path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS_QUEUE_NAME_MAP/" + iface + ":abc"]
    try:
        msg_list = gnmi_get(duthost, ptfhost, path_list)
    except Exception as e:
        assert "GRPC error" in str(e), str(e)
    else:
        pytest.fail("Should fail for invalid path: " + path_list[0])


def test_gnmi_output(duthosts, rand_one_dut_hostname, ptfhost):
    """
    Read COUNTERS table
    Get table key from COUNTERS_PORT_NAME_MAP
    """
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    logger.info('start gnmi output testing')
    # Get COUNTERS table key for Ethernet0
    dut_command = "sonic-db-cli COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, "Invalid oid: " + counter_key
    path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS/" + counter_key]
    msg_list = gnmi_get(duthost, ptfhost, path_list)
    result = msg_list[0]
    logger.info("GNMI Server output")
    logger.info(result)
    pytest_assert("SAI_PORT_STAT_IF_IN_ERRORS" in result,
                  "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi_output: " + result)


test_data_counters_port_name_map = [
    {
        "name": "Subscribe table for COUNTERS_PORT_NAME_MAP",
        "path": "/sonic-db:COUNTERS_DB/localhost/COUNTERS_PORT_NAME_MAP"
    },
    {
        "name": "Subscribe table field for COUNTERS_PORT_NAME_MAP",
        "path": "/sonic-db:COUNTERS_DB/localhost/COUNTERS_PORT_NAME_MAP/Ethernet0"
    }
]


@pytest.mark.parametrize('test_data', test_data_counters_port_name_map)
def test_gnmi_counterdb_polling_01(duthosts, rand_one_dut_hostname, ptfhost, test_data):
    '''
    Verify GNMI subscribe API
    Subscribe polling mode for COUNTERS_PORT_NAME_MAP
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    path_list = [test_data["path"]]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("oid") >= exp_cnt, test_data["name"] + ": " + msg


def test_gnmi_counterdb_polling_02(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI subscribe API
    Subscribe polling mode for COUNTERS
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    # Get COUNTERS table key for Ethernet0
    dut_command = "sonic-db-cli COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, "Invalid oid: " + counter_key
    # Subscribe table
    path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS/"]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, msg
    # Subscribe table key
    path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS/" + counter_key]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, msg
    # Subscribe table field
    path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS/" + counter_key + "/SAI_PORT_STAT_IF_IN_ERRORS"]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, msg


@pytest.mark.parametrize('test_data', test_data_counters_port_name_map)
def test_gnmi_counterdb_streaming_sample_01(duthosts, rand_one_dut_hostname, ptfhost, test_data):
    '''
    Verify GNMI subscribe API
    Subscribe streaming sample mode for COUNTERS_PORT_NAME_MAP
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    path_list = [test_data["path"]]
    msg, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, exp_cnt)
    assert msg.count("oid") >= exp_cnt, test_data["name"] + ": " + msg


def test_gnmi_counterdb_streaming_sample_02(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI subscribe API
    Subscribe streaming sample mode for COUNTERS
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    # Get COUNTERS table key for Ethernet0
    dut_command = "sonic-db-cli COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, "Invalid oid: " + counter_key
    # Subscribe table
    path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS/"]
    msg, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, msg
    # Subscribe table key
    path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS/" + counter_key]
    msg, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, msg
    # Subscribe table field
    path_list = ["/sonic-db:COUNTERS_DB/localhost/COUNTERS/" + counter_key + "/SAI_PORT_STAT_IF_IN_ERRORS"]
    msg, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, msg

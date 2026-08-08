import json
import logging
import pytest
import re

from .helper import gnmi_get, gnmi_subscribe_polling, gnmi_subscribe_streaming_sample, get_namespace, \
                     apply_cert_config
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

CFG_DB_PATH = "/etc/sonic/config_db.json"
ORIG_CFG_DB = "/etc/sonic/orig_config_db.json"

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


def _load_new_cfg(duthost, data):
    duthost.copy(content=json.dumps(data, indent=4), dest=CFG_DB_PATH)
    config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True,
                  wait_for_bgp=True, yang_validate=False)
    # config reload restarts the gnmi container and drops the test cert/server setup;
    # re-apply it so subsequent gnmi_get calls authenticate.
    apply_cert_config(duthost)


def _get_buffer_queues_cnt(duthost, ptfhost, iface):
    namespace_name = get_namespace(duthost)
    path_list = ["/sonic-db:COUNTERS_DB/{}/COUNTERS_QUEUE_NAME_MAP".format(namespace_name)]
    try:
        msg_list = gnmi_get(duthost, ptfhost, path_list)
    except Exception:
        return 0
    result = str(msg_list)
    return len(re.findall(r'{}:\d+'.format(re.escape(iface)), result))


def _check_buffer_queues_cnt(duthost, ptfhost, iface):
    return _get_buffer_queues_cnt(duthost, ptfhost, iface) > 0


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
    namespace_name = get_namespace(duthost)
    if duthost.is_multi_asic:
        dut_command = f"show queue counters {iface} -n {namespace_name}"
    else:
        dut_command = f"show queue counters {iface}"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    uc_list = re.findall(r"UC(\d+)", result["stdout"])
    for i in uc_list:
        # Read UC
        path_list = [f"/sonic-db:COUNTERS_DB/{namespace_name}/COUNTERS_QUEUE_NAME_MAP/" + iface + ":" + str(i)]
        msg_list = gnmi_get(duthost, ptfhost, path_list)
        result = msg_list[0]
        pytest_assert("oid" in result, (
            "OID not found in result. "
            "Result: {}"
        ).format(result))

    # Read invalid UC
    path_list = [f"/sonic-db:COUNTERS_DB/{namespace_name}/COUNTERS_QUEUE_NAME_MAP/" + iface + ":abc"]
    try:
        msg_list = gnmi_get(duthost, ptfhost, path_list)
    except Exception as e:
        assert "GRPC error" in str(e), (
            "Expected GRPC error, but got: {}. "
        ).format(str(e))

    else:
        pytest.fail("Should fail for invalid path: " + path_list[0])

    # Verify the "create_only_config_db_buffers" optimization: with it enabled,
    # removing a BUFFER_QUEUE entry must reduce the number of queue counters in
    # COUNTERS_QUEUE_NAME_MAP for that interface.
    # Covers https://github.com/sonic-net/sonic-buildimage/issues/17448
    #.
    interfaces = duthost.get_interfaces_status()
    pattern = re.compile(r'^Ethernet[0-9]{1,3}$')
    admin_up_interfaces = [i for i, info in interfaces.items()
                           if pattern.match(i) and info['admin'] == 'up' and info['oper'] == 'up']

    duthost.shell("sonic-cfggen -d --print-data > {}".format(ORIG_CFG_DB))
    data = json.loads(duthost.shell("cat {}".format(ORIG_CFG_DB), verbose=False)['stdout'])

    if 'BUFFER_QUEUE' not in data or not data['BUFFER_QUEUE']:
        pytest.skip("Skipping test as BUFFER_QUEUE table is not present in config db")

    buffer_queues = list(data['BUFFER_QUEUE'].keys())
    buffer_queues_interfaces = [bq.split('|')[0] for bq in buffer_queues]

    interface_to_check = None
    for bq in buffer_queues_interfaces:
        if bq in admin_up_interfaces:
            interface_to_check = bq
            break
    if interface_to_check is None:
        pytest.skip("Skipping test as there are no admin-up interfaces with buffer queues to check")

    interface_buffer_queues = [bq for bq in buffer_queues if bq.split('|')[0] == interface_to_check]
    if len(interface_buffer_queues) == 0:
        pytest.skip("No valid entry for any interface:queue entry")

    # If the interface has a single grouped queue entry (e.g. Ethernet0|0-9), split
    # off the first queue (Ethernet0|0) so there is a distinct entry to remove.
    is_single_queue = False
    bq_entry = interface_buffer_queues[0]
    if len(interface_buffer_queues) == 1:
        ifc, q_range = bq_entry.split('|')
        if '-' in q_range:
            start, end = map(int, q_range.split('-'))
            if start < end:
                single_queue_entry = f"{ifc}|{start}"
                remaining_queue_entry = f"{ifc}|{start + 1}-{end}"
                profile = data['BUFFER_QUEUE'][bq_entry]['profile']
                data['BUFFER_QUEUE'][remaining_queue_entry] = {"profile": profile}
                data['BUFFER_QUEUE'][single_queue_entry] = {"profile": profile}
                del data['BUFFER_QUEUE'][bq_entry]
                bq_entry = single_queue_entry
            else:
                pytest.skip("Invalid buffer queue range")
        else:
            is_single_queue = True

    try:
        data['DEVICE_METADATA']["localhost"]["create_only_config_db_buffers"] = "true"
        _load_new_cfg(duthost, data)
        pytest_assert(wait_until(120, 20, 0, _check_buffer_queues_cnt, duthost, ptfhost, interface_to_check),
                      "Unable to get count of buffer queues from COUNTERS_QUEUE_NAME_MAP")
        pre_del_cnt = _get_buffer_queues_cnt(duthost, ptfhost, interface_to_check)

        # Remove a buffer queue, reload, and get the new number of queue counters.
        del data['BUFFER_QUEUE'][bq_entry]
        _load_new_cfg(duthost, data)
        if not is_single_queue:
            pytest_assert(wait_until(120, 20, 0, _check_buffer_queues_cnt, duthost, ptfhost, interface_to_check),
                          "Unable to get count of buffer queues from COUNTERS_QUEUE_NAME_MAP")
        post_del_cnt = _get_buffer_queues_cnt(duthost, ptfhost, interface_to_check)

        pytest_assert(pre_del_cnt > post_del_cnt,
                      "Number of queue counters count differs from expected")
    finally:
        data = json.loads(duthost.shell("cat {}".format(ORIG_CFG_DB), verbose=False)['stdout'])
        _load_new_cfg(duthost, data)


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
    namespace_name = get_namespace(duthost)
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}."
    ).format(counter_key)

    path_list = [f"/sonic-db:COUNTERS_DB/{namespace_name}/COUNTERS/" + counter_key]
    msg_list = gnmi_get(duthost, ptfhost, path_list)
    result = msg_list[0]
    logger.info("GNMI Server output")
    logger.info(result)
    pytest_assert("SAI_PORT_STAT_IF_IN_ERRORS" in result, (
        "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi_output: {}."
    ).format(result))


test_data_counters_port_name_map = [
    {
        "name": "Subscribe table for COUNTERS_PORT_NAME_MAP",
        "path": "/sonic-db:COUNTERS_DB/",
        "port": "",
    },
    {
        "name": "Subscribe table field for COUNTERS_PORT_NAME_MAP",
        "path": "/sonic-db:COUNTERS_DB/",
        "port": "/Ethernet0"
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
    namespace_name = get_namespace(duthost)
    path_list = [f"{test_data['path']}{namespace_name}/COUNTERS_PORT_NAME_MAP{test_data['port']}"]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("oid") >= exp_cnt, (
        "{}: {}. "
        "Expected count of 'oid': {}"
        "Actual count of 'oid': {}"
    ).format(test_data["name"], msg, exp_cnt, msg.count("oid"))


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
    namespace_name = get_namespace(duthost)
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}. "
        "Expected 'oid' in counter key"
    ).format(counter_key)

    # Subscribe table
    counters_path = f"/sonic-db:COUNTERS_DB/{namespace_name}/COUNTERS/"
    path_list = [counters_path]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, (
        "Expected count of 'SAI_PORT_STAT_IF_IN_ERRORS' not met. "
        "Expected count: {}"
        "Actual count: {}"
        "Message: {}"
    ).format(exp_cnt, msg.count("SAI_PORT_STAT_IF_IN_ERRORS"), msg)

    # Subscribe table key
    path_list = [counters_path + counter_key]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, (
        "Expected count of 'SAI_PORT_STAT_IF_IN_ERRORS' not met. "
        "Expected count: {}"
        "Actual count: {}"
        "Message: {}"
    ).format(exp_cnt, msg.count("SAI_PORT_STAT_IF_IN_ERRORS"), msg)
    # Subscribe table field
    path_list = [counters_path + counter_key + "/SAI_PORT_STAT_IF_IN_ERRORS"]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, (
        "Expected count of 'SAI_PORT_STAT_IF_IN_ERRORS' not met. "
        "Expected count: {}"
        "Actual count: {}"
        "Message: {}"
    ).format(exp_cnt, msg.count("SAI_PORT_STAT_IF_IN_ERRORS"), msg)


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
    namespace_name = get_namespace(duthost)
    path_list = [f"{test_data['path']}{namespace_name}/COUNTERS_PORT_NAME_MAP{test_data['port']}"]
    msg, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, exp_cnt, origin="sonic-db")
    assert msg.count("oid") >= exp_cnt, (
        "Expected count of 'oid' not met. "
        "Expected count: {}"
        "Actual count: {}"
        "Message: {}"
    ).format(exp_cnt, msg.count("oid"), msg)


def test_gnmi_counterdb_streaming_sample_02(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI subscribe API
    Subscribe streaming sample mode for COUNTERS
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    namespace_name = get_namespace(duthost)
    # Get COUNTERS table key for Ethernet0
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}. "
        "Expected 'oid' in counter key"
    ).format(counter_key)

    # Subscribe table field
    path_list = [f"/sonic-db:COUNTERS_DB/{namespace_name}/COUNTERS/" + counter_key + "/SAI_PORT_STAT_IF_IN_ERRORS"]
    msg, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, exp_cnt, origin="sonic-db")
    assert msg.count("SAI_PORT_STAT_IF_IN_ERRORS") >= exp_cnt, (
        "Expected count of 'SAI_PORT_STAT_IF_IN_ERRORS' not met. "
        "Expected count: {}"
        "Actual count: {}"
        "Message: {}"
    ).format(exp_cnt, msg.count("SAI_PORT_STAT_IF_IN_ERRORS"), msg)

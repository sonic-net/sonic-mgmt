import json
import logging
import pytest
import re

from .helper import get_namespace
from tests.common import config_reload
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.pygnmi_client import PygnmiClientCallError, PygnmiClientError, SubscribeMode
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

CFG_DB_PATH = "/etc/sonic/config_db.json"
CFG_DB_BACKUP = "/etc/sonic/config_db.json.gnmi_countersdb_backup"

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp"),
]


def _iter_response_text(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _iter_response_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_response_text(item)
    elif value is not None:
        yield str(value)


def _iter_updates(value):
    if isinstance(value, dict):
        updates = value.get("update")
        if isinstance(updates, list):
            yield from (update for update in updates if isinstance(update, dict))
        for item in value.values():
            yield from _iter_updates(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_updates(item)


def _response_has_update(value, text):
    for update in _iter_updates(value):
        update_value = update.get("val")
        if update_value is None or update_value == "" or update_value == {} or update_value == []:
            continue
        path = str(update.get("path") or "")
        if text in path or any(text in item for item in _iter_response_text(update_value)):
            return True
    return False


def _assert_responses_contain(result, text, expected):
    pytest_assert(len(result) == expected, (
        "Expected {} responses, got {}: {}"
    ).format(expected, len(result), result))
    pytest_assert(all(_response_has_update(response, text) for response in result), (
        "Expected '{}' in every response: {}"
    ).format(text, result))


def _countersdb_prefix(duthost):
    return "sonic-db:COUNTERS_DB/{}".format(get_namespace(duthost))


def _load_new_cfg(duthost, grpc_env, data):
    duthost.copy(content=json.dumps(data, indent=4), dest=CFG_DB_PATH)
    config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True,
                  wait_for_bgp=True, yang_validate=False)
    # config reload restarts the gnmi container and drops the test cert/server setup;
    # re-apply it so subsequent pygnmi calls authenticate.
    grpc_env.reconfigure_after_reboot()


def _get_buffer_queues_cnt(duthost, client, iface):
    try:
        result = client.get(
            "COUNTERS_QUEUE_NAME_MAP",
            prefix=_countersdb_prefix(duthost),
        )
    except PygnmiClientError:
        return 0
    queue_pattern = re.compile(r'{}:\d+'.format(re.escape(iface)))
    queues = set()
    for text in _iter_response_text(result):
        queues.update(queue_pattern.findall(text))
    return len(queues)


def _check_buffer_queues_cnt(duthost, client, iface):
    return _get_buffer_queues_cnt(duthost, client, iface) > 0


def test_gnmi_queue_buffer_cnt(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Check number of queue counters
    """
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
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
        path = "COUNTERS_QUEUE_NAME_MAP/" + iface + ":" + str(i)
        result = client.get(path, prefix=_countersdb_prefix(duthost))
        pytest_assert(_response_has_update(result, "oid"), (
            "OID not found in result. "
            "Result: {}"
        ).format(result))

    # Read invalid UC
    invalid_path = "COUNTERS_QUEUE_NAME_MAP/" + iface + ":abc"
    with pytest.raises(PygnmiClientCallError):
        client.get(invalid_path, prefix=_countersdb_prefix(duthost))

    # Verify the "create_only_config_db_buffers" optimization: with it enabled,
    # removing a BUFFER_QUEUE entry must reduce the number of queue counters in
    # COUNTERS_QUEUE_NAME_MAP for that interface.
    # Covers https://github.com/sonic-net/sonic-buildimage/issues/17448
    interfaces = duthost.get_interfaces_status()
    pattern = re.compile(r'^Ethernet[0-9]{1,3}$')
    admin_up_interfaces = [i for i, info in interfaces.items()
                           if pattern.match(i) and info['admin'] == 'up' and info['oper'] == 'up']

    data = json.loads(duthost.shell("sonic-cfggen -d --print-data", verbose=False)['stdout'])

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

    duthost.shell("cp {} {}".format(CFG_DB_PATH, CFG_DB_BACKUP))
    try:
        data['DEVICE_METADATA']["localhost"]["create_only_config_db_buffers"] = "true"
        _load_new_cfg(duthost, gnmi_tls, data)
        pytest_assert(wait_until(120, 20, 0, _check_buffer_queues_cnt, duthost, client, interface_to_check),
                      "Unable to get count of buffer queues from COUNTERS_QUEUE_NAME_MAP")
        pre_del_cnt = _get_buffer_queues_cnt(duthost, client, interface_to_check)

        # Remove a buffer queue, reload, and get the new number of queue counters.
        del data['BUFFER_QUEUE'][bq_entry]
        _load_new_cfg(duthost, gnmi_tls, data)
        if not is_single_queue:
            pytest_assert(wait_until(120, 20, 0, _check_buffer_queues_cnt, duthost, client, interface_to_check),
                          "Unable to get count of buffer queues from COUNTERS_QUEUE_NAME_MAP")
        post_del_cnt = _get_buffer_queues_cnt(duthost, client, interface_to_check)

        pytest_assert(pre_del_cnt > post_del_cnt,
                      "Number of queue counters count differs from expected")
    finally:
        duthost.shell("mv {} {}".format(CFG_DB_BACKUP, CFG_DB_PATH))
        config_reload(duthost, config_source='config_db', safe_reload=True,
                      check_intf_up_ports=True, wait_for_bgp=True,
                      yang_validate=False)


def test_gnmi_output(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Read COUNTERS table
    Get table key from COUNTERS_PORT_NAME_MAP
    """
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    logger.info('start gnmi output testing')
    # Get COUNTERS table key for Ethernet0
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}."
    ).format(counter_key)

    path = "COUNTERS/" + counter_key
    result = client.get(path, prefix=_countersdb_prefix(duthost))
    logger.info("GNMI Server output")
    logger.info(result)
    pytest_assert(_response_has_update(result, "SAI_PORT_STAT_IF_IN_ERRORS"), (
        "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi_output: {}."
    ).format(result))


test_data_counters_port_name_map = [
    {
        "name": "Subscribe table for COUNTERS_PORT_NAME_MAP",
        "port": "",
    },
    {
        "name": "Subscribe table field for COUNTERS_PORT_NAME_MAP",
        "port": "/Ethernet0"
    }
]


@pytest.mark.parametrize('test_data', test_data_counters_port_name_map)
def test_gnmi_counterdb_polling_01(rand_one_dut_hostname, gnmi_tls, test_data):  # noqa: F811
    '''
    Verify GNMI subscribe API
    Subscribe polling mode for COUNTERS_PORT_NAME_MAP
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    path = "COUNTERS_PORT_NAME_MAP{}".format(test_data['port'])
    result = list(gnmi_tls.pygnmi_client.subscribe(
        path, mode=SubscribeMode.POLL,
        poll_count=exp_cnt, poll_interval=1,
        prefix=_countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "oid", exp_cnt)


def test_gnmi_counterdb_polling_02(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    Verify GNMI subscribe API
    Subscribe polling mode for COUNTERS
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    # Get COUNTERS table key for Ethernet0
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}. "
        "Expected 'oid' in counter key"
    ).format(counter_key)

    # Subscribe table
    counters_path = "COUNTERS/"
    result = list(gnmi_tls.pygnmi_client.subscribe(
        counters_path, mode=SubscribeMode.POLL,
        poll_count=exp_cnt, poll_interval=1,
        prefix=_countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "SAI_PORT_STAT_IF_IN_ERRORS", exp_cnt)

    # Subscribe table key
    result = list(gnmi_tls.pygnmi_client.subscribe(
        counters_path + counter_key, mode=SubscribeMode.POLL,
        poll_count=exp_cnt, poll_interval=1,
        prefix=_countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "SAI_PORT_STAT_IF_IN_ERRORS", exp_cnt)
    # Subscribe table field
    result = list(gnmi_tls.pygnmi_client.subscribe(
        counters_path + counter_key + "/SAI_PORT_STAT_IF_IN_ERRORS",
        mode=SubscribeMode.POLL, poll_count=exp_cnt, poll_interval=1,
        prefix=_countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "SAI_PORT_STAT_IF_IN_ERRORS", exp_cnt)


@pytest.mark.parametrize('test_data', test_data_counters_port_name_map)
def test_gnmi_counterdb_streaming_sample_01(rand_one_dut_hostname, gnmi_tls, test_data):  # noqa: F811
    '''
    Verify GNMI subscribe API
    Subscribe streaming sample mode for COUNTERS_PORT_NAME_MAP
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    path = "COUNTERS_PORT_NAME_MAP{}".format(test_data['port'])
    result = list(gnmi_tls.pygnmi_client.subscribe(
        path, sample_interval=0,
        count=exp_cnt, collect_seconds=30,
        prefix=_countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "oid", exp_cnt)


def test_gnmi_counterdb_streaming_sample_02(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    Verify GNMI subscribe API
    Subscribe streaming sample mode for COUNTERS
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    # Get COUNTERS table key for Ethernet0
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}. "
        "Expected 'oid' in counter key"
    ).format(counter_key)

    # Subscribe table field
    path = "COUNTERS/" + counter_key + "/SAI_PORT_STAT_IF_IN_ERRORS"
    result = list(gnmi_tls.pygnmi_client.subscribe(
        path, sample_interval=0, count=exp_cnt, collect_seconds=30,
        prefix=_countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "SAI_PORT_STAT_IF_IN_ERRORS", exp_cnt)

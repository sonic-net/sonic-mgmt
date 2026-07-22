import logging
import pytest
import re
import threading

from .helper import gnmi_set, gnmi_get, gnmi_subscribe_polling_py, get_namespace
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def _gnmi_client_connected(duthost, ptfhost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    res = ptfhost.shell('netstat -tn | grep ":{} .*ESTABLISHED"'.format(env.gnmi_port),
                        module_ignore_errors=True)
    return res["rc"] == 0


def _modify_fake_appdb_table(duthost, namespace, add=True, entries=1):
    cmd_prefix = "sonic-db-cli"
    if duthost.is_multi_asic:
        cmd_prefix = "sonic-db-cli -n {}".format(namespace)
    for entry in range(entries):
        if add:
            cmd = cmd_prefix + " APPL_DB hset FAKE_APPL_DB_TABLE_{0}:fake_key{0} dummy{0} val".format(entry)
        else:
            cmd = cmd_prefix + " APPL_DB hdel FAKE_APPL_DB_TABLE_{0}:fake_key{0} dummy{0}".format(entry)
        assert duthost.shell(cmd)['rc'] == 0, "Unable to modify FAKE_APPL_DB_TABLE_{}".format(entry)


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


def test_gnmi_appldb_01(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native write with ApplDB
    Update DASH_VNET_TABLE
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "vnet.txt"
    text = "{\"Vnet1\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE:@/root/%s" % (file_name)]
    gnmi_set(duthost, ptfhost, [], update_list, [])
    # Check gnmi_get result
    path_list1 = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/localhost/_DASH_VNET_TABLE/Vnet1/vni"]
    output = None
    try:
        msg_list1 = gnmi_get(duthost, ptfhost, path_list1)
    except Exception as e:
        logger.info("Failed to read path1: " + str(e))
    else:
        output = msg_list1[0]
    try:
        msg_list2 = gnmi_get(duthost, ptfhost, path_list2)
    except Exception as e:
        logger.info("Failed to read path2: " + str(e))
    else:
        output = msg_list2[0]
    assert output == "\"1000\"", "Unexpected output: '{}'".format(output)

    # Remove DASH_VNET_TABLE
    delete_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1"]
    gnmi_set(duthost, ptfhost, delete_list, [], [])
    # Check gnmi_get result
    path_list1 = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/localhost/_DASH_VNET_TABLE/Vnet1/vni"]
    try:
        msg_list1 = gnmi_get(duthost, ptfhost, path_list1)
    except Exception as e:
        logger.info("Failed to read path1: " + str(e))
    else:
        pytest.fail("Remove DASH_VNET_TABLE failed: " + msg_list1[0])
    try:
        msg_list2 = gnmi_get(duthost, ptfhost, path_list2)
    except Exception as e:
        logger.info("Failed to read path2: " + str(e))
    else:
        pytest.fail("Remove DASH_VNET_TABLE failed: " + msg_list2[0])


def test_poll_mode_no_table_or_key(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    POLL mode from APPL_DB querying a non-existent table and key returns sync
    responses and no error. Ported from tests/telemetry test_poll_mode_no_table_or_key.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    namespace_name = get_namespace(duthost)
    path_list = ["/sonic-db:APPL_DB/{}/FAKE_APPL_DB_TABLE_0".format(namespace_name),
                 "/sonic-db:APPL_DB/{}/FAKE_APPL_DB_TABLE_1/fake_key1".format(namespace_name)]
    result = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, polling_interval=5,
                                       update_count=0, max_sync_count=5, timeout=30)
    assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
    out = str(result['stdout'])
    sync_responses = re.findall("sync_response: true", out)
    assert len(sync_responses) == 5, (
        "Expected 5 sync responses, got {}: {}".format(len(sync_responses), out))


def test_poll_mode_present_table_delayed_key(duthosts, rand_one_dut_hostname, ptfhost, enum_rand_one_asic_index):
    '''
    POLL an existing APPL_DB table returns data with no error; then re-poll while
    inserting a key mid-stream and confirm the new data appears. Ported from
    tests/telemetry test_poll_mode_present_table_delayed_key.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_ns = namespace if namespace else "localhost"
    path_list = ["/sonic-db:APPL_DB/{}/FAKE_APPL_DB_TABLE_0".format(path_ns),
                 "/sonic-db:APPL_DB/{}/FAKE_APPL_DB_TABLE_1/fake_key1".format(path_ns)]

    _modify_fake_appdb_table(duthost, namespace)  # add first table data
    result = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, polling_interval=2,
                                       update_count=5, max_sync_count=-1, timeout=30)
    assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
    updates = re.findall("json_ietf_val", str(result['stdout']))
    assert len(updates) == 5, "Expected 5 update responses, got {}".format(len(updates))

    holder = {}

    def poll_worker():
        holder['result'] = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, polling_interval=2,
                                                     update_count=20, max_sync_count=-1, timeout=60)

    client_thread = threading.Thread(target=poll_worker)
    client_thread.start()
    try:
        wait_until(5, 1, 0, _gnmi_client_connected, duthost, ptfhost)
        _modify_fake_appdb_table(duthost, namespace, add=True, entries=2)  # add second table data
        client_thread.join(60)
    finally:
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)  # remove added tables

    out = str(holder.get('result', {}).get('stdout', ''))
    assert re.findall("dummy1", out), "Missing update response for delayed key: {}".format(out)


def test_poll_mode_delete(duthosts, rand_one_dut_hostname, ptfhost, enum_rand_one_asic_index):
    '''
    POLL existing APPL_DB tables returns data with no error; then delete both
    mid-stream and confirm delete notifications. Ported from tests/telemetry
    test_poll_mode_delete.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_ns = namespace if namespace else "localhost"
    path_list = ["/sonic-db:APPL_DB/{}/FAKE_APPL_DB_TABLE_0".format(path_ns),
                 "/sonic-db:APPL_DB/{}/FAKE_APPL_DB_TABLE_1/fake_key1".format(path_ns)]

    _modify_fake_appdb_table(duthost, namespace, add=True, entries=2)  # add both tables data
    result = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, polling_interval=1,
                                       update_count=10, max_sync_count=-1, timeout=30)
    assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
    updates = re.findall("json_ietf_val", str(result['stdout']))
    assert len(updates) == 10, "Expected 10 update responses, got {}".format(len(updates))

    holder = {}

    def poll_worker():
        holder['result'] = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, polling_interval=2,
                                                     update_count=0, max_sync_count=15, timeout=60)

    client_thread = threading.Thread(target=poll_worker)
    client_thread.start()
    wait_until(5, 1, 0, _gnmi_client_connected, duthost, ptfhost)
    _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)  # delete both tables
    client_thread.join(60)

    out = str(holder.get('result', {}).get('stdout', ''))
    deletes = re.findall("delete", out)
    assert len(deletes) == 2, "Expected 2 delete responses, got {}: {}".format(len(deletes), out)

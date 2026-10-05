import logging
import pytest
import re
import threading

from .helper import gnmi_subscribe_polling_py
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.utilities import wait_until, is_ipv6_only_topology

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


def _verify_route_table_status(duthost, namespace, expected_status, is_ipv6_only):
    cmd_prefix = "sonic-db-cli"
    if duthost.is_multi_asic:
        cmd_prefix = "sonic-db-cli -n {}".format(namespace)
    if is_ipv6_only:
        cmd = cmd_prefix + " APPL_DB exists \"ROUTE_TABLE:::/0\""
    else:
        cmd = cmd_prefix + " APPL_DB exists \"ROUTE_TABLE:0.0.0.0/0\""
    return duthost.shell(cmd)["stdout"] == expected_status


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


def test_poll_mode_no_table_or_key(duthosts, rand_one_dut_hostname, ptfhost, enum_rand_one_asic_index):
    '''
    POLL mode from APPL_DB querying a non-existent table and key returns sync
    responses and no error.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]
    result = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target="APPL_DB",
                                       polling_interval=5, update_count=0, max_sync_count=5,
                                       timeout=30, namespace=namespace)
    assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
    out = str(result['stdout'])
    sync_responses = re.findall("sync_response: true", out)
    assert len(sync_responses) == 5, (
        "Expected 5 sync responses, got {}: {}".format(len(sync_responses), out))


def test_poll_mode_present_table_delayed_key(duthosts, rand_one_dut_hostname, ptfhost, enum_rand_one_asic_index):
    '''
    POLL an existing APPL_DB table returns data with no error; then re-poll while
    inserting a key mid-stream and confirm the new data appears.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]

    _modify_fake_appdb_table(duthost, namespace)  # add first table data
    result = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target="APPL_DB",
                                       polling_interval=2, update_count=5, max_sync_count=-1,
                                       timeout=30, namespace=namespace)
    assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
    updates = re.findall("json_ietf_val", str(result['stdout']))
    assert len(updates) == 5, "Expected 5 update responses, got {}".format(len(updates))

    holder = {}

    def poll_worker():
        holder['result'] = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target="APPL_DB",
                                                     polling_interval=2, update_count=20, max_sync_count=-1,
                                                     timeout=60, namespace=namespace)

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
    mid-stream and confirm delete notifications.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]

    _modify_fake_appdb_table(duthost, namespace, add=True, entries=2)  # add both tables data
    result = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target="APPL_DB",
                                       polling_interval=1, update_count=10, max_sync_count=-1,
                                       timeout=30, namespace=namespace)
    assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
    updates = re.findall("json_ietf_val", str(result['stdout']))
    assert len(updates) == 10, "Expected 10 update responses, got {}".format(len(updates))

    holder = {}

    def poll_worker():
        holder['result'] = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target="APPL_DB",
                                                     polling_interval=2, update_count=0, max_sync_count=15,
                                                     timeout=60, namespace=namespace)

    client_thread = threading.Thread(target=poll_worker)
    client_thread.start()
    wait_until(5, 1, 0, _gnmi_client_connected, duthost, ptfhost)
    _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)  # delete both tables
    client_thread.join(60)

    out = str(holder.get('result', {}).get('stdout', ''))
    deletes = re.findall("delete", out)
    assert len(deletes) == 2, "Expected 2 delete responses, got {}: {}".format(len(deletes), out)


def test_poll_mode_default_route_supervisor(duthosts, rand_one_dut_hostname, ptfhost, enum_rand_one_asic_index):
    '''
    On a supervisor node, POLL an APPL_DB table plus the default route path returns
    data with no error.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if not duthost.is_supervisor_node():
        pytest.skip("Testing only for supervisor node")
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", "ROUTE_TABLE/0.0.0.0\\/0"]
    _modify_fake_appdb_table(duthost, namespace)  # add first table data
    try:
        result = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target="APPL_DB",
                                           polling_interval=2, update_count=5, max_sync_count=-1,
                                           timeout=30, namespace=namespace)
        assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
        updates = re.findall("json_ietf_val", str(result['stdout']))
        assert len(updates) == 5, "Expected 5 update responses, got {}".format(len(updates))
    finally:
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=1)  # remove added table


def test_poll_mode_default_route(duthosts, rand_one_dut_hostname, ptfhost, enum_upstream_dut_hostname,
                                 tbinfo, enum_rand_one_asic_index):
    '''
    POLL an APPL_DB table plus the default route: with the default route removed
    (bgp shutdown) data still returns, and after adding it back (bgp startup) the
    route data appears mid-stream.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping for supervisor node since there is no default route")
    if duthosts[enum_upstream_dut_hostname] != duthost:
        pytest.skip("Skipping for {}. This is not valid for downstream node".format(duthost))

    is_ipv6_only = is_ipv6_only_topology(tbinfo)
    route = "ROUTE_TABLE/::\\/0" if is_ipv6_only else "ROUTE_TABLE/0.0.0.0\\/0"
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", route]

    _modify_fake_appdb_table(duthost, namespace)  # add first table data
    try:
        # Remove default route and wait until it is gone.
        duthost.shell("config bgp shutdown all")
        assert wait_until(60, 5, 0, _verify_route_table_status, duthost, namespace, "0", is_ipv6_only), \
            "ROUTE_TABLE default route not missing"

        result = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target="APPL_DB",
                                           polling_interval=2, update_count=5, max_sync_count=-1,
                                           timeout=30, namespace=namespace)
        assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
        updates = re.findall("json_ietf_val", str(result['stdout']))
        assert len(updates) == 5, "Expected 5 update responses, got {}".format(len(updates))

        holder = {}

        def poll_worker():
            holder['result'] = gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target="APPL_DB",
                                                         polling_interval=10, update_count=10, max_sync_count=-1,
                                                         timeout=120, namespace=namespace)

        client_thread = threading.Thread(target=poll_worker)
        client_thread.start()
        wait_until(5, 1, 0, _gnmi_client_connected, duthost, ptfhost)
        # Add the default route back.
        duthost.shell("config bgp startup all")
        assert wait_until(60, 5, 0, _verify_route_table_status, duthost, namespace, "1", is_ipv6_only), \
            "ROUTE_TABLE default route missing"
        client_thread.join(120)
        out = str(holder.get('result', {}).get('stdout', ''))
        assert re.findall("nexthop", out), "Missing update response for default route: {}".format(out)
    finally:
        duthost.shell("config bgp startup all", module_ignore_errors=True)
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=1)  # remove added table

import logging
import json
import pytest
from contextlib import closing

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.pygnmi_client import SubscribeMode, Encoding
from tests.common.utilities import wait_until, is_ipv6_only_topology

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp")
]


def _gnmi_subscribe_polling(client, path_list, target, polling_interval, update_count,
                            max_sync_count, timeout, namespace=None, on_first_batch=None):
    target += "/{}".format(namespace) if namespace else ""
    result = []
    received_updates = 0
    poll_count = max_sync_count if max_sync_count > 0 else timeout // polling_interval + 1
    original_timeout = client.timeout
    client.timeout = timeout
    try:
        with closing(client.subscribe(path_list, target=target, mode=SubscribeMode.POLL,
                                      encoding=Encoding.JSON, poll_count=poll_count,
                                      poll_interval=polling_interval)) as responses:
            for response in responses:
                result.append(response)
                if len(result) == 1 and on_first_batch is not None:
                    on_first_batch()
                received_updates += len(response.get("update", {}).get("update", []))
                if update_count and received_updates >= update_count:
                    break
    finally:
        client.timeout = original_timeout
    return result


def _verify_route_table_status(duthost, namespace, expected_status, is_ipv6_only):
    cmd_prefix = "sonic-db-cli"
    if duthost.is_multi_asic:
        cmd_prefix = "sonic-db-cli -n {}".format(namespace)
    if is_ipv6_only:
        cmd = cmd_prefix + " APPL_DB exists \"ROUTE_TABLE:::/0\""
    else:
        cmd = cmd_prefix + " APPL_DB exists \"ROUTE_TABLE:0.0.0.0/0\""
    return duthost.shell(cmd)["stdout"] == expected_status


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


def test_poll_mode_no_table_or_key(gnmi_tls, rand_one_dut_hostname, enum_rand_one_asic_index):  # noqa: F811
    '''
    POLL mode from APPL_DB querying a non-existent table and key returns sync
    responses and no error.
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]
    result = _gnmi_subscribe_polling(client, path_list, target="APPL_DB",
                                     polling_interval=5, update_count=0, max_sync_count=5,
                                     timeout=30, namespace=namespace)
    out = json.dumps(result)
    sync_responses = [response for response in result if response.get("sync_response") is True]
    assert len(sync_responses) == 5, (
        "Expected 5 sync responses, got {}: {}".format(len(sync_responses), out))


def test_poll_mode_present_table_delayed_key(gnmi_tls, rand_one_dut_hostname,  # noqa: F811
                                             enum_rand_one_asic_index):
    '''
    POLL an existing APPL_DB table returns data with no error; then re-poll while
    inserting a key mid-stream and confirm the new data appears.
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]

    _modify_fake_appdb_table(duthost, namespace)  # add first table data
    result = _gnmi_subscribe_polling(client, path_list, target="APPL_DB",
                                     polling_interval=2, update_count=5, max_sync_count=-1,
                                     timeout=30, namespace=namespace)
    updates = [update for response in result for update in response.get("update", {}).get("update", [])]
    assert len(updates) == 5, "Expected 5 update responses, got {}".format(len(updates))

    def add_delayed_key():
        _modify_fake_appdb_table(duthost, namespace, add=True, entries=2)  # add second table data

    try:
        result = _gnmi_subscribe_polling(client, path_list, target="APPL_DB",
                                         polling_interval=2, update_count=20, max_sync_count=-1,
                                         timeout=60, namespace=namespace, on_first_batch=add_delayed_key)
    finally:
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)  # remove added tables

    out = json.dumps(result)
    assert "dummy1" in out, "Missing update response for delayed key: {}".format(out)


def test_poll_mode_delete(gnmi_tls, rand_one_dut_hostname, enum_rand_one_asic_index):  # noqa: F811
    '''
    POLL existing APPL_DB tables returns data with no error; then delete both
    mid-stream and confirm delete notifications.
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]

    _modify_fake_appdb_table(duthost, namespace, add=True, entries=2)  # add both tables data
    try:
        result = _gnmi_subscribe_polling(client, path_list, target="APPL_DB",
                                         polling_interval=1, update_count=10, max_sync_count=-1,
                                         timeout=30, namespace=namespace)
        updates = [update for response in result for update in response.get("update", {}).get("update", [])]
        assert len(updates) == 10, "Expected 10 update responses, got {}".format(len(updates))

        def delete_tables():
            _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)  # delete both tables

        result = _gnmi_subscribe_polling(client, path_list, target="APPL_DB",
                                         polling_interval=2, update_count=0, max_sync_count=15,
                                         timeout=60, namespace=namespace, on_first_batch=delete_tables)
    finally:
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)
    out = json.dumps(result)
    deletes = [deleted for response in result for deleted in response.get("update", {}).get("delete", [])]
    assert len(deletes) == 2, "Expected 2 delete responses, got {}: {}".format(len(deletes), out)


def test_poll_mode_default_route_supervisor(gnmi_tls, rand_one_dut_hostname, enum_rand_one_asic_index):  # noqa: F811
    '''
    On a supervisor node, POLL an APPL_DB table plus the default route path returns
    data with no error.
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    if not duthost.is_supervisor_node():
        pytest.skip("Testing only for supervisor node")
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    path_list = ["FAKE_APPL_DB_TABLE_0", "ROUTE_TABLE/0.0.0.0\\/0"]
    _modify_fake_appdb_table(duthost, namespace)  # add first table data
    try:
        result = _gnmi_subscribe_polling(client, path_list, target="APPL_DB",
                                         polling_interval=2, update_count=5, max_sync_count=-1,
                                         timeout=30, namespace=namespace)
        updates = [update for response in result for update in response.get("update", {}).get("update", [])]
        assert len(updates) == 5, "Expected 5 update responses, got {}".format(len(updates))
    finally:
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=1)  # remove added table


def test_poll_mode_default_route(gnmi_tls, duthosts, rand_one_dut_hostname,  # noqa: F811
                                 enum_upstream_dut_hostname,
                                 tbinfo, enum_rand_one_asic_index):
    '''
    POLL an APPL_DB table plus the default route: with the default route removed
    (bgp shutdown) data still returns, and after adding it back (bgp startup) the
    route data appears mid-stream.
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
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

        result = _gnmi_subscribe_polling(client, path_list, target="APPL_DB",
                                         polling_interval=2, update_count=5, max_sync_count=-1,
                                         timeout=30, namespace=namespace)
        updates = [update for response in result for update in response.get("update", {}).get("update", [])]
        assert len(updates) == 5, "Expected 5 update responses, got {}".format(len(updates))

        def add_default_route():
            duthost.shell("config bgp startup all")
            assert wait_until(60, 5, 0, _verify_route_table_status, duthost, namespace, "1", is_ipv6_only), \
                "ROUTE_TABLE default route missing"

        result = _gnmi_subscribe_polling(client, path_list, target="APPL_DB",
                                         polling_interval=10, update_count=10, max_sync_count=-1,
                                         timeout=120, namespace=namespace, on_first_batch=add_default_route)
        out = json.dumps(result)
        assert "nexthop" in out, "Missing update response for default route: {}".format(out)
    finally:
        duthost.shell("config bgp startup all", module_ignore_errors=True)
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=1)  # remove added table

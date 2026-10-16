import logging
import json
import pytest
from contextlib import closing

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.pygnmi_client import SubscribeMode, Encoding

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp")
]


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
    '''POLL missing APPL_DB table/key paths returns sync responses without error.'''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    target = "APPL_DB/{}".format(namespace) if namespace else "APPL_DB"
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]
    result = list(client.subscribe(path_list, target=target, mode=SubscribeMode.POLL,
                                   encoding=Encoding.JSON, poll_count=5, poll_interval=5))
    out = json.dumps(result)
    sync_responses = [response for response in result if response.get("sync_response") is True]
    assert len(sync_responses) == 5, (
        "Expected 5 sync responses, got {}: {}".format(len(sync_responses), out))


def test_poll_mode_present_table_delayed_key(gnmi_tls, rand_one_dut_hostname,  # noqa: F811
                                             enum_rand_one_asic_index):
    '''POLL an existing table, then insert the missing key on the same subscription.'''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    target = "APPL_DB/{}".format(namespace) if namespace else "APPL_DB"
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]
    original_timeout = client.timeout
    _modify_fake_appdb_table(duthost, namespace)
    try:
        result = list(client.subscribe(path_list, target=target, mode=SubscribeMode.POLL,
                                       encoding=Encoding.JSON, poll_count=5, poll_interval=2))
        updates = [update for response in result for update in response.get("update", {}).get("update", [])]
        assert len(updates) == 5, "Expected 5 update responses, got {}".format(len(updates))

        client.timeout = 60
        with closing(client.subscribe(path_list, target=target, mode=SubscribeMode.POLL,
                                      encoding=Encoding.JSON, poll_count=20, poll_interval=2)) as responses:
            result = [next(responses)]
            _modify_fake_appdb_table(duthost, namespace, add=True, entries=2)
            updates = list(result[0].get("update", {}).get("update", []))
            for response in responses:
                result.append(response)
                updates.extend(response.get("update", {}).get("update", []))
                if len(updates) >= 20:
                    break
    finally:
        client.timeout = original_timeout
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)

    out = json.dumps(result)
    assert "dummy1" in out, "Missing update response for delayed key: {}".format(out)


def test_poll_mode_delete(gnmi_tls, rand_one_dut_hostname, enum_rand_one_asic_index):  # noqa: F811
    '''POLL existing APPL_DB table/key paths, then delete both and check notifications.'''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
    target = "APPL_DB/{}".format(namespace) if namespace else "APPL_DB"
    path_list = ["FAKE_APPL_DB_TABLE_0", "FAKE_APPL_DB_TABLE_1/fake_key1"]
    original_timeout = client.timeout
    _modify_fake_appdb_table(duthost, namespace, add=True, entries=2)
    try:
        result = list(client.subscribe(path_list, target=target, mode=SubscribeMode.POLL,
                                       encoding=Encoding.JSON, poll_count=5, poll_interval=1))
        updates = [update for response in result for update in response.get("update", {}).get("update", [])]
        assert len(updates) == 10, "Expected 10 update responses, got {}".format(len(updates))

        client.timeout = 60
        with closing(client.subscribe(path_list, target=target, mode=SubscribeMode.POLL,
                                      encoding=Encoding.JSON, poll_count=15, poll_interval=2)) as responses:
            result = [next(responses)]
            _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)
            result.extend(responses)
    finally:
        client.timeout = original_timeout
        _modify_fake_appdb_table(duthost, namespace, add=False, entries=2)
    out = json.dumps(result)
    deletes = [deleted for response in result for deleted in response.get("update", {}).get("delete", [])]
    assert len(deletes) == 2, "Expected 2 delete responses, got {}: {}".format(len(deletes), out)

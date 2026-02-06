import logging
import pytest
import re
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from telemetry_utils import generate_client_cli, check_gnmi_cli_running, invoke_py_cli_from_ptf
from tests.common.utilities import InterruptableThread

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

METHOD_SUBSCRIBE = "subscribe"
SUBSCRIBE_MODE_POLL = 2


def verify_route_table_status(duthost, namespace, expected_status="1"):  # status 0 for down, 1 for up
    cmd_prefix = "sonic-db-cli"
    if duthost.is_multi_asic:
        cmd_prefix = "sonic-db-cli -n {}".format(namespace)
    cmd = cmd_prefix + " APPL_DB exists \"ROUTE_TABLE:0.0.0.0/0\""
    status = duthost.shell(cmd)["stdout"]
    return status == expected_status


def modify_fake_appdb_table(duthost, add=True, entries=1):
    cmd_prefix = "sonic-db-cli"
    if duthost.is_multi_asic:
        cmd_prefix = "sonic-db-cli -n asic0"
    for entry in range(entries):
        command = cmd_prefix + " APPL_DB {} FAKE_APPL_DB_TABLE_{}:fake_key{} {}"
        if add:
            command = command.format("hset", entry, entry, "dummy{} val".format(entry))
        else:
            command = command.format("hdel", entry, entry, "dummy{}".format(entry))
        pytest_assert(duthost.shell(command)['rc'] == 0, "Unable to modify FAKE_APPL_DB_TABLE{}".format(entry))


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_poll_mode_no_table_or_key(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                                   setup_streaming_telemetry, gnxi_path):
    """
    Test poll mode from APPL_DB and query a non existing table and key, ensure no errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info('Start telemetry poll mode testing')
    namespace = ""
    if duthost.is_multi_asic:
        namespace = "asic0"
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=5,
                              xpath="FAKE_APPL_DB_TABLE_0 FAKE_APPL_DB_TABLE_1/fake_key1", target="APPL_DB",
                              max_sync_count=5, update_count=0, timeout=30, namespace=namespace)
    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
    show_gnmi_out = ptf_result['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    sync_responses_match = re.findall("sync_response: true", result)
    pytest_assert(len(sync_responses_match) == 5, "Missing sync responses")


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_poll_mode_present_table_delayed_key(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                                             setup_streaming_telemetry, gnxi_path):
    """
    Test poll mode from APPL_DB and query an existing table and missing key, ensure no errors and present data
    After that, begin querying again and put the key and ensure no errors and new data
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info('Start telemetry poll mode testing')
    namespace = ""
    if duthost.is_multi_asic:
        namespace = "asic0"
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=2,
                              xpath="FAKE_APPL_DB_TABLE_0 FAKE_APPL_DB_TABLE_1/fake_key1", target="APPL_DB",
                              max_sync_count=-1, update_count=5, timeout=30, namespace=namespace)
    modify_fake_appdb_table(duthost)  # Add first table data
    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
    show_gnmi_out = ptf_result['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    update_responses_match = re.findall("json_ietf_val", result)
    pytest_assert(len(update_responses_match) == 5, "Missing update responses")

    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=1,
                              xpath="FAKE_APPL_DB_TABLE_0 FAKE_APPL_DB_TABLE_1/fake_key1", target="APPL_DB",
                              max_sync_count=-1, update_count=10, timeout=30, namespace=namespace)

    def callback(show_gnmi_out):
        result = str(show_gnmi_out)
        logger.info(result)
        update_responses_match = re.findall("dummy1", result)
        assert len(update_responses_match) != 0, "Missing update response"

    client_thread = InterruptableThread(target=invoke_py_cli_from_ptf, args=(ptfhost, cmd, callback,))
    client_thread.start()

    wait_until(5, 1, 0, check_gnmi_cli_running, duthost, ptfhost)

    modify_fake_appdb_table(duthost, True, 2)  # Add second table data
    client_thread.join(30)

    modify_fake_appdb_table(duthost, False, 2)  # Remove all added tables


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_poll_mode_delete(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                          setup_streaming_telemetry, gnxi_path):
    """
    Test poll mode from APPL_DB and query an existing table and key, ensure no errors and present data
    After that, delete both and ensure no errors and delete notifications
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info('Start telemetry poll mode testing')
    namespace = ""
    if duthost.is_multi_asic:
        namespace = "asic0"
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=1,
                              xpath="FAKE_APPL_DB_TABLE_0 FAKE_APPL_DB_TABLE_1/fake_key1", target="APPL_DB",
                              max_sync_count=-1, update_count=10, timeout=30, namespace=namespace)
    modify_fake_appdb_table(duthost, True, 2)  # Add both tables data
    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
    show_gnmi_out = ptf_result['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    update_responses_match = re.findall("json_ietf_val", result)
    pytest_assert(len(update_responses_match) == 10, "Missing update responses")

    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=2,
                              xpath="FAKE_APPL_DB_TABLE_0 FAKE_APPL_DB_TABLE_1/fake_key1", target="APPL_DB",
                              max_sync_count=6, update_count=0, timeout=30, namespace=namespace)

    def callback(show_gnmi_out):
        result = str(show_gnmi_out)
        update_responses_match = re.findall("delete", result)
        logger.info(result)
        assert len(update_responses_match) == 2, "No delete responses"

    client_thread = InterruptableThread(target=invoke_py_cli_from_ptf, args=(ptfhost, cmd, callback,))
    client_thread.start()

    wait_until(5, 1, 0, check_gnmi_cli_running, duthost, ptfhost)

    modify_fake_appdb_table(duthost, False, 2)  # Remove all added tables
    client_thread.join(30)


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_poll_mode_default_route(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, enum_upstream_dut_hostname,
                                 setup_streaming_telemetry, gnxi_path):
    """
    Test poll mode from APPL_DB and query an existing table and no default route, ensure no errors and present data
    Test query again and add default route and ensure data comes.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    upstream_lc = duthosts[enum_upstream_dut_hostname]

    if duthost.is_supervisor_node():
        pytest.skip("Skipping for supervisor node since there is no default route")

    if upstream_lc != duthost:
        pytest.skip("Skipping for {}. This is not valid for downstream node".format(duthost))

    namespace = ""
    if duthost.is_multi_asic:
        namespace = "asic0"
    logger.info('Start telemetry poll mode testing')
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=2,
                              xpath="\"FAKE_APPL_DB_TABLE_0\" \"ROUTE_TABLE/0.0.0.0\/0\"",  # noqa: W605
                              target="APPL_DB", max_sync_count=-1, update_count=5, timeout=30, namespace=namespace)
    modify_fake_appdb_table(duthost)  # Add first table data

    # Remove default route and wait till there is no entry
    duthost.shell("config bgp shutdown all")
    pytest_assert(wait_until(60, 5, 0, verify_route_table_status, duthost, namespace, "0"),
                  "ROUTE_TABLE default route not missing")

    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
    show_gnmi_out = ptf_result['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    update_responses_match = re.findall("json_ietf_val", result)
    pytest_assert(len(update_responses_match) == 5, "Missing update responses")

    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=10,
                              xpath="\"FAKE_APPL_DB_TABLE_0\" \"ROUTE_TABLE/0.0.0.0\/0\"",  # noqa: W605
                              target="APPL_DB", max_sync_count=-1, update_count=10, timeout=120, namespace=namespace)

    def callback(show_gnmi_out):
        result = str(show_gnmi_out)
        logger.info(result)
        update_responses_match = re.findall("nexthop", result)
        assert len(update_responses_match) != 0, "Missing update response"

    client_thread = InterruptableThread(target=invoke_py_cli_from_ptf, args=(ptfhost, cmd, callback,))
    client_thread.start()

    wait_until(5, 1, 0, check_gnmi_cli_running, duthost, ptfhost)

    # Add back default route
    duthost.shell("config bgp startup all")
    pytest_assert(wait_until(60, 5, 0, verify_route_table_status, duthost, namespace, "1"),
                  "ROUTE_TABLE default route missing")

    # Give 60 seconds for client to connect to server and then 60 for default route to populate after bgp session start
    client_thread.join(120)

    modify_fake_appdb_table(duthost, False, 1)  # Remove all added tables


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_poll_mode_default_route_supervisor(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                                            setup_streaming_telemetry, gnxi_path):
    """
    Test poll mode from APPL_DB and query an existing table and no default route, ensure no errors and present data
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_supervisor_node():
        pytest.skip("Testing only for supervisor node")
    logger.info('Start telemetry poll mode testing')
    namespace = ""
    if duthost.is_multi_asic:
        namespace = "asic0"
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=2,
                              xpath="\"FAKE_APPL_DB_TABLE_0\" \"ROUTE_TABLE/0.0.0.0\/0\"",  # noqa: W605
                              target="APPL_DB", max_sync_count=-1, update_count=5, timeout=30, namespace=namespace)
    modify_fake_appdb_table(duthost)  # Add first table data
    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
    show_gnmi_out = ptf_result['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    update_responses_match = re.findall("json_ietf_val", result)
    pytest_assert(len(update_responses_match) == 5, "Missing update responses")
    modify_fake_appdb_table(duthost, False, 1)  # Remove added table

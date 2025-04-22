import threading
import logging
import pytest
import re
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from telemetry_utils import generate_client_cli, check_gnmi_cli_running
from tests.common.helpers.gnmi_utils import GNMIEnvironment


pytestmark = [
    pytest.mark.topology('any')
]


logger = logging.getLogger(__name__)


def invoke_py_cli_from_ptf(ptfhost, cmd, callback):
    ret = ptfhost.shell(cmd)
    assert ret["rc"] == 0, "PTF docker did not get a response"
    callback(ret["stdout"])


def modify_fake_appdb_table(duthost, is_multi_asic=False, add=True, entries=1):
    cmd_prefix = "sonic-db-cli"
    if is_multi_asic:
        cmd_prefix = "sonic-db-cli -n asic0"
    for entry in range(entries):
        command = cmd_prefix + "APPL_DB {} FAKE_APPL_DB_TABLE{}:fake_key{} {}"
        if add:
            command.format("hset", entry, entry, "dummy val")
        else:
            command.format("hdel", entry, entry "dummy")
        pytest_assert(duthost.shell(command)['rc'] == 0, "Unable to modify FAKE_APPL_DB_TABLE{}".format(entry))


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_poll_mode_no_table_or_key(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                                   setup_streaming_telemetry, gnxi_path):
    """
    Test poll mode from APPL_DB and query a non existing table and key, ensure no errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    logger.info('Start telemetry poll mode testing')
    dut_ip = duthost.mgmt_ip
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=5,
                              xpath="FAKE_APPL_DB_TABLE FAKE_APPL_DB_TABLE_2/fake_key", target="APPL_DB", sync_count=5,
                              update_count=0, timeout=30)
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
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    logger.info('Start telemetry poll mode testing')
    dut_ip = duthost.mgmt_ip
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=5,
                              xpath="FAKE_APPL_DB_TABLE FAKE_APPL_DB_TABLE_2/fake_key", target="APPL_DB", sync_count=5,
                              update_count=0, timeout=30)
    modify_fake_appdb_table(duthost)
    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
    show_gnmi_out = ptf_result['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    sync_responses_match = re.findall("sync_response: true", result)
    pytest_assert(len(sync_responses_match) == 5, "Missing sync responses")
    update_responses_match = re.findall("json_ietf_val", result)
    pytest_assert(len(update_responses_match) == 5, "Missing update responses")

    def callback(show_gnmi_out):
        result = str(show_gnmi_out)
        update_responses_match = re.findall("dummy2", result)
        pytest_assert(len(update_responses_match) != 0, "Missing update response")

    client_thread = threading.Thread(target=invoke_py_cli_from_ptf, args=(ptfhost, cmd, callback,))
    client_thread.start()

    wait_until(5, 1, 0, check_gnmi_cli_running, ptfhost)

    modify_fake_appdb_table(duthost, False, True, 2)
    client_thread.join(30)

    modify_fake_appdb_table(duthost, False, False, 2)


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_poll_mode_delete(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                          setup_streaming_telemetry, gnxi_path):
    """
    Test poll mode from APPL_DB and query an existing table and key, ensure no errors and present data
    After that, delete both and ensure no errors and delete notifications
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    logger.info('Start telemetry poll mode testing')
    dut_ip = duthost.mgmt_ip
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=5,
                              xpath="FAKE_APPL_DB_TABLE FAKE_APPL_DB_TABLE_2/fake_key", target="APPL_DB", sync_count=5,
                              update_count=0, timeout=30)
    modify_fake_appdb_table(duthost)
    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
    show_gnmi_out = ptf_result['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    sync_responses_match = re.findall("sync_response: true", result)
    pytest_assert(len(sync_responses_match) == 5, "Missing sync responses")
    update_responses_match = re.findall("json_ietf_val", result)
    pytest_assert(len(update_responses_match) == 10, "Missing update responses")

    def callback(show_gnmi_out):
        result = str(show_gnmi_out)
        update_responses_match = re.findall("delete", result)
        pytest_assert(len(update_responses_match) != 2, "Missing delete response")

    client_thread = threading.Thread(target=invoke_py_cli_from_ptf, args=(ptfhost, cmd, callback,))
    client_thread.start()

    wait_until(5, 1, 0, check_gnmi_cli_running, ptfhost)

    modify_fake_appdb_table(duthost, False, False, 2)
    client_thread.join(30)

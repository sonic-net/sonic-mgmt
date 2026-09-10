import logging
import pytest
import re
import threading

from .helper import gnmi_subscribe_polling_py
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


def _gnmi_client_connected(duthost, ptfhost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    res = ptfhost.shell('netstat -tn | grep ":{} .*ESTABLISHED"'.format(env.gnmi_port),
                        module_ignore_errors=True)
    return res["rc"] == 0


def _srv6_namespace(duthost):
    return "asic0" if duthost.is_multi_asic else None


def _sonic_db_cli(duthost):
    return "sonic-db-cli" + (" -n asic0" if duthost.is_multi_asic else "")


def _check_srv6_stats(duthost):
    return len(duthost.shell("show srv6 stats")["stdout_lines"]) > 2


@pytest.fixture()
def setup_my_sid(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    cli = _sonic_db_cli(duthost)
    duthost.command(cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1:: func_len 0")
    duthost.command(cli + " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")
    yield
    duthost.command(cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")


def test_poll_mode_srv6_sid_counters(duthosts, rand_one_dut_hostname, ptfhost, setup_my_sid):
    '''
    POLL COUNTERS_DB for SRv6 MY_SID counters: query before data exists (no error),
    then enable counter polling and confirm counter data arrives.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ns = _srv6_namespace(duthost)
    result = gnmi_subscribe_polling_py(duthost, ptfhost, ["COUNTERS/SID:*"], target="COUNTERS_DB",
                                       polling_interval=2, update_count=5, max_sync_count=-1,
                                       timeout=30, namespace=ns)
    assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
    assert re.findall("json_ietf_val", str(result['stdout'])), "Incorrect update responses"

    duthost.shell("counterpoll srv6 enable")
    wait_until(30, 1, 5, _check_srv6_stats, duthost)

    holder = {}

    def poll_worker():
        holder['result'] = gnmi_subscribe_polling_py(duthost, ptfhost, ["COUNTERS/SID:*"], target="COUNTERS_DB",
                                                     polling_interval=10, update_count=10, max_sync_count=-1,
                                                     timeout=120, namespace=ns)

    client_thread = threading.Thread(target=poll_worker)
    client_thread.start()
    try:
        wait_until(5, 1, 0, _gnmi_client_connected, duthost, ptfhost)
        client_thread.join(120)
        out = str(holder.get('result', {}).get('stdout', ''))
        assert re.findall("SAI_COUNTER_STAT_PACKETS", out), "Missing update responses: {}".format(out)
    finally:
        duthost.shell("counterpoll srv6 disable")


def test_poll_mode_srv6_sid_counters_with_mock_data(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    POLL COUNTERS_DB for SRv6 MY_SID counters using injected mock COUNTERS data.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ns = _srv6_namespace(duthost)
    result = gnmi_subscribe_polling_py(duthost, ptfhost, ["COUNTERS/SID:*"], target="COUNTERS_DB",
                                       polling_interval=2, update_count=5, max_sync_count=-1,
                                       timeout=30, namespace=ns)
    assert result['rc'] == 0, "ptf poll command failed: {}".format(result)
    assert re.findall("json_ietf_val", str(result['stdout'])), "Incorrect update responses"

    cli = _sonic_db_cli(duthost)
    duthost.shell(cli + " COUNTERS_DB HSET \"COUNTERS:oid:0x11110000001eb3\" "
                        "SAI_COUNTER_STAT_PACKETS 10 SAI_COUNTER_STAT_BYTES 40960")
    duthost.shell(cli + " COUNTERS_DB HSET \"COUNTERS_SRV6_NAME_MAP\" "
                        "\"fcbb:bbbb:1::/48\" \"oid:0x11110000001eb3\"")

    holder = {}

    def poll_worker():
        holder['result'] = gnmi_subscribe_polling_py(duthost, ptfhost, ["COUNTERS/SID:*"], target="COUNTERS_DB",
                                                     polling_interval=10, update_count=10, max_sync_count=-1,
                                                     timeout=120, namespace=ns)

    client_thread = threading.Thread(target=poll_worker)
    client_thread.start()
    try:
        wait_until(5, 1, 0, _gnmi_client_connected, duthost, ptfhost)
        client_thread.join(120)
        out = str(holder.get('result', {}).get('stdout', ''))
        assert re.findall("SAI_COUNTER_STAT_PACKETS", out), "Missing update responses: {}".format(out)
    finally:
        duthost.shell(cli + " COUNTERS_DB DEL \"COUNTERS:oid:0x11110000001eb3\"")
        duthost.shell(cli + " COUNTERS_DB HDEL \"COUNTERS_SRV6_NAME_MAP\" \"fcbb:bbbb:1::/48\"")

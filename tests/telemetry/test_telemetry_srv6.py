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


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_poll_mode_srv6_sid_counters(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                                     setup_streaming_telemetry, gnxi_path):
    """
    Test poll mode from COUNTERS_DB and query SRv6 MY_SID counters:
    First, query when the data does not exist,ensure no errors and present data
    Second, add data and then test query again ensuring data comes.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    namespace = ""
    if duthost.is_multi_asic:
        namespace = "asic0"
    logger.info('Start telemetry poll mode testing')
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=2,
                              xpath="\"COUNTERS/SID:*\"",  # noqa: W605
                              target="COUNTERS_DB", max_sync_count=-1, update_count=5, timeout=30, namespace=namespace)

    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
    show_gnmi_out = ptf_result['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    update_responses_match = re.findall("json_ietf_val", result)
    pytest_assert(len(update_responses_match) > 0, "Incorrect update responses")

    if namespace != "":
        SONIC_DB_CLI = f"sonic-db-cli -n {namespace}"
    else:
        SONIC_DB_CLI = "sonic-db-cli"
    # Now generate some SRv6 SID counter values by adding mock data
    duthost.shell(f"{SONIC_DB_CLI} COUNTERS_DB HSET \"COUNTERS:oid:0x11110000001eb3\" SAI_COUNTER_STAT_PACKETS 10 \
                  SAI_COUNTER_STAT_BYTES 40960")
    duthost.shell(f"{SONIC_DB_CLI} COUNTERS_DB HSET \"COUNTERS_SRV6_NAME_MAP\" \"fcbb:bbbb:1::/48\" \
                  \"oid:0x11110000001eb3\"")

    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              subscribe_mode=SUBSCRIBE_MODE_POLL, polling_interval=10,
                              xpath="\"COUNTERS/SID:*\"",  # noqa: W605
                              target="COUNTERS_DB", max_sync_count=-1, update_count=10,
                              timeout=120, namespace=namespace)

    def callback(show_gnmi_out):
        result = str(show_gnmi_out)
        logger.info(result)
        update_responses_match = re.findall("SAI_COUNTER_STAT_PACKETS", result)
        pytest_assert(len(update_responses_match) > 0, "Missing update responses")

    client_thread = InterruptableThread(target=invoke_py_cli_from_ptf, args=(ptfhost, cmd, callback,))
    client_thread.start()

    wait_until(5, 1, 0, check_gnmi_cli_running, duthost, ptfhost)

    # Give 60 seconds for client to connect to server and then 60 for default route to populate after bgp session start
    client_thread.join(120)

    duthost.shell(f"{SONIC_DB_CLI} COUNTERS_DB DEL \"COUNTERS:oid:0x11110000001eb3\"")
    duthost.shell(f"{SONIC_DB_CLI} COUNTERS_DB HDEL \"COUNTERS_SRV6_NAME_MAP\" \"fcbb:bbbb:1::/48\"")

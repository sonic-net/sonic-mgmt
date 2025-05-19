import logging
import pytest

from tests.common.utilities import event_publish_tool
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.helpers.telemetry_helper import setup_streaming_telemetry_context


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


MAX_PUBLISH_CYCLES = 5
MAX_READ_WRITE_CYCLES = 10
MAX_READ_CYCLES = 2


def skip_eventd_on_multi_asic_slim(duthost):
    if duthost.is_multi_asic:
        pytest.skip("Skip eventd on multi-asic")
    features_dict, succeeded = duthost.get_feature_status()
    if succeeded and ('eventd' not in features_dict or features_dict['eventd'] == 'disabled'):
        pytest.skip("eventd is disabled on the system")


def is_eventd_running(duthost):
    return "RUNNING" in duthost.shell("docker exec eventd supervisorctl status eventd",
                                      module_ignore_errors=True)["stdout"]


def restart_eventd(duthost):
    logger.info("Restarting eventd to ensure clean slate")
    duthost.shell("systemctl reset-failed eventd")
    duthost.shell("docker stop eventd")
    duthost.shell("docker start eventd")
    pytest_assert(wait_until(120, 10, 0, is_eventd_running, duthost), "eventd not running")
    logger.info("eventd is fully restarted")


def get_eventd_mem_usage(duthost):
    pid_command = "pidof /usr/bin/eventd"
    pid_output = duthost.shell(pid_command)["stdout"]
    if not pid_output:
        pytest.fail("Failed to get the PID of eventd")
    pid = pid_output.strip()
    mem_command = "cat /proc/{}/status | grep -i vmrss | awk '{{print $2}}'".format(pid)
    mem_output = duthost.shell(mem_command)["stdout"]
    if not mem_output:
        pytest.fail("Failed to get the memory usage of eventd")
    mem_usage = int(mem_output.strip()) / 1024  # convert from KB to MB
    logging.info("eventd PID {}, MEM USAGE:{} MB".format(pid, mem_usage))
    return mem_usage


def invoke_multi_publish_tool(duthost):
    duthost.copy(src="eventd/multi_source_publisher.py", dest="/tmp")
    duthost.shell("chmod +x /tmp/multi_source_publisher.py")
    duthost.shell("python3 /tmp/multi_source_publisher.py")


def mass_publish_events(duthost):
    logger.info("Publishing 300K events")
    # Publish max cache events ~300K
    event_publish_tool(duthost, "", 150000)
    # Publish max overflow cache events
    invoke_multi_publish_tool(duthost)


def read_events(duthost, localhost, ptfhost, gnxi_path):
    with setup_streaming_telemetry_context(False, duthost, localhost, ptfhost, gnxi_path):
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
        dut_ip = duthost.mgmt_ip
        cmd = 'python ' + gnxi_path + 'gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m subscribe -x all[heartbeat=2] -xt \
              EVENTS -o "ndastreamingservertest" --subscribe_mode 0 --submode 1 \
              --update_count 30'.format(dut_ip, env.gnmi_port)
        ret = ptfhost.shell(cmd)["rc"]
        pytest_assert(ret == 0, "gnmi client call to EVENTS fails")


def test_eventd_mem_utilization_no_connections(duthosts, enum_rand_one_per_hwsku_hostname):
    logger.info("Beginning eventd mem utilization test with no connections")
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_eventd_on_multi_asic_slim(duthost)

    restart_eventd(duthost)

    # Grab initial mem_usage

    initial_mem_usage = get_eventd_mem_usage(duthost)

    # Repeat max cach events and max overflow cache events publishing 5 times
    # Ensure difference after and before is less than 100 MB

    for _ in range(MAX_PUBLISH_CYCLES):
        mass_publish_events(duthost)
        mem_usage = get_eventd_mem_usage(duthost)
        diff_mem_usage = mem_usage - initial_mem_usage
        pytest_assert(diff_mem_usage <= 100, "Mem usage grows more than expected")
        # With all cache full, no more than 100 MB should be added to RSS


def test_eventd_mem_utilization_connections(duthosts, enum_rand_one_per_hwsku_hostname, localhost, ptfhost, gnxi_path):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_eventd_on_multi_asic_slim(duthost)

    restart_eventd(duthost)

    # Grab initial mem_usage

    initial_mem_usage = get_eventd_mem_usage(duthost)

    # Repeat max cach events and max overflow cache events publishing 5 times, then read
    # Ensure difference after and before each read/write is less than 25 MB for all cycles

    for _ in range(MAX_READ_WRITE_CYCLES):
        mass_publish_events(duthost)
        # Read multiple times
        for _ in range(MAX_READ_CYCLES):
            read_events(duthost, localhost, ptfhost, gnxi_path)
        mem_usage = get_eventd_mem_usage(duthost)
        diff_mem_usage = mem_usage - initial_mem_usage
        pytest_assert(diff_mem_usage <= 25, "Mem usage grows more than expected")

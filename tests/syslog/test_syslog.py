import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any")
]

DUT_PCAP_FILEPATH = "/tmp/test_syslog_tcpdump.pcap"
DOCKER_TMP_PATH = "/tmp/"

# Check pcap file for the destination IPs
def _check_pcap(dummy_ip_a, dummy_ip_b, filepath):
    is_ok_a = False
    is_ok_b = False

    if dummy_ip_a is None:
        is_ok_a = True
    if dummy_ip_b is None:
        is_ok_b = True

    packets = rdpcap(filepath)
    for data in packets:
        proto = "IPv6" if "IPv6" in data else "IP"
        if is_ok_a is False and data[proto].dst == dummy_ip_a:
            is_ok_a = True
        if is_ok_b is False and data[proto].dst == dummy_ip_b:
            is_ok_b = True
        if is_ok_a and is_ok_b:
            return True

    return False

@pytest.mark.parametrize("dummy_syslog_server_ip_a, dummy_syslog_server_ip_b", [("10.0.80.166", None), ("fd82:b34f:cc99::100", None), ("10.0.80.165", "10.0.80.166"), ("fd82:b34f:cc99::100", "10.0.80.166"), ("fd82:b34f:cc99::100", "fd82:b34f:cc99::200")])
def test_syslog(duthosts, enum_rand_one_per_hwsku_frontend_hostname, dummy_syslog_server_ip_a, dummy_syslog_server_ip_b):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info("Starting syslog tests")
    test_message = "Basic Test Message"

    logger.info("Configuring the DUT")
    # Add dummy rsyslog destination for testing
    if dummy_syslog_server_ip_a is not None:
        duthost.shell("sudo config syslog add {}".format(dummy_syslog_server_ip_a))
        logger.debug("Added new rsyslog server IP {}".format(dummy_syslog_server_ip_a))
    if dummy_syslog_server_ip_b is not None:
        duthost.shell("sudo config syslog add {}".format(dummy_syslog_server_ip_b))
        logger.debug("Added new rsyslog server IP {}".format(dummy_syslog_server_ip_b))

    logger.info("Start tcpdump")
    tcpdump_task, tcpdump_result = duthost.shell("sudo timeout 20 tcpdump -i any -s0 -A -w {} \"udp and port 514\"".format(DUT_PCAP_FILEPATH), module_async=True)
    # wait for starting tcpdump
    time.sleep(5)

    logger.debug("Generating log message from DUT")
    # Generate a syslog from the DUT
    duthost.shell("logger --priority INFO {}".format(test_message))

    # wait for stoping tcpdump 
    tcpdump_task.close()
    tcpdump_task.join()

    # Remove the syslog configuration
    if dummy_syslog_server_ip_a is not None:
        duthost.shell("sudo config syslog del {}".format(dummy_syslog_server_ip_a))
    if dummy_syslog_server_ip_b is not None:
        duthost.shell("sudo config syslog del {}".format(dummy_syslog_server_ip_b))

    duthost.fetch(src=DUT_PCAP_FILEPATH, dest=DOCKER_TMP_PATH)
    filepath = os.path.join(DOCKER_TMP_PATH, duthost.hostname, DUT_PCAP_FILEPATH.lstrip(os.path.sep))

    pytest_assert(_check_pcap(dummy_syslog_server_ip_a, dummy_syslog_server_ip_b, filepath),
                  "Dummy syslog server IP not seen in the pcap file")
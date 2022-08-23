import logging
import pytest
import os
import time

from scapy.all import rdpcap

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any")
]

DUT_PCAP_FILEPATH = "/tmp/test_syslog_tcpdump.pcap"
DOCKER_TMP_PATH = "/tmp/"

# If any dummy IP type doesn't have a matching default route, skip test for this parametrize
def check_dummy_addr_and_default_route(dummy_ip_a, dummy_ip_b, has_v4_default_route, has_v6_default_route):
    skip_v4 = False
    skip_v6 = False

    if dummy_ip_a is not None and ":" not in dummy_ip_a and not has_v4_default_route:
        skip_v4 = True
    if dummy_ip_a is not None and ":" in dummy_ip_a and not has_v6_default_route:
        skip_v6 = True

    if dummy_ip_b is not None and ":" not in dummy_ip_b and not has_v4_default_route:
        skip_v4 = True
    if dummy_ip_b is not None and ":" in dummy_ip_b and not has_v6_default_route:
        skip_v6 = True

    if skip_v4 | skip_v6:
        proto = "IPv4" if skip_v4 else "IPv6"
        pytest.skip("DUT has no matching default route for dummy syslog ips: ({}, {}), has no {} default route".format(dummy_ip_a, dummy_ip_b, proto))

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

    missed_ip = []
    if not is_ok_a:
        missed_ip.append(dummy_ip_a)
    if not is_ok_b:
        missed_ip.append(dummy_ip_b)
    logger.error("Pcap file doesn't contain dummy syslog ips: ({})".format(", ".join(missed_ip)))
    return False

# Before real test, check default route on DUT:
#     If DUT has no IPv4 and IPv6 default route, skip syslog test. If DUT has at least one type default route, tell test_syslog function to do further check
@pytest.fixture(scope="module")
def check_default_route(rand_selected_dut):
    duthost = rand_selected_dut
    ret = {'IPv4': False, 'IPv6': False}

    logger.info("Checking DUT default route")
    result = duthost.shell("ip route show default | grep via", module_ignore_errors=True)['rc']
    if result == 0:
        ret['IPv4'] = True
    result = duthost.shell("ip -6 route show default | grep via", module_ignore_errors=True)['rc']
    if result == 0:
        ret['IPv6'] = True

    if not ret['IPv4'] and not ret['IPv6']:
        pytest.skip("DUT has no default route, skiped")

    yield ret

@pytest.mark.parametrize("dummy_syslog_server_ip_a, dummy_syslog_server_ip_b", [("7.0.80.166", None), ("fd82:b34f:cc99::100", None), ("7.0.80.165", "7.0.80.166"), ("fd82:b34f:cc99::100", "7.0.80.166"), ("fd82:b34f:cc99::100", "fd82:b34f:cc99::200")])
def test_syslog(rand_selected_dut, dummy_syslog_server_ip_a, dummy_syslog_server_ip_b, check_default_route):
    duthost = rand_selected_dut
    logger.info("Starting syslog tests")
    test_message = "Basic Test Message"

    check_dummy_addr_and_default_route(dummy_syslog_server_ip_a, dummy_syslog_server_ip_b, check_default_route['IPv4'], check_default_route['IPv6'])

    logger.info("Configuring the DUT")
    # Add dummy rsyslog destination for testing
    if dummy_syslog_server_ip_a is not None:
        if "201911" in duthost.os_version and ":" in dummy_syslog_server_ip_a:
            pytest.skip("IPv6 syslog server IP not supported on 201911")
        duthost.shell("sudo config syslog add {}".format(dummy_syslog_server_ip_a))
        logger.debug("Added new rsyslog server IP {}".format(dummy_syslog_server_ip_a))
    if dummy_syslog_server_ip_b is not None:
        if "201911" in duthost.os_version and ":" in dummy_syslog_server_ip_b:
            pytest.skip("IPv6 syslog server IP not supported on 201911")
        duthost.shell("sudo config syslog add {}".format(dummy_syslog_server_ip_b))
        logger.debug("Added new rsyslog server IP {}".format(dummy_syslog_server_ip_b))

    logger.info("Start tcpdump")
    # Make sure that the DUT_PCAP_FILEPATH dose not exist
    duthost.shell("sudo rm -f {}".format(DUT_PCAP_FILEPATH))
    # Scapy doesn't support LINUX_SLL2 (Linux cooked v2), and tcpdump on Bullseye
    # defaults to writing in that format when listening on any interface. Therefore,
    # have it use LINUX_SLL (Linux cooked) instead.
    tcpdump_task, tcpdump_result = duthost.shell("sudo timeout 20 tcpdump -y LINUX_SLL -i any -s0 -A -w {} \"udp and port 514\"".format(DUT_PCAP_FILEPATH), module_async=True)
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

    if not _check_pcap(dummy_syslog_server_ip_a, dummy_syslog_server_ip_b, filepath):
        default_route_v4 = duthost.shell("ip route show default")['stdout']
        logger.debug("DUT's IPv4 default route:\n%s" % default_route_v4)
        default_route_v6 = duthost.shell("ip -6 route show default")['stdout']
        logger.debug("DUT's IPv6 default route:\n%s" % default_route_v6)
        syslog_config = duthost.shell("grep 'remote syslog server' -A 7 /etc/rsyslog.conf")['stdout']
        logger.debug("DUT's syslog server IPs:\n%s" % syslog_config)

        pytest.fail("Dummy syslog server IP not seen in the pcap file")

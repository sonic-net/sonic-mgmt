"""
Tests for the `show platform npu...` commands in SONiC
"""
import time
import logging
import os
import pytest

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
from tests.common.utilities import wait_until

from tests.common.helpers.assertions import pytest_assert
from tests.drop_packets.drop_packets import setup, tx_dut_ports, pkt_fields, ports_info, log_pkt_params
from tests.drop_packets.test_drop_counters import do_test
from tests.cisco.common.utils import CheckEnvironment

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


@pytest.fixture(scope='module')
def enable_debug_shell(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if duthost.facts["asic_type"] == "cisco-8000":
        def get_packet_debug_status():
            pkt_debug_status = duthost.shell("sudo show platform npu packet-debug status")["stdout_lines"]
            return pkt_debug_status
        original_dshell_status = duthost.shell("docker exec syncd supervisorctl status dshell_client | \
                                                grep \"dshell_client.*RUNNING\"",
                                               module_ignore_errors=True)["stdout_lines"]
        if 'RUNNING' not in original_dshell_status:
            debug_shell_enable = duthost.command("sudo config platform cisco sdk-debug enable")
            logging.info(debug_shell_enable)
            is_debug_shell_enabled = lambda: get_packet_debug_status() is not None
            wait_until(360, 5, 0, is_debug_shell_enabled)
        yield
        if 'RUNNING' not in original_dshell_status:
            debug_shell_disable = duthost.command("sudo config platform cisco sdk-debug disable")
            logging.info(debug_shell_disable)


def test_packet_capture(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enable_debug_shell,
                        do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Verify output of `sudo config platform cisco packet-debug drops enable -n asic0`
    """
    # 1. Enable packet-debug drops capture
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if CheckEnvironment.is_sim(duthost):
        pytest.skip("Test not supported in SIM environment")
    result = duthost.command("sudo config platform cisco packet-debug drops enable")
    logging.info(result)
    time.sleep(10)
    assert "Packet capture enabled" in result["stdout"], "CLI output missing/not correct"

    # 2. Dump and clear packet-debug capture buffer
    result = duthost.command("show platform npu packet-debug capture -c")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu trap"
    assert "Capture buffer is cleared" in result["stdout"], "CLI output missing/not correct"

    # 3. Check that buffer is empty
    result = duthost.command("show platform npu packet-debug capture -d")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu trap"
    assert "Buffer is empty" in result["stdout"], "CLI output missing/not correct"

    # 4. Send traffic with corrupt packet
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                    pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM IP address
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        ip_ttl=0)

    group = "L3"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports, skip_counter_check=True)

    # 5. Check we have captured the packets
    # 5.1 Remove existing capture file
    result = duthost.command("sudo rm -f /var/dump/capture_0.pcap")
    # 5.2 Dump packet capture
    result = duthost.command("show platform npu packet-debug capture -d")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    # 5.3 Verify no traceback
    assert not traceback_found, "Traceback found in show platform npu trap"
    # 5.4 Verify we have some output from command
    assert '(68)' in result["stdout"] , "CLI output missing/not correct"
    # 5.5 Verify dump captured in default file
    assert "dump captured" in result["stdout"]
    result = duthost.command('stat --printf="%s" /var/dump/capture_0.pcap')
    assert not result["stderr"]
    assert result["stdout"] != '0'
    # 5.6 Verify dump captured with given filename
    result = duthost.command("show platform npu packet-debug capture -f capture2.pcap")
    assert "dump captured" in result["stdout"]
    result = duthost.command('stat --printf="%s" /var/dump/capture2_0.pcap')
    assert not result["stderr"]
    assert result["stdout"] != '0'
    # 5.7 Remove capture files
    result = duthost.command("sudo rm -f /var/dump/capture_0.pcap")
    result = duthost.command("sudo rm -f /var/dump/capture2_0.pcap")

    # 6. Disable packet-debug drops feature
    result = duthost.command("sudo config platform cisco packet-debug drops disable")
    logging.info(result)
    time.sleep(10)
    assert "Packet capture disabled" in result["stdout"], "CLI output missing/not correct"

    # 7 Verify we receive packet for configured event
    # 7.1 enable packet-debug with event type
    result = duthost.command("sudo config platform cisco packet-debug drops enable -e 68")
    # 7.2 run the test
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports, skip_counter_check=True)
    # 7.3 get a dump and verify we get the expected packet
    result = duthost.command("show platform npu packet-debug capture -d")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    # 7.4 Verify no traceback
    assert not traceback_found, "Traceback found in show platform npu trap"
    # 7.5 Verify we have captured output from command
    assert '(68)' in result["stdout"] , "CLI output missing/not correct"
    # 7.6 disable packet capture
    result = duthost.command("sudo config platform cisco packet-debug drops disable -e 68")
    logging.info(result)
    time.sleep(10)
    assert "Packet capture disabled" in result["stdout"], "CLI output missing/not correct"

    # 8 Test to verify we don't get unwanted events in dump
    # 8.1 enable packet-debug with event type
    result = duthost.command("sudo config platform cisco packet-debug drops enable -e 2")
    # 8.2 run the test. it shall generate HEADER_ERR drops
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports, skip_counter_check=True)
    # 8.3 get a dump and verify we don't get any dump
    result = duthost.command("show platform npu packet-debug capture -d")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    # 8.4 Verify no traceback
    assert not traceback_found, "Traceback found in show platform npu trap"
    # 8.5 Verify no output
    assert 'Buffer is empty' in result["stdout"] , "CLI output missing/not correct"
    # 8.6 disable packet capture
    result = duthost.command("sudo config platform cisco packet-debug drops disable -e 2")
    logging.info(result)
    time.sleep(10)
    assert "Packet capture disabled" in result["stdout"], "CLI output missing/not correct"

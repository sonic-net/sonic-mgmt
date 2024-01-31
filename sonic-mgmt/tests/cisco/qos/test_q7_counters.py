"""
Tests for verifying the control plane frames are
taking the UC7 queue
"""

import logging
import pytest
import ipaddress
import time
import json
from tests.cisco.common.utils import CheckEnvironment, verify_command_result


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def get_queue_counter(asichost, portchannel_members):

    sonic_queue_counter_cmd = 'show queue counters {} --json'
    total_pkts = 0
    for member in portchannel_members:
        cmd = sonic_queue_counter_cmd.format(member)
        result = asichost.command(cmd)
        verify_command_result(result, cmd)

        json_str = result["stdout"].strip()
        try:
            data = json.loads(json_str)
        except Exception as e:
            pytest.fail("JSON load error: {}".format(e))

        if "UC7" in data[member]:
            uc7_counter_str = data[member]["UC7"].get("totalpacket", "0")
            uc7_counter = int(uc7_counter_str)
            total_pkts += uc7_counter

    return total_pkts


def clear_queue_counters(asichost):
    asichost.command("sonic-clear queuecounters")


def test_verify_q7_counters(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, tbinfo, request):

    """
    @summary: Verify output of `show queue counters` for UC7 increases as expected
    """

    duthost = duthosts[enum_frontend_dut_hostname]

    if CheckEnvironment.is_sim(duthost):
        pytest.skip("Test not supported in SIM environment")

    asichost = duthost.asic_instance(enum_frontend_asic_index)

    port_channels_data = asichost.get_portchannels_and_members_in_ns(tbinfo)

    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    """
      1. Clear sonic-queuecounters
      2. Iterate over all port channel.
      3. Get begin queue counter for UC7 as sum of counters per member link
      4. Ping 50 packets to the peer IP
      6. Sleep for 2 seconds
      5. Get end queue counter for UC7 as sum of counters per member link
      6. Check the delta between end and begin counter is greater than the pinged count
    """

    PING_COUNT = 50
    SLEEP_INTERVAL = 2

    start_counters = {}  # Dictionary to store start counters for each port channel
    clear_queue_counters(asichost)

    port_channel_peer_addr = {}

    for pc in mg_facts["minigraph_portchannel_interfaces"]:
        try:
            if ipaddress.ip_address(pc['peer_addr']).version == 4:
                port_channel_peer_addr[pc['attachto']] = pc['peer_addr']
            elif ipaddress.ip_address(pc['peer_addr']).version == 6:
                continue
        except ipaddress.AddressValueError:
            # the case where 'peer_addr' is 'NA' or an invalid address
            # choose to ignore and log
            logging.info("Ignoring PortChannel {} which has a invalid IPV4 address {}".format(
                                                        pc['attachto'], pc['peer_addr']))
            pass

    for portchannel in port_channel_peer_addr.keys():
        portchannel_members = port_channels_data[portchannel]
        logging.info("Checking portchannel {} with members {} and peer ip {}".format(
              portchannel, portchannel_members, port_channel_peer_addr[portchannel]))

        start_counters[portchannel] = get_queue_counter(asichost, portchannel_members)

        # Start ping traffic to peer
        ping_cmd = "ping {} -c {} -f".format(port_channel_peer_addr[portchannel], PING_COUNT)
        result = asichost.command(ping_cmd)
        verify_command_result(result, ping_cmd)

    time.sleep(SLEEP_INTERVAL)

    for portchannel in port_channel_peer_addr.keys():
        portchannel_members = port_channels_data[portchannel]
        start_counter = start_counters[portchannel]
        end_counter = get_queue_counter(asichost, portchannel_members)

        assert (end_counter - start_counter >= PING_COUNT), \
               "Insufficient UC7 counter increase of {}. Expected at least {} increase.".format(
                                                               (end_counter - start_counter),
                                                               PING_COUNT
                                                             )

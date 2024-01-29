"""
Tests for verifying the control plane frames are
taking the UC7 queue
"""

import logging
import pytest
import time
from tests.common.cisco_data import is_cisco_device
import json


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def verify_command_result(result, cmd):
    # Raise an AssertionError if "stdout" is empty
    assert result["stdout"], "No output for {}".format(cmd)

    # Check if "cisco sdk-debug enable" is present in result["stdout"]
    dshell_disabled = "cisco sdk-debug enable" in result["stdout"]
    # Raise an AssertionError if "cisco sdk-debug enable" is found
    assert not dshell_disabled, "debug shell server is not running for command: {}".format(cmd)

    # Check if "Traceback" is present in result["stdout"]
    traceback_found = "Traceback" in result["stdout"]
    # Raise an AssertionError if "Traceback" is found
    assert not traceback_found, "Traceback found in {}".format(cmd)


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
    @summary: Verify output of `show queue counters for UC7 increases as expected`
    """

    duthost = duthosts[enum_frontend_dut_hostname]

    if not is_cisco_device(duthost):
        pytest.skip("Skipping as not a Cisco device")

    asichost = duthost.asic_instance(enum_frontend_asic_index)

    port_channels_data = asichost.get_portchannels_and_members_in_ns(tbinfo)

    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    """
      Create set of unique port channel entries
      1. Iterate over all port channel.
      2. Clear sonic-queuecounters
      3. Get begin queue counter for UC7 as sum of counters per memeber link
      4. Ping 100 packets to the peer IP
      5. Get end queue counter for UC7 as sum of counters per member link
      6. Check the delta between end and begin counter is greater than the pinged count
    """

    PING_COUNT = 100

    for portchannel, portchannel_members in port_channels_data.items():
        for neighbor in mg_facts['minigraph_portchannel_interfaces']:
            if neighbor['attachto'] == portchannel:
                logging.info("Checking portchannel {} with members {} and peer ip {}".format(
                      neighbor['attachto'], portchannel_members, neighbor['peer_addr']))

                clear_queue_counters(asichost)

                start_counter = get_queue_counter(asichost, portchannel_members)

                # Start ping traffic to peer
                ping_cmd = "ping {} -c {} -f".format(neighbor['peer_addr'], PING_COUNT)
                result = asichost.command(ping_cmd)
                verify_command_result(result, ping_cmd)

                time.sleep(10)
                end_counter = get_queue_counter(asichost, portchannel_members)

                assert (end_counter - start_counter >= PING_COUNT), \
                       "Insufficient UC7 counter increase of {}. Expected at least {} increase.".format(
                                                                       (end_counter - start_counter),
                                                                       PING_COUNT
                                                                     )

                '''
                    There will be two entries per port channel.
                    One for IPV4 and another for IPV6 address.
                    Verify one of them and break and move on to
                    next port channel
                '''
                break

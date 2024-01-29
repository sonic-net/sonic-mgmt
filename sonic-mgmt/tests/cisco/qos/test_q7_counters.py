"""
Tests for verifying the control plane frames are
taking the UC7 queue
"""

import logging
import pytest
import time
from tests.common.cisco_data import is_cisco_device
# from tests.common.helpers.assertions import pytest_assert
import json


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def get_asic_facts(duthost):
    asic_namespace_list = []

    if duthost.is_multi_asic:
        for asic in duthost.frontend_asics:
            asic_namespace_list.append(asic.namespace)
    else:
        asic_namespace_list.append('asic0')

    return asic_namespace_list


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


def get_queue_counter(duthost, portchannel_members):

    sonic_queue_counter_cmd = 'show queue counters {} --json'
    total_pkts = 0
    for member in portchannel_members:
        cmd = sonic_queue_counter_cmd.format(member)
        result = duthost.command(cmd)
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


def test_verify_q7_counters(duthosts, rand_one_dut_hostname, tbinfo, request):
    """
    @summary: Verify output of `show queue counters for UC7 increases as expected`
    """

    duthost = duthosts[rand_one_dut_hostname]
    if not is_cisco_device(duthost):
        pytest.skip("Skipping as not a Cisco device")

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    portchannel_itfs = cfg_facts["PORTCHANNEL_INTERFACE"]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    """
      Create set of unique port channel entries
      1. Iterate over all port channel.
      2. Clear sonic-queuecounters
      3. Get begin queue counter for UC7 as sum of counters per memeber link
      4. Ping 100 packets to the peer IP
      5. Get end queue counter for UC7 as sum of counters per member link
      6. Check the delta between end and begin counter is greater than the pinged count
    """
    port_channel_set = set()
    port_channel_set.update([portchannel for portchannel, _ in list(portchannel_itfs.items())])

    PING_COUNT = 100

    for portchannel in port_channel_set:
        portchannel_members = list(cfg_facts["PORTCHANNEL_MEMBER"][portchannel].keys())
        for neighbor in mg_facts['minigraph_portchannel_interfaces']:
            if neighbor['attachto'] == portchannel:
                logging.info("portchannel {} peer ip {} members {}".format(
                      neighbor['attachto'], neighbor['peer_addr'], portchannel_members))

                sonic_clear_cmd = 'sonic-clear queuecounters'
                result = duthost.command(sonic_clear_cmd)
                verify_command_result(result, sonic_clear_cmd)

                start_counter = get_queue_counter(duthost, portchannel_members)

                # Start ping traffic to peer
                ping_cmd = "ping {} -c {} -f".format(neighbor['peer_addr'], PING_COUNT)
                result = duthost.command(ping_cmd)
                verify_command_result(result, ping_cmd)

                time.sleep(10)
                end_counter = get_queue_counter(duthost, portchannel_members)

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

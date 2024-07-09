#! /usr/bin/env python3

import pytest
import logging
import time
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.utilities import wait_until
from run_events_test import run_test
from event_utils import find_test_vlan, find_test_port_and_mac, create_dhcp_discover_packet

logger = logging.getLogger(__name__)
tag = "sonic-events-dhcp-relay"


def test_event(duthost, gnxi_path, ptfhost, ptfadapter, data_dir, validate_yang):
    features_states, succeeded = duthost.get_feature_status()
    if not succeeded or features_states["dhcp_relay"] != "enabled":
        pytest.skip("dhcp_relay is not enabled, skipping dhcp_relay events")
    logger.info("Beginning to test dhcp-relay events")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger_dhcp_relay_discard,
             "dhcp_relay_discard.json", "sonic-events-dhcp-relay:dhcp-relay-discard", tag, False, 30, ptfadapter)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger_dhcp_relay_disparity,
             "dhcp_relay_disparity.json", "sonic-events-dhcp-relay:dhcp-relay-disparity", tag, False, 30, ptfadapter)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger_dhcp_relay_bind_failure,
             "dhcp_relay_bind_failure.json", "sonic-events-dhcp-relay:dhcp-relay-bind-failure", tag, False, 30)


def trigger_dhcp_relay_discard(duthost, ptfadapter):
    send_dhcp_discover_packets(duthost, ptfadapter)


def trigger_dhcp_relay_disparity(duthost, ptfadapter):
    """11 packets because dhcpmon process will store up to 10 unhealthy status events
    https://github.com/sonic-net/sonic-dhcpmon/blob/master/src/dhcp_mon.cpp#L94
    static int dhcp_unhealthy_max_count = 10;
    Sending at interval of 18 seconds because dhcpmon process will check health at that interval
    static int window_interval_sec = 18;
    """
    send_dhcp_discover_packets(duthost, ptfadapter, 11, 18)


def trigger_dhcp_relay_bind_failure(duthost):
    # Flush ipv6 vlan address and restart dhc6relay process
    py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "dhcp_relay"),
              "dhcp_relay container not started")

    # Get Vlan with IPv6 address configured
    dhcp_test_info = find_test_vlan(duthost)
    py_assert(len(dhcp_test_info) != 0, "Unable to find vlan for test")

    vlan = dhcp_test_info["vlan"]
    dhcp6_relay_process = dhcp_test_info["dhcp6relay_process"]
    ipv6_ip = dhcp_test_info["ipv6_address"]

    try:
        # Flush ipv6 address from vlan
        duthost.shell("ip -6 address flush dev {}".format(vlan))

        # Restart dhcrelay process
        duthost.shell("docker exec dhcp_relay supervisorctl restart {}".format(dhcp6_relay_process))

    finally:
        # Add back ipv6 address to vlan
        duthost.shell("ip address add {} dev {}".format(ipv6_ip, vlan))

        # Restart dhcrelay process
        duthost.shell("docker exec dhcp_relay supervisorctl restart {}".format(dhcp6_relay_process))


def send_dhcp_discover_packets(duthost, ptfadapter, packets_to_send=5, interval=1):
    py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "dhcp_relay"),
              "dhcp_relay container not started")

    # Get Vlan with IPv4 address configured
    dhcp_test_info = find_test_vlan(duthost)
    py_assert(len(dhcp_test_info) != 0, "Unable to find vlan for test")

    vlan = dhcp_test_info["vlan"]
    dhcrelay_process = dhcp_test_info["dhcrelay_process"]
    ipv4_ip = dhcp_test_info["ipv4_address"]
    member_interfaces = dhcp_test_info["member_interface"]

    try:
        # Flush ipv4 address from vlan
        duthost.shell("ip -4 address flush dev {}".format(vlan))

        # Restart dhcrelay process
        duthost.shell("docker exec dhcp_relay supervisorctl restart {}".format(dhcrelay_process))

        # Send packets

        # results contains up to 5 tuples of member interfaces from vlan (port, mac address)
        results = find_test_port_and_mac(duthost, member_interfaces, 5)

        for i in range(packets_to_send):
            result = results[i % len(results)]
            port = result[0]
            client_mac = result[1]
            packet = create_dhcp_discover_packet(client_mac)
            testutils.send_packet(ptfadapter, port, packet)
            time.sleep(interval)

    finally:
        # Add back ipv4 address to vlan
        duthost.shell("ip address add {} dev {}".format(ipv4_ip, vlan))

        # Restart dhcrelay process
        duthost.shell("docker exec dhcp_relay supervisorctl restart {}".format(dhcrelay_process))

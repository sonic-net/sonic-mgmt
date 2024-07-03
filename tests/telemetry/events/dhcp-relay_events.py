#! /usr/bin/env python3

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
    logger.info("Beginning to test dhcp-relay events")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, send_dhcp_discover_packets,
             "dhcp_relay_discard.json", "sonic-events-dhcp-relay:dhcp-relay-discard", tag, False, 30, ptfadapter)


def send_dhcp_discover_packets(duthost, ptfadapter):
    py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "dhcp_relay"),
              "dhcp_relay container not started")

    # Get Vlan with IPv4 address configured
    vlan, ipv4_ip, members = find_test_vlan(duthost)
    py_assert(vlan != "", "Unable to find vlan for test")

    try:
        # Flush ipv4 address from vlan
        duthost.shell("ip -4 address flush dev {}".format(vlan))

        # Restart dhcrelay process
        duthost.shell("docker exec dhcp_relay supervisorctl restart isc-dhcpv4-relay-{}".format(vlan))

        # Send packets
        results = find_test_port_and_mac(duthost, members, 5)
        for result in results:
            packet = create_dhcp_discover_packet(result[1])
            testutils.send_packet(ptfadapter, result[0], packet)
            time.sleep(1)

    finally:
        # Add back ipv4 address to vlan
        duthost.shell("ip address add {} dev {}".format(ipv4_ip, vlan))

        # Restart dhcrelay process
        duthost.shell("docker exec dhcp_relay supervisorctl restart isc-dhcpv4-relay-{}".format(vlan))

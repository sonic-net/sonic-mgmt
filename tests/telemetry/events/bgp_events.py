#! /usr/bin/env python3

import logging
import time
import ipaddress

from tests.common.utilities import is_ipv6_only_topology
from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-bgp"


def test_event(duthost, gnxi_path, ptfhost, ptfadapter, data_dir, validate_yang, tbinfo=None):
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, drop_tcp_packets,
             "bgp_notification.json", "sonic-events-bgp:notification", tag, tbinfo=tbinfo)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, shutdown_bgp_neighbors,
             "bgp_state.json", "sonic-events-bgp:bgp-state", tag, tbinfo=tbinfo)


def drop_tcp_packets(duthost, tbinfo=None):
    is_ipv6_only = tbinfo and is_ipv6_only_topology(tbinfo)
    # Get all BGP neighbors and filter by IP version based on management interface
    all_bgp_neighbors = duthost.get_bgp_neighbors()
    bgp_neighbor = None

    if is_ipv6_only:
        # Find an IPv6 BGP neighbor
        for neighbor_ip in all_bgp_neighbors.keys():
            if ipaddress.ip_address(neighbor_ip).version == 6:
                bgp_neighbor = neighbor_ip
                break
        if bgp_neighbor is None:
            raise Exception("No IPv6 BGP neighbors found for IPv6-only management interface")
        iptables_cmd = "ip6tables"
        logger.info(
            "Using IPv6 BGP neighbor {} and ip6tables for IPv6-only DUT management interface".format(
                bgp_neighbor
            )
        )
    else:
        # Find an IPv4 BGP neighbor (or just use the first one)
        for neighbor_ip in all_bgp_neighbors.keys():
            if ipaddress.ip_address(neighbor_ip).version == 4:
                bgp_neighbor = neighbor_ip
                break
        if bgp_neighbor is None:
            # Fallback to first neighbor if no IPv4 found
            bgp_neighbor = list(all_bgp_neighbors.keys())[0]
        iptables_cmd = "iptables"
        logger.info("Using IPv4 BGP neighbor {} and iptables for IPv4 topology".format(bgp_neighbor))

    holdtime_timer_ms = duthost.get_bgp_neighbor_info(bgp_neighbor)["bgpTimerConfiguredHoldTimeMsecs"]

    logger.info("Adding rule to drop TCP packets to test bgp-notification")

    ret = duthost.shell("{} -I INPUT -p tcp --dport 179 -j DROP".format(iptables_cmd))
    assert ret["rc"] == 0, "Unable to add DROP rule to {}".format(iptables_cmd)

    ret = duthost.shell("{} -I INPUT -p tcp --sport 179 -j DROP".format(iptables_cmd))
    assert ret["rc"] == 0, "Unable to add DROP rule to {}".format(iptables_cmd)

    ret = duthost.shell("{} -L".format(iptables_cmd))
    assert ret["rc"] == 0, "Unable to list {} rules".format(iptables_cmd)

    time.sleep(holdtime_timer_ms / 1000)  # Give time for hold timer expiry event, val from configured bgp neighbor info

    ret = duthost.shell("{} -D INPUT -p tcp --dport 179 -j DROP".format(iptables_cmd))
    assert ret["rc"] == 0, "Unable to remove DROP rule from {}".format(iptables_cmd)

    ret = duthost.shell("{} -D INPUT -p tcp --sport 179 -j DROP".format(iptables_cmd))
    assert ret["rc"] == 0, "Unable to remove DROP rule from {}".format(iptables_cmd)


def shutdown_bgp_neighbors(duthost, tbinfo=None):
    logger.info("Shutting down bgp neighbors to test bgp-state event")
    is_ipv6_only = tbinfo and is_ipv6_only_topology(tbinfo)
    assert duthost.is_service_running("bgpcfgd", "bgp") is True and duthost.is_bgp_state_idle(is_ipv6_only) is False
    logger.info("Start all bgp sessions")
    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"

    ret = duthost.shell("config bgp shutdown all")
    assert ret["rc"] == 0, "Failing to shutdown"

    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"

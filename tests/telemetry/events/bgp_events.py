#! /usr/bin/env python3

import logging
import time
import random
import pytest

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-bgp"


def test_event(duthost, gnxi_path, ptfhost, ptfadapter, data_dir, validate_yang):
    if duthost.is_supervisor_node():
        pytest.skip(
            "Skipping test for BGP onsupervisor card")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, drop_tcp_packets,
             "bgp_notification.json", "sonic-events-bgp:notification", tag)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, shutdown_bgp_neighbors,
             "bgp_state.json", "sonic-events-bgp:bgp-state", tag)


def drop_tcp_packets(duthost):
    if duthost.is_multi_asic:
        nslist = duthost.get_asic_namespace_list()
        ns = random.choice(nslist)
        asic_id = duthost.get_asic_id_from_namespace(ns)
        bgp_neighbor = list(duthost.get_bgp_neighbors_for_asic(ns).keys())[0]
        holdtime_timer_ms = duthost.get_bgp_neighbor_info(bgp_neighbor, asic_id)["bgpTimerConfiguredHoldTimeMsecs"]

        logger.info("Adding rule to drop TCP packets to test bgp-notification")

        ret = duthost.shell("sudo ip netns exec {} iptables -I INPUT -p tcp --dport 179 -j DROP".format(ns))
        assert ret["rc"] == 0, "Unable to add DROP rule to iptables"

        ret = duthost.shell("sudo ip netns exec {} iptables -I INPUT -p tcp --sport 179 -j DROP".format(ns))
        assert ret["rc"] == 0, "Unable to add DROP rule to iptables"

        ret = duthost.shell("sudo ip netns exec {} iptables -L".format(ns))
        assert ret["rc"] == 0, "Unable to list iptables rules"

        # Give time for hold timer expiry event, val from configured bgp neighbor info
        time.sleep(holdtime_timer_ms / 1000)

        ret = duthost.shell("sudo ip netns exec {} iptables -D INPUT -p tcp --dport 179 -j DROP".format(ns))
        assert ret["rc"] == 0, "Unable to remove DROP rule from iptables"
        ret = duthost.shell("sudo ip netns exec {} iptables -D INPUT -p tcp --sport 179 -j DROP".format(ns))
        assert ret["rc"] == 0, "Unable to remove DROP rule from iptables"
    else:
        bgp_neighbor = list(duthost.get_bgp_neighbors().keys())[0]

        holdtime_timer_ms = duthost.get_bgp_neighbor_info(bgp_neighbor)["bgpTimerConfiguredHoldTimeMsecs"]

        logger.info("Adding rule to drop TCP packets to test bgp-notification")

        ret = duthost.shell("iptables -I INPUT -p tcp --dport 179 -j DROP")
        assert ret["rc"] == 0, "Unable to add DROP rule to iptables"

        ret = duthost.shell("iptables -I INPUT -p tcp --sport 179 -j DROP")
        assert ret["rc"] == 0, "Unable to add DROP rule to iptables"

        ret = duthost.shell("iptables -L")
        assert ret["rc"] == 0, "Unable to list iptables rules"

        # Give time for hold timer expiry event, val from configured bgp neighbor info
        time.sleep(holdtime_timer_ms / 1000)

        ret = duthost.shell("iptables -D INPUT -p tcp --dport 179 -j DROP")
        assert ret["rc"] == 0, "Unable to remove DROP rule from iptables"

        ret = duthost.shell("iptables -D INPUT -p tcp --sport 179 -j DROP")
        assert ret["rc"] == 0, "Unable to remove DROP rule from iptables"


def shutdown_bgp_neighbors(duthost):
    logger.info("Shutting down bgp neighbors to test bgp-state event")
    assert duthost.is_service_running("bgpcfgd", "bgp") is True and duthost.is_bgp_state_idle() is False
    logger.info("Start all bgp sessions")
    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"

    ret = duthost.shell("config bgp shutdown all")
    assert ret["rc"] == 0, "Failing to shutdown"

    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"

#!/usr/bin/env python

import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

import ipaddress
import time

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]


def verify_all_neighbor_status(duthost, nbrhosts, status):
    neighbor_table = duthost.switch_arptable()['ansible_facts']['arptable']["v6"]
    for nbr_name, nbrhost in nbrhosts:
        address = nbrhost["conf"]["interfaces"]["Port-Channel1"]["ipv6"]
        if neighbor_table[address]["state"] != status:
            return False
    return True


@pytest.fixture
def create_incomplete_neighbor(duthost, nbrhosts, tbinfo):
    # creating incomplete ND neighbors involves several steps
    # 1. adding ip6tables entry to drop all incoming neighbor advertisement packets
    # 2. remove current neighbor entries
    # 3. on the neighbor device, ping dut
    duthost.command("sudo ip6tables -I INPUT -p ipv6-icmp -j DROP --icmpv6-type neighbour-advertisement")

    duthost.command("sudo ip -6 neigh flush all")

    dut_asn = tbinfo["topo"]["properties"]["configuration_properties"]["common"]["dut_asn"]
    for nbr_name, nbrhost in nbrhosts:
        for address in nbrhost["conf"]["bgp"]["peers"][dut_asn]:
            if isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address):
                nbrhost["host"].shell("nohup ping {} >/dev/null 2>&1 &".format(address))

    pytest_assert(wait_until(5, 1, 0, lambda: verify_all_neighbor_status(duthost, nbrhosts, "INCOMPLETE")),
                  "Neighbor status is not all set to INCOMPLETE")

    yield

    duthost.command("sudo ip6tables -D INPUT -p ipv6-icmp -j DROP --icmpv6-type neighbour-advertisement")

    for nbr_name, nbrhost in nbrhosts:
        nbrhost["host"].shell("sudo kill -9 $(pgrep ping)")

    pytest_assert(wait_until(5, 1, 0, lambda: verify_all_neighbor_status(duthost, nbrhosts, "REACHABLE")),
                  "Neighbor status is not all back to REACHABLE")


def test_conntrack_table_with_incomplete_neighbor(create_incomplete_neighbor, duthost, nbrhosts):
    # the whole tests involves several steps
    # 1. create a neighbor entry in incomplete state
    # 2. ping with icmpv6
    # 3. check conntrack table entries

    # start_conntrack_table_size = int(duthost.command("cat /proc/sys/net/netfilter/nf_conntrack_count")["stdout"])

    for nbr_name, nbrhost in nbrhosts:
        address = nbrhost["conf"]["interfaces"]["Port-Channel1"]["ipv6"]
        duthost.shell("nohup ping {} >/dev/null 2>&1 &".format(address))

    time.sleep(60)

    # end_conntrack_table_size = int(duthost.command("cat /proc/sys/net/netfilter/nf_conntrack_count")["stdout"])

    pytest_assert("[UNREPLIED]" not in duthost.command("sudo conntrack -f ipv6 -L dying")["stdout"],
                  "unreplied icmpv6 requests ended up in the dying list")

    for nbr_name, nbrhost in nbrhosts:
        address = nbrhost["conf"]["interfaces"]["Port-Channel1"]["ipv6"]
        duthost.shell("sudo kill -9 $(pgrep -f \"ping {}\")".format(address))

"""
ECN ACL marking x SRv6 forwarding interaction test.

This is a self-contained, additive wrapper around the existing SRv6 dataplane
infrastructure: it reuses the shared SRv6 helpers (locator / SID config,
neighbor / port discovery, send-verify) and only adds an ingress ECN ACL layer
on top. It does not modify any existing SRv6 or ACL test. Removing this file
(and its conditional_mark entry) leaves all pre-existing tests unchanged.

Scenario 1 - coexistence on uN forwarding:
    The DUT is an SRv6 uN endpoint. An ingress L3V6 ACL marks ECN=3 (CE) on the
    outer IPv6 header of the SRv6 packet. We verify the uN-forwarded packet
    (outer DA shifted, hop limit decremented) egresses with outer ECN=3, i.e.
    ECN ACL marking and SRv6 uN forwarding coexist without clobbering each other.
"""
import json
import logging

import pytest
from scapy.all import Raw
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.l2 import Ether
import ptf.packet as packet
from ptf.mask import Mask

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.srv6.srv6_utils import runSendReceive, get_neighbor_mac, verify_asic_db_sid_entry_exist
from tests.srv6.test_srv6_dataplane import get_ptf_src_port_and_dut_port_and_neighbor
from tests.common.helpers.srv6_helper import (
    create_srv6_locator, del_srv6_locator, create_srv6_sid, del_srv6_sid,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox", "broadcom"),
    pytest.mark.topology("t0", "t1"),
]

LOCATOR = "ecnloc"
LOCATOR_PREFIX = "fcbb:bbbb:1::"
SID = "fcbb:bbbb:1::"                 # /48 uN SID
UN_DA = "fcbb:bbbb:1:2::"            # incoming outer DA (hits the uN SID)
UN_DA_SHIFTED = "fcbb:bbbb:2::"     # outer DA after the uN uSID shift
FWD_ROUTE = "fcbb:bbbb:2::/48"
BLACKHOLE = "fcbb:bbbb::/32"
OUTER_SRC = "1000::1"
ACL_TABLE = "ECN_SRV6_TEST"
ACL_RULE = "MARK_SRV6"
ECN_MARK = 3


@pytest.fixture(scope="module")
def setup_srv6_ecn(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    dut_mac = duthost.facts["router_mac"]

    ingress_intf, ptf_src_ports, neighbor = \
        get_ptf_src_port_and_dut_port_and_neighbor(duthost, tbinfo)

    neighbor_ip = None
    for line in duthost.command("show ipv6 bgp summary")["stdout"].split("\n"):
        if neighbor in line:
            neighbor_ip = line.split()[0]
    pytest_assert(neighbor_ip, "Could not find IPv6 for neighbor {}".format(neighbor))

    # resolve the forwarding egress interface (portchannel if applicable)
    fwd_intf = ingress_intf
    pc_info = duthost.command("show int portchannel")["stdout"]
    if ingress_intf in pc_info:
        for line in pc_info.split("\n"):
            if ingress_intf in line:
                fwd_intf = line.split()[1]
                break

    db = "sonic-db-cli"

    # --- SRv6 uN setup (reuse existing helpers) ---
    create_srv6_locator(duthost, LOCATOR, LOCATOR_PREFIX)
    create_srv6_sid(duthost, LOCATOR, SID, action="uN", decap_dscp_mode="pipe")
    duthost.command(db + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|{} nexthop {} ifname {}"
                    .format(FWD_ROUTE, neighbor_ip, fwd_intf))
    duthost.command(db + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|{} blackhole true"
                    .format(BLACKHOLE))
    pytest_assert(wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, db),
                  "SRv6 MY_SID entry missing in ASIC_DB")

    # --- ingress ECN ACL (L3V6) bound to the ingress interface ---
    cfg = {
        "ACL_TABLE": {
            ACL_TABLE: {
                "policy_desc": "ECN SRv6 coexistence",
                "type": "L3V6",
                "stage": "ingress",
                "ports": [ingress_intf],
            }
        },
        "ACL_RULE": {
            "{}|{}".format(ACL_TABLE, ACL_RULE): {
                "PRIORITY": "9990",
                "SRC_IPV6": OUTER_SRC + "/128",
                "ECN_ACTION": str(ECN_MARK),
            }
        },
    }
    duthost.copy(content=json.dumps(cfg), dest="/tmp/ecn_srv6_acl.json")
    duthost.shell("sudo sonic-cfggen -j /tmp/ecn_srv6_acl.json --write-to-db")

    def _rule_active():
        out = duthost.shell("show acl rule {} {}".format(ACL_TABLE, ACL_RULE),
                            module_ignore_errors=True)["stdout"]
        return "ECN: {}".format(ECN_MARK) in out and "Active" in out
    pytest_assert(wait_until(30, 5, 0, _rule_active),
                  "ECN ACL rule was not programmed Active")

    yield {
        "duthost": duthost,
        "dut_mac": dut_mac,
        "ptf_src_ports": ptf_src_ports,
        "neighbor_ip": neighbor_ip,
    }

    duthost.command(db + " CONFIG_DB DEL 'ACL_RULE|{}|{}'".format(ACL_TABLE, ACL_RULE),
                    module_ignore_errors=True)
    duthost.command(db + " CONFIG_DB DEL 'ACL_TABLE|{}'".format(ACL_TABLE),
                    module_ignore_errors=True)
    del_srv6_sid(duthost, LOCATOR, SID)
    del_srv6_locator(duthost, LOCATOR)
    duthost.command(db + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|{}".format(FWD_ROUTE),
                    module_ignore_errors=True)
    duthost.command(db + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|{}".format(BLACKHOLE),
                    module_ignore_errors=True)
    duthost.shell("rm -f /tmp/ecn_srv6_acl.json", module_ignore_errors=True)


def test_srv6_ecn_marking_uN(setup_srv6_ecn, ptfadapter):
    info = setup_srv6_ecn
    duthost = info["duthost"]
    dut_mac = info["dut_mac"]
    ptf_src_ports = info["ptf_src_ports"]
    ptf_src_port = ptf_src_ports[0]
    src_mac = ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()

    # SRv6 uN packet (IPv6-in-IPv6), outer ECN=0 on ingress.
    injected = Ether(dst=dut_mac, src=src_mac) \
        / IPv6(src=OUTER_SRC, dst=UN_DA, tc=0) \
        / IPv6() / UDP(dport=4791) / Raw(load="ecnsrv6test")

    # After uN forwarding the outer DA is shifted and hop limit decremented; the
    # ingress ACL must additionally set outer ECN=3 (DSCP unchanged -> tc=0x03).
    exp = injected.copy()
    exp["Ether"].dst = get_neighbor_mac(duthost, info["neighbor_ip"])
    exp["Ether"].src = dut_mac
    exp["IPv6"].dst = UN_DA_SHIFTED
    exp["IPv6"].hlim -= 1
    exp["IPv6"].tc = (0 << 2) | ECN_MARK

    masked = Mask(exp)
    masked.set_do_not_care_packet(packet.Ether, "dst")
    masked.set_do_not_care_packet(packet.Ether, "src")
    masked.set_do_not_care_packet(packet.IPv6, "fl")

    passed = runSendReceive(injected, ptf_src_port, masked, ptf_src_ports, True, ptfadapter)
    pytest_assert(
        passed,
        "SRv6 uN packet was not received with outer ECN=3; ECN ACL marking and "
        "SRv6 uN forwarding do not coexist as expected.")


def test_srv6_ecn_negative_control(setup_srv6_ecn, ptfadapter):
    """Fact-check: an SRv6 packet whose outer SRC_IPV6 does NOT match the ACL
    rule must still be uN-forwarded but must NOT be ECN-marked (stays ECN=0).
    This proves the ECN=3 seen in test_srv6_ecn_marking_uN comes from the ACL
    match specifically, not from SRv6 processing or any other artifact."""
    info = setup_srv6_ecn
    duthost = info["duthost"]
    dut_mac = info["dut_mac"]
    ptf_src_ports = info["ptf_src_ports"]
    ptf_src_port = ptf_src_ports[0]
    src_mac = ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()

    non_match_src = "2000::1"  # not covered by the ACL rule (SRC_IPV6 1000::1/128)
    injected = Ether(dst=dut_mac, src=src_mac) \
        / IPv6(src=non_match_src, dst=UN_DA, tc=0) \
        / IPv6() / UDP(dport=4791) / Raw(load="ecnsrv6neg")

    exp = injected.copy()
    exp["Ether"].dst = get_neighbor_mac(duthost, info["neighbor_ip"])
    exp["Ether"].src = dut_mac
    exp["IPv6"].dst = UN_DA_SHIFTED
    exp["IPv6"].hlim -= 1
    exp["IPv6"].tc = 0  # ECN must stay 0 - rule did not match

    masked = Mask(exp)
    masked.set_do_not_care_packet(packet.Ether, "dst")
    masked.set_do_not_care_packet(packet.Ether, "src")
    masked.set_do_not_care_packet(packet.IPv6, "fl")

    passed = runSendReceive(injected, ptf_src_port, masked, ptf_src_ports, True, ptfadapter)
    pytest_assert(
        passed,
        "Non-matching SRv6 packet was not received with outer ECN=0; the ECN ACL "
        "is marking traffic it should not, or SRv6 forwarding alters ECN.")

import copy
import ipaddress
import json
from pathlib import Path

import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

from tests.common.config_reload import config_reload


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.dualtor_active_standby_toggle_to_enum_tor_manual_mode,
]

BACKUP_PATH = "/tmp/custom_acl_dscp_original.json"
with Path(__file__).with_name("custom_acl_dscp_rewrite.json").open() as config_file:
    ACL_CONFIG = json.load(config_file)


@pytest.fixture(scope="module", params=[
    ("ingress", "ipv4"), ("ingress", "ipv6"),
    ("egress", "ipv4"), ("egress", "ipv6"),
])
def supported_dscp_stage(request, duthosts, enum_dut_hostname):
    """Skip unsupported DSCP rewrite stages before configuring the test ACL."""
    dut = duthosts[enum_dut_hostname]
    if dut.is_multi_asic:
        pytest.skip("Direct ACL DSCP validation requires a single-ASIC T0 DUT")
    stage, family = request.param
    actions = dut.shell(
        'sonic-db-cli STATE_DB hget "ACL_STAGE_CAPABILITY_TABLE|{}" action_list'.format(stage.upper())
    )["stdout"].strip().split(",")
    if "DSCP_ACTION" not in actions:
        pytest.skip("{} does not support SET_DSCP at {}".format(dut.hostname, stage))
    return stage, family


@pytest.fixture(scope="module")
def dscp_context(supported_dscp_stage, duthosts, enum_dut_hostname, tbinfo):
    dut = duthosts[enum_dut_hostname]
    stage, family = supported_dscp_stage
    config = copy.deepcopy(ACL_CONFIG)
    table = next(iter(config["ACL_TABLE"].values()))
    rules = config["ACL_RULE"]

    facts = dut.get_extended_minigraph_facts(tbinfo)
    if not facts["minigraph_vlans"]:
        pytest.skip("This test requires a downstream VLAN")
    vlan_name, vlan = next(iter(facts["minigraph_vlans"].items()))
    source_port = vlan["members"][0]
    uplinks = [
        member for channel in facts["minigraph_portchannels"].values()
        for member in channel["members"]
    ]
    if not uplinks or source_port not in facts["minigraph_ptf_indices"]:
        pytest.skip("This test requires a downstream physical port and routed uplink portchannels")
    version = 4 if family == "ipv4" else 6
    vlan_interfaces = [
        interface for interface in facts["minigraph_vlan_interfaces"]
        if interface["attachto"] == vlan_name
        and ipaddress.ip_address(str(interface["addr"])).version == version
    ]
    destinations = list(dict.fromkeys(
        str(interface["peer_addr"]) for interface in facts["minigraph_portchannel_interfaces"]
        if ipaddress.ip_address(str(interface["peer_addr"])).version == version
    ))
    if not vlan_interfaces or len(destinations) < len(rules) + 1:
        pytest.skip("This test requires a VLAN address and four upstream peer addresses for {}".format(family))
    vlan_interface = ipaddress.ip_interface(
        "{}/{}".format(vlan_interfaces[0]["addr"], vlan_interfaces[0]["prefixlen"])
    )
    sources = [vlan_interface.ip + offset for offset in (2, 3)]
    if any(address not in vlan_interface.network or address == vlan_interface.network.broadcast_address
           for address in sources):
        pytest.skip("The VLAN subnet does not have enough source addresses")
    source_match = "SRC_IP" if family == "ipv4" else "SRC_IPV6"
    destination_match = "DST_IP" if family == "ipv4" else "DST_IPV6"
    prefix_length = 32 if family == "ipv4" else 128
    if family == "ipv6":
        match_fields = {"SRC_IP": source_match, "DST_IP": destination_match}
        table_type = config["ACL_TABLE_TYPE"][table["type"]]
        table_type["MATCHES"] = [match_fields.get(field, field) for field in table_type["MATCHES"]]
    table["stage"] = stage
    table["ports"] = [source_port] if stage == "ingress" else uplinks
    for index, rule in enumerate(rules.values()):
        rule[source_match] = "{}/{}".format(sources[0], prefix_length)
        rule[destination_match] = "{}/{}".format(destinations[index], prefix_length)

    dut.shell("test ! -e {0} && cp /etc/sonic/config_db.json {0}".format(BACKUP_PATH))
    try:
        if dut.shell('sonic-db-cli CONFIG_DB exists "ACL_TABLE|DATAACL"')["stdout"].strip() == "1":
            dut.shell("config acl remove table DATAACL")
        dut.shell("sonic-cfggen -a '{}' -w".format(json.dumps(config)))
        dut.shell("config save -y")
        # Exercise SWSS action handling independently of the companion YANG schema update.
        config_reload(dut, wait_for_bgp=True, yang_validate=False)

        yield {
            "family": family,
            "rules": rules,
            "sources": [str(address) for address in sources],
            "destinations": destinations,
            "source_port": facts["minigraph_ptf_indices"][source_port],
            "uplinks": [facts["minigraph_ptf_indices"][port] for port in uplinks],
            "router_mac": dut.get_dut_iface_mac(vlan_name)
            if "dualtor" in tbinfo["topo"]["name"] else dut.facts["router_mac"],
        }
    finally:
        dut.shell("cp {} /etc/sonic/config_db.json".format(BACKUP_PATH))
        config_reload(dut, wait_for_bgp=True, yang_validate=False)
        dut.file(path=BACKUP_PATH, state="absent")


@pytest.mark.parametrize("rule_name", list(ACL_CONFIG["ACL_RULE"]), ids=lambda name: name.split("|")[1])
def test_custom_acl_dscp_rewrite(dscp_context, ptfadapter, rule_name):
    """Verify three-field ACL matches rewrite DSCP, while misses and ECN remain unchanged."""
    context = dscp_context
    family = context["family"]
    rule = context["rules"][rule_name]
    original_dscp = int(rule["DSCP"])
    rewritten_dscp = int(rule["DSCP_ACTION"])
    matching_destination = list(context["rules"]).index(rule_name)
    for mismatch in ["source", "destination", "dscp", None]:
        source = context["sources"][1 if mismatch == "source" else 0]
        destination_index = len(context["rules"]) if mismatch == "destination" else matching_destination
        destination = context["destinations"][destination_index]
        input_dscp = original_dscp ^ 1 if mismatch == "dscp" else original_dscp
        for ecn in [0, 3]:
            input_tos = (input_dscp << 2) | ecn
            output_tos = ((rewritten_dscp if mismatch is None else input_dscp) << 2) | ecn
            if family == "ipv4":
                packet = testutils.simple_tcp_packet(
                    eth_dst=context["router_mac"], ip_src=source,
                    ip_dst=destination, ip_tos=input_tos, ip_ttl=64,
                )
                expected = packet.copy()
                expected[scapy.IP].tos = output_tos
                expected[scapy.IP].ttl = 63
                del expected[scapy.IP].chksum
            else:
                packet = testutils.simple_tcpv6_packet(
                    eth_dst=context["router_mac"], ipv6_src=source,
                    ipv6_dst=destination, ipv6_tc=input_tos, ipv6_hlim=64,
                )
                expected = packet.copy()
                expected[scapy.IPv6].tc = output_tos
                expected[scapy.IPv6].hlim = 63
            masked = Mask(expected)
            masked.set_do_not_care_scapy(scapy.Ether, "src")
            masked.set_do_not_care_scapy(scapy.Ether, "dst")
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, context["source_port"], packet)
            testutils.verify_packet_any_port(ptfadapter, masked, context["uplinks"], timeout=5)

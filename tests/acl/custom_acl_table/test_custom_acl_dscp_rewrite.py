import ipaddress
import json

import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.dualtor_active_standby_toggle_to_enum_tor_manual_mode,
]

TABLE_NAME = "DSCP_REWRITE_TEST"
BACKUP_PATH = "/tmp/custom_acl_dscp_original.json"
DSCP_VALUES = [0, 46, 63]
ORIGINAL_DSCP = 8


def _dscp_entries(dut):
    rules = " ".join("RULE_{}".format(dscp) for dscp in DSCP_VALUES)
    lines = dut.shell(
        'counters=$(for rule in {rules}; do '
        'sonic-db-cli COUNTERS_DB hget ACL_COUNTER_RULE_MAP "{table}:$rule"; done | tr "\\n" " "); '
        'sonic-db-cli ASIC_DB keys "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*" | '
        'while read -r key; do '
        'counter=$(sonic-db-cli ASIC_DB hget "$key" SAI_ACL_ENTRY_ATTR_ACTION_COUNTER); '
        'test -n "$counter" || continue; '
        'case " $counters " in *" $counter "*) '
        'value=$(sonic-db-cli ASIC_DB hget "$key" SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP); '
        'if test -n "$value"; then printf "%s %s\\n" "$key" "$value"; fi;; esac; done'.format(
            rules=rules, table=TABLE_NAME,
        )
    )["stdout_lines"]
    return dict(line.split(" ", 1) for line in lines if line)


@pytest.fixture(scope="module", params=[
    ("ingress", "ipv4"), ("ingress", "ipv6"),
    ("egress", "ipv4"), ("egress", "ipv6"),
])
def dscp_context(request, duthosts, enum_dut_hostname, tbinfo):
    dut = duthosts[enum_dut_hostname]
    if dut.is_multi_asic:
        pytest.skip("Direct ACL DSCP validation requires a single-ASIC T0 DUT")
    stage, family = request.param
    actions = dut.shell(
        'sonic-db-cli STATE_DB hget "ACL_STAGE_CAPABILITY_TABLE|{}" action_list'.format(stage.upper())
    )["stdout"].strip().split(",")
    if "DSCP_ACTION" not in actions:
        pytest.skip("{} does not support SET_DSCP at {}".format(dut.hostname, stage))

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
    if not vlan_interfaces or len(destinations) < len(DSCP_VALUES) + 1:
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
    config = {
        "ACL_TABLE_TYPE": {
            TABLE_NAME: {
                "MATCHES": [source_match, destination_match, "DSCP"],
                "ACTIONS": ["DSCP_ACTION", "PACKET_ACTION", "COUNTER"],
                "BIND_POINTS": ["PORT"],
            },
        },
        "ACL_TABLE": {
            TABLE_NAME: {
                "type": TABLE_NAME,
                "stage": stage,
                "ports": [source_port] if stage == "ingress" else uplinks,
            },
        },
        "ACL_RULE": {},
    }
    for index, dscp in enumerate(DSCP_VALUES):
        rule = {
            "PRIORITY": str(1000 + index),
            source_match: "{}/{}".format(sources[0], prefix_length),
            destination_match: "{}/{}".format(destinations[index], prefix_length),
            "DSCP": str(ORIGINAL_DSCP),
            "DSCP_ACTION": str(dscp),
        }
        if dscp == 46:
            rule["PACKET_ACTION"] = "FORWARD"
        config["ACL_RULE"]["{}|RULE_{}".format(TABLE_NAME, dscp)] = rule

    egress_table = 'sonic-db-cli STATE_DB exists "ACL_TABLE_TABLE|EgressSetDSCP"'
    original_egress_table = dut.shell(egress_table)["stdout"].strip()
    dut.shell("test ! -e {0} && cp /etc/sonic/config_db.json {0}".format(BACKUP_PATH))
    try:
        if dut.shell('sonic-db-cli CONFIG_DB exists "ACL_TABLE|DATAACL"')["stdout"].strip() == "1":
            dut.shell("config acl remove table DATAACL")
        dut.shell("sonic-cfggen -a '{}' -w".format(json.dumps(config)))
        dut.shell("config save -y")
        # Exercise SWSS action handling independently of the companion YANG schema update.
        config_reload(dut, wait_for_bgp=True, yang_validate=False)

        pytest_assert(
            wait_until(90, 5, 0, lambda: len(_dscp_entries(dut)) == len(DSCP_VALUES)),
            "Direct DSCP actions were not programmed into ASIC_DB",
        )
        entries = _dscp_entries(dut)
        pytest_assert(
            set(entries.values()) == {str(dscp) for dscp in DSCP_VALUES},
            "ASIC DSCP actions differ from the configured values",
        )
        for key in entries:
            metadata = dut.shell(
                'sonic-db-cli ASIC_DB hget "{}" SAI_ACL_ENTRY_ATTR_ACTION_SET_ACL_META_DATA'.format(key)
            )["stdout"].strip()
            pytest_assert(metadata in ("", "disabled"), "Direct rule allocated ACL metadata")
        pytest_assert(
            dut.shell(egress_table)["stdout"].strip() == original_egress_table,
            "Direct rewrite unexpectedly changed the underlay egress table",
        )
        yield {
            "family": family,
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


@pytest.mark.parametrize("dscp", DSCP_VALUES)
def test_custom_acl_dscp_rewrite(dscp_context, ptfadapter, dscp):
    """Verify three-field ACL matches rewrite DSCP, while misses and ECN remain unchanged."""
    context = dscp_context
    family = context["family"]
    for mismatch in ["source", "destination", "dscp", None]:
        source = context["sources"][1 if mismatch == "source" else 0]
        destination_index = len(DSCP_VALUES) if mismatch == "destination" else DSCP_VALUES.index(dscp)
        destination = context["destinations"][destination_index]
        input_dscp = ORIGINAL_DSCP + 1 if mismatch == "dscp" else ORIGINAL_DSCP
        for ecn in [0, 3]:
            input_tos = (input_dscp << 2) | ecn
            output_tos = ((dscp if mismatch is None else input_dscp) << 2) | ecn
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

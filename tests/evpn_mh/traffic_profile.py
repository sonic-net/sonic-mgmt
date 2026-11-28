"""Load and validate semantic EVPN-MH traffic profiles."""

from copy import deepcopy
import ipaddress
import re
from pathlib import Path

import yaml
from yaml.constructor import ConstructorError

from .topology import ethernet_segments


PROFILE_PATH = Path(__file__).parent / "files" / "traffic_profiles.yml"
PACKET_KINDS = (
    "arp_reply", "arp_request", "ethernet", "ipv4_udp", "ipv4_icmp",
    "ipv6_udp", "ipv6_ns", "ipv6_na")


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark,
                "found duplicate key {!r}".format(key), key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_profiles(path=PROFILE_PATH):
    with Path(path).open(encoding="utf-8") as stream:
        data = yaml.load(stream, Loader=_UniqueKeyLoader)
    validate_profiles(data)
    return data


def validate_profiles(data):
    if not isinstance(data, dict):
        raise ValueError("traffic profile document must be a mapping")
    if data.get("version") != 1:
        raise ValueError("traffic profile version must be 1")
    defaults = data.get("defaults", {})
    for field in ("packet_count", "frame_size", "max_loss_percent",
                  "max_duplicate_percent"):
        if field not in defaults:
            raise ValueError("traffic defaults missing {}".format(field))
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("traffic profiles must be a non-empty mapping")
    for profile_name, profile in profiles.items():
        flows = profile.get("flows", [])
        if not flows:
            raise ValueError("profile {} has no flows".format(profile_name))
        names = set()
        for flow in flows:
            for field in ("name", "tx_endpoint", "receive_groups", "packet"):
                if field not in flow:
                    raise ValueError("profile {} flow missing {}".format(profile_name, field))
            if flow["packet"].get("kind") not in PACKET_KINDS:
                raise ValueError("profile {} has unsupported packet kind".format(profile_name))
            if flow["name"] in names:
                raise ValueError("profile {} has duplicate flow {}".format(profile_name, flow["name"]))
            names.add(flow["name"])
            if not all(isinstance(group, list) and group
                       for group in flow["receive_groups"]):
                raise ValueError("profile {} has an empty receive group".format(
                    profile_name))
            for percentage in ("max_loss_percent", "max_duplicate_percent"):
                value = flow.get(percentage, defaults.get(percentage, 0))
                if float(value) < 0 or float(value) > 100:
                    raise ValueError("profile {} has invalid {}".format(
                        profile_name, percentage))
            variation_fields = (
                "udp_src_count", "udp_dst_count", "udp_port_step")
            if any(field in flow for field in variation_fields):
                if not all(field in flow for field in variation_fields):
                    raise ValueError(
                        "profile {} flow {} must configure both UDP counts "
                        "and the port step".format(profile_name, flow["name"]))
                values = {field: flow[field] for field in variation_fields}
                if not all(isinstance(value, int) and not isinstance(value, bool)
                           and value > 0 for value in values.values()):
                    raise ValueError(
                        "profile {} flow {} has invalid UDP variation".format(
                            profile_name, flow["name"]))
                if flow["packet"]["kind"] not in ("ipv4_udp", "ipv6_udp"):
                    raise ValueError(
                        "profile {} flow {} varies UDP ports on a non-UDP "
                        "packet".format(profile_name, flow["name"]))
                packet_count = int(flow.get(
                    "packet_count", defaults["packet_count"]))
                if (values["udp_src_count"] != packet_count
                        or values["udp_dst_count"] != packet_count):
                    raise ValueError(
                        "profile {} flow {} must define one unique paired "
                        "UDP tuple per packet".format(profile_name, flow["name"]))


def _compile_packet(packet, topology):
    """Resolve semantic endpoint references into concrete packet fields."""
    endpoints = topology["endpoints"]
    compiled = deepcopy(packet)
    source = compiled.pop("src")
    if source not in endpoints and source in topology.get("ethernet_segments", {}):
        source = topology["ethernet_segments"][source]["endpoint"]
    if source not in endpoints:
        raise ValueError("unknown source endpoint {}".format(source))
    compiled.setdefault("src_mac", endpoints[source]["mac"])
    if endpoints[source].get("tagged_vlan"):
        compiled.setdefault("vlan_id", int(endpoints[source]["tagged_vlan"]))

    vlan_id = compiled.get("vlan_id")
    if isinstance(vlan_id, str):
        if vlan_id not in topology:
            raise ValueError("unknown topology VLAN reference {}".format(vlan_id))
        compiled["vlan_id"] = int(topology[vlan_id])

    kind = compiled["kind"]
    if kind == "ethernet":
        return compiled
    if kind in ("arp_reply", "arp_request"):
        compiled.setdefault("src_ip", endpoints[source]["ipv4"])
        compiled.setdefault("dst_ip", endpoints[source]["gateway_ipv4"])
        compiled.setdefault(
            "dst_mac",
            (topology["anycast_gateway_mac"] if kind == "arp_reply"
             else "ff:ff:ff:ff:ff:ff"),
        )
        return compiled
    if kind == "ipv6_ns":
        compiled.setdefault("src_ip", endpoints[source]["ipv6"])
        compiled.setdefault("target_ip", endpoints[source]["gateway_ipv6"])
        # RFC 4861 requires every Neighbor Discovery message to use hop
        # limit 255.  A normal IPv6 default (64) is rejected by the DUT and
        # therefore cannot teach the synthetic PTF host neighbor.
        compiled.setdefault("hlim", 255)
        return compiled
    if kind == "ipv6_na":
        compiled.setdefault("src_ip", endpoints[source]["ipv6"])
        compiled.setdefault("target_ip", compiled["src_ip"])
        compiled.setdefault("dst_ip", endpoints[source]["gateway_ipv6"])
        compiled.setdefault("dst_mac", topology["anycast_gateway_mac"])
        compiled.setdefault("hlim", 255)
        return compiled

    destination = compiled.pop("dst", None)
    gateway = compiled.pop("gateway", False)
    family = "ipv6" if kind == "ipv6_udp" else "ipv4"
    unknown_prefix = compiled.pop("unknown_destination_prefix", None)
    if unknown_prefix:
        if unknown_prefix not in topology:
            raise ValueError(
                "unknown topology prefix reference {}".format(unknown_prefix))
        network = ipaddress.ip_network(topology[unknown_prefix])
        if network.version != (6 if family == "ipv6" else 4):
            raise ValueError(
                "{} does not match {} packet family".format(
                    unknown_prefix, family))
        used = {
            ipaddress.ip_address(value)
            for details in endpoints.values()
            for value in (details.get(family), details.get("gateway_{}".format(family)))
            if value
        }
        candidate = None
        for offset in range(1, min(int(network.num_addresses), 256)):
            address = network.network_address + offset
            if address == network.broadcast_address or address in used:
                continue
            candidate = address
            break
        if candidate is None:
            raise ValueError(
                "{} has no unused destination in the first 255 hosts".format(
                    unknown_prefix))
        compiled.setdefault("dst_ip", str(candidate))
    compiled.setdefault("src_ip", endpoints[source][family])
    if gateway:
        compiled.setdefault(
            "dst_ip", endpoints[source]["gateway_{}".format(family)])
        compiled.setdefault("dst_mac", topology["anycast_gateway_mac"])
    else:
        if destination not in endpoints:
            raise ValueError("unknown destination endpoint {}".format(destination))
        compiled.setdefault("dst_ip", endpoints[destination][family])
        compiled.setdefault(
            "dst_mac", topology["anycast_gateway_mac"]
            if compiled.pop("routed", False)
            else endpoints[destination]["mac"])
    return compiled


def _bond_endpoints(topology):
    if topology.get("ethernet_segments"):
        segments = ethernet_segments(topology)
    else:
        # Profile-only unit users and compact legacy topology data need only
        # the PTF attachment metadata, not the complete ES control-plane
        # schema validated by ``ethernet_segments``.
        segments = {"h2": {
            "endpoint": "h2",
            "ptf_member_roles": ("h2_leg0", "h2_leg1"),
            "ptf_bond_interface": topology.get(
                "ptf_bond_interface", "bond-evpn-mh"),
            "ptf_host_interface": topology.get(
                "ptf_h2_interface", "evpn-h2"),
        }}
    bonds = {}
    for name, segment in segments.items():
        details = {
            "member_roles": list(segment["ptf_member_roles"]),
            "bond_interface": segment["ptf_bond_interface"],
            "host_interface": segment["ptf_host_interface"],
        }
        bonds[name] = details
        bonds[segment["endpoint"]] = details
    return bonds


def _compile_expected(packet, expected, topology):
    compiled = deepcopy(expected or {})
    destination = packet.get("dst")
    if packet.get("gateway"):
        source = packet["src"]
        compiled.update({
            "src_mac": topology["anycast_gateway_mac"],
            "dst_mac": topology["endpoints"][source]["mac"],
            "src_ip": topology["endpoints"][source]["gateway_ipv4"],
            "dst_ip": topology["endpoints"][source]["ipv4"],
        })
    elif packet.get("routed"):
        source_details = topology["endpoints"][packet["src"]]
        destination_details = topology["endpoints"][destination]
        local_to_remote = (
            destination_details.get("attachment_role") == "remote_leaf"
            and int(destination_details.get("vlan", -1))
            == int(topology.get("remote_vlan", -2))
            and source_details.get("attachment_role") != "remote_leaf"
            and int(source_details.get("vlan", -1))
            == int(topology.get("mh_vlan", -2)))
        remote_to_local = (
            source_details.get("attachment_role") == "remote_leaf"
            and int(source_details.get("vlan", -1))
            == int(topology.get("remote_vlan", -2))
            and destination_details.get("attachment_role") != "remote_leaf"
            and int(destination_details.get("vlan", -1))
            == int(topology.get("mh_vlan", -2)))
        # Symmetric IRB crosses an ingress and an egress routed boundary in
        # either direction.  Local same-side routed profiles remain one hop.
        symmetric_irb = local_to_remote or remote_to_local
        routing_hops = 2 if symmetric_irb else 1
        if "src_mac" not in compiled:
            if local_to_remote:
                vlan = str(int(destination_details["vlan"]))
                mac = topology.get("routed_egress_macs", {}).get(
                    "remote_leaf", {}).get(vlan, "")
                if (not isinstance(mac, str)
                        or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
                        or int(mac.split(":", 1)[0], 16) & 1
                        or mac == "00:00:00:00:00:00"):
                    raise ValueError(
                        "remote routed VLAN{} needs its native EOS SVI "
                        "egress MAC from evpn_mh_routed_egress".format(vlan))
                compiled["src_mac"] = mac
            else:
                compiled["src_mac"] = topology["anycast_gateway_mac"]
        compiled.setdefault("dst_mac", destination_details["mac"])
        hop_field = "hlim" if packet["kind"] == "ipv6_udp" else "ttl"
        if hop_field not in compiled:
            initial_hops = int(packet.get(hop_field, 64))
            if not routing_hops < initial_hops <= 255:
                raise ValueError("routed packet has insufficient {}".format(hop_field))
            compiled[hop_field] = initial_hops - routing_hops
    return compiled


def resolved_profile(name, topology, runtime=None, path=PROFILE_PATH):
    data = load_profiles(path)
    if name not in data["profiles"]:
        raise KeyError("unknown traffic profile {}".format(name))
    profile = deepcopy(data["profiles"][name])
    profile["defaults"] = deepcopy(data["defaults"])
    referenced = set()
    for flow in profile["flows"]:
        referenced.add(flow["packet"]["src"])
        if flow["packet"].get("dst"):
            referenced.add(flow["packet"]["dst"])
    profile["neighbors"] = deepcopy({
        endpoint: details
        for endpoint, details in topology["endpoints"].items()
        if not details.get("physical_only")
        # Community topology entries are retained for provenance, and their
        # frozen legacy aliases are added during normalization.  PTF consumes
        # only the alias copy, which is the name present in the semantic port
        # map and in the frozen traffic profiles.
        and (not details.get("source_alias")
             or endpoint == details.get("source_alias"))
        and (not details.get("traffic_only") or endpoint in referenced)
    })
    profile["bond_endpoints"] = _bond_endpoints(topology)
    # Preserve the legacy scalar view only as an explicit primary-segment
    # compatibility surface.  All native PTF resolution uses bond_endpoints.
    primary_name = topology.get("primary_test_segment")
    if primary_name:
        primary = topology["ethernet_segments"][primary_name]
        profile["mh_bond_interface"] = primary["ptf_bond_interface"]
        profile["mh_host_interface"] = primary["ptf_host_interface"]
    profile["endpoint_vlans"] = {
        endpoint: int(details.get("tagged_vlan", 0) or 0)
        for endpoint, details in topology["endpoints"].items()
    }
    if runtime:
        profile["defaults"].update(deepcopy(runtime.get("default_overrides", {})))
        profile.update(deepcopy(runtime.get("profile_overrides", {})))
    for flow in profile["flows"]:
        semantic_packet = deepcopy(flow["packet"])
        if runtime:
            packet_overrides = runtime.get("flow_overrides", {}).get(
                flow["name"], {}).get("packet", {})
            semantic_packet.update(deepcopy(packet_overrides))
        expected = ({} if flow.get("transmit_only") else
                    _compile_expected(semantic_packet, flow.get("expected_packet"), topology))
        flow["packet"] = _compile_packet(semantic_packet, topology)
        if expected:
            flow["expected_packet"] = expected
    if runtime:
        profile["runtime"] = deepcopy(runtime)
    return profile

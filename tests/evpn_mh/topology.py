"""Bind EVPN-MH tests to the immutable community ``dualtor-aa`` topology.

``tbinfo`` supplies physical DUT, VM and PTF attachment facts.  The separate
``files/evpn_mh_service.yml`` supplies test-owned protocol values.  No caller
may manufacture a third SONiC DUT: ARISTA04T1 is the remote EOS EVPN peer.
"""

from copy import deepcopy
import ipaddress
from pathlib import Path

import yaml


TOPOLOGY_NAME = "dualtor-aa"
REQUIRED_DUT_ROLES = ("mh_leaf0", "mh_leaf1")
NEIGHBOR_NAMES = {
    "underlay0": "ARISTA01T1",
    "underlay1": "ARISTA02T1",
    "underlay2": "ARISTA03T1",
    "remote_leaf": "ARISTA04T1",
}
UNDERLAY_NEIGHBOR_ROLES = ("underlay0", "underlay1", "underlay2")

# Values are stock host-interface pair indexes, not physical port names.
ENDPOINT_PAIR_INDEX = {
    "h1_leg0": 0,
    "sh1": 1,
    "h2_leg0": 25,
    "h2_leg1": 26,
    "h1_leg1": 27,
}
ENDPOINT_ATTACHMENTS = {
    "sh1": "mh_leaf0",
    "h1_leg0": "mh_leaf0",
    "h1_leg1": "mh_leaf1",
    "h2_leg0": "mh_leaf0",
    "h2_leg1": "mh_leaf1",
}
# Keep immutable topology validation separate from the fixture's runtime-owned
# access set.  Pair 1 is stock active-active/Vlan1000 and is temporarily pinned
# upper for the one single-homed endpoint; the checkpoint restores its state.
STOCK_DISABLED_PAIRS = (0, 25, 26, 27)
FEATURE_PINNED_PAIRS = (0, 1, 25, 26, 27)
SERVICE_MODEL_PATH = Path(__file__).resolve().parent / "files" / "evpn_mh_service.yml"


class TopologyContractError(ValueError):
    """The testbed does not match the locked stock-topology contract."""


def _topology(tbinfo):
    try:
        return tbinfo["topo"]["properties"]["topology"]
    except (KeyError, TypeError) as error:
        raise TopologyContractError(
            "tbinfo is missing topo.properties.topology"
        ) from error


def _configuration(tbinfo):
    try:
        return tbinfo["topo"]["properties"]["configuration"]
    except (KeyError, TypeError) as error:
        raise TopologyContractError(
            "tbinfo is missing topo.properties.configuration"
        ) from error


def is_evpn_mh_topology(tbinfo):
    """Return whether ``tbinfo`` selects the one accepted topology name."""
    return tbinfo.get("topo", {}).get("name") == TOPOLOGY_NAME


def _split_host_pair(value):
    links = []
    for raw_link in str(value).split(","):
        fields = raw_link.strip().split("@", 1)[0].split(".", 1)
        if len(fields) != 2:
            raise TopologyContractError(
                "invalid dualtor host-interface entry {!r}".format(value)
            )
        links.append((int(fields[0]), int(fields[1])))
    return tuple(links)


def _explicit_ptf_index(value):
    text = str(value)
    if "@" not in text:
        raise TopologyContractError(
            "T1 link lacks an explicit PTF index: {!r}".format(value)
        )
    return int(text.rsplit("@", 1)[1])


def validate_stock_topology(tbinfo):
    """Validate every stock resource fact consumed by the fixture."""
    if not is_evpn_mh_topology(tbinfo):
        raise TopologyContractError(
            "EVPN-MH requires topo={} (selected {!r})".format(
                TOPOLOGY_NAME, tbinfo.get("topo", {}).get("name")
            )
        )
    topology = _topology(tbinfo)
    if int(topology.get("dut_num", -1)) != 2:
        raise TopologyContractError("dualtor-aa must contain exactly two DUTs")

    expected_hosts = ["0.{0},1.{0}".format(index) for index in range(28)]
    if list(topology.get("host_interfaces", ())) != expected_hosts:
        raise TopologyContractError(
            "dualtor-aa host pairs differ from the stock 0..27 layout"
        )
    expected_disabled = [
        "0.{0},1.{0}".format(index) for index in STOCK_DISABLED_PAIRS
    ]
    if list(topology.get("disabled_host_interfaces", ())) != expected_disabled:
        raise TopologyContractError("disabled pairs must be exactly 0,25,26,27")
    expected_active = ["0.{0},1.{0}".format(index) for index in range(1, 25)]
    if list(topology.get("host_interfaces_active_active", ())) != expected_active:
        raise TopologyContractError("active-active pairs must be exactly 1..24")

    vms = topology.get("VMs", {})
    if list(vms) != list(NEIGHBOR_NAMES.values()):
        raise TopologyContractError(
            "dualtor-aa must contain ARISTA01T1 through ARISTA04T1"
        )
    ptf_indexes = [
        _explicit_ptf_index(link)
        for vm in vms.values()
        for link in vm.get("vlans", ())
    ]
    if ptf_indexes != list(range(28, 36)):
        raise TopologyContractError("T1 PTF indexes must be exactly 28..35")

    vlan = (
        topology.get("DUT", {}).get("vlan_configs", {})
        .get("one_vlan_a", {}).get("Vlan1000", {})
    )
    if list(vlan.get("intfs", ())) != list(range(1, 25)):
        raise TopologyContractError("Vlan1000 must own only pairs 1..24")
    return topology


def _neighbor_host(value):
    """Unwrap the public ``nbrhosts`` NeighborDevice record."""
    if isinstance(value, dict) and "host" in value:
        return value["host"]
    try:
        return value["host"]
    except (KeyError, TypeError):
        return value


def resolve_dut_roles(duthosts, tbinfo):
    """Bind upper/lower ToRs to the two local EVPN-MH roles."""
    validate_stock_topology(tbinfo)
    hosts = list(duthosts)
    if len(hosts) != 2:
        raise TopologyContractError("exactly two duthost objects are required")
    if hosts[0] is hosts[1] or (
            getattr(hosts[0], "hostname", None)
            == getattr(hosts[1], "hostname", None)):
        raise TopologyContractError("upper and lower ToR resolved to one DUT")
    return {"mh_leaf0": hosts[0], "mh_leaf1": hosts[1]}


def resolve_neighbor_roles(nbrhosts, tbinfo):
    """Return the three underlay EOS peers and remote EOS leaf by role."""
    validate_stock_topology(tbinfo)
    missing = [name for name in NEIGHBOR_NAMES.values() if name not in nbrhosts]
    if missing:
        raise TopologyContractError(
            "missing EOS neighbors: {}".format(", ".join(missing))
        )
    return {
        role: _neighbor_host(nbrhosts[name])
        for role, name in NEIGHBOR_NAMES.items()
    }


def _used_ptf_indexes(topology):
    used = set(range(len(topology.get("host_interfaces", ()))))
    used.update(
        _explicit_ptf_index(link)
        for vm in topology.get("VMs", {}).values()
        for link in vm.get("vlans", ())
    )
    return used


def backplane_ptf_index(tbinfo):
    """Mirror stock PTF ``remote.py`` allocation for ``backplane``."""
    used = _used_ptf_indexes(validate_stock_topology(tbinfo))
    index = 1
    while index in used:
        index += 1
    return index


def resolve_ptf_ports(tbinfo):
    """Map semantic endpoints to existing PTF interfaces.

    H3 and H4 share ``backplane``; VLAN tags distinguish their attachments.
    """
    validate_stock_topology(tbinfo)
    backplane = backplane_ptf_index(tbinfo)
    ports = dict(ENDPOINT_PAIR_INDEX)
    ports.update({
        "h3": backplane,
        "h4": backplane,
        "backplane": backplane,
    })
    return ports


def load_service_model(path=SERVICE_MODEL_PATH):
    """Load and validate topology-independent protocol/service intent."""
    with Path(path).open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream)
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise TopologyContractError("service schema_version must be 1")
    properties = deepcopy(document.get("evpn_mh_service"))
    if not isinstance(properties, dict):
        raise TopologyContractError("service model lacks evpn_mh_service")
    required = (
        "overlay_asn", "remote_overlay_asn", "primary_test_segment", "l2vni",
        "remote_l2vni", "l3vni", "l3vni_vlan", "mh_ipv4_prefix",
        "remote_ipv4_prefix", "mh_ipv6_prefix", "remote_ipv6_prefix",
        "mh_vlan", "remote_vlan", "vrf", "anycast_gateway_mac",
        "endpoints", "ethernet_segments", "single_homed_endpoints",
    )
    missing = [key for key in required if key not in properties]
    if missing:
        raise TopologyContractError(
            "service model is missing: {}".format(", ".join(missing))
        )

    endpoints = properties["endpoints"]
    expected_endpoints = {"h1", "h2", "h3", "h4", "sh1"}
    if set(endpoints) != expected_endpoints:
        raise TopologyContractError(
            "endpoints must be exactly {}".format(
                ", ".join(sorted(expected_endpoints))))
    for family, prefix_keys in (
            ("ipv4", ("mh_ipv4_prefix", "remote_ipv4_prefix")),
            ("ipv6", ("mh_ipv6_prefix", "remote_ipv6_prefix"))):
        networks = [ipaddress.ip_network(properties[key]) for key in prefix_keys]
        for name, endpoint in endpoints.items():
            address = ipaddress.ip_address(endpoint[family])
            network = next((item for item in networks if address in item), None)
            if network is None:
                raise TopologyContractError(
                    "{} {} is outside declared prefixes".format(name, family)
                )
            endpoint["{}_prefixlen".format(family)] = network.prefixlen
    if endpoints["h3"].get("tagged_vlan") != int(properties["mh_vlan"]):
        raise TopologyContractError("H3 must be tagged on the local VLAN")
    if endpoints["h4"].get("tagged_vlan") != int(properties["remote_vlan"]):
        raise TopologyContractError("H4 must be tagged on the remote VLAN")
    single_homed = properties["single_homed_endpoints"]
    if set(single_homed) != {"sh1"}:
        raise TopologyContractError(
            "single_homed_endpoints must define exactly sh1")
    attachment = single_homed["sh1"]
    required_attachment = {
        "dut_role": "mh_leaf0",
        "ptf_port_role": "sh1",
        "vlan": int(properties["mh_vlan"]),
        "l2vni": int(properties["l2vni"]),
        "stock_vlan": 1000,
        "stock_mux_cable_type": "active-active",
    }
    for field, expected in required_attachment.items():
        value = attachment.get(field)
        if field in ("vlan", "l2vni", "stock_vlan"):
            try:
                value = int(value)
            except (TypeError, ValueError):
                value = None
        if value != expected:
            raise TopologyContractError(
                "sh1 single-homed {} must be {!r}".format(field, expected))
    properties["ethernet_segments"] = ethernet_segments(properties)
    primary = properties["primary_test_segment"]
    if primary not in properties["ethernet_segments"]:
        raise TopologyContractError(
            "primary_test_segment {!r} is not declared".format(primary))
    return properties


def _strip_prefix(value):
    return str(ipaddress.ip_interface(value).ip)


def _derive_vtep_addresses(tbinfo):
    loopbacks = _topology(tbinfo).get("DUT", {}).get("loopback", {}).get("ipv4", ())
    if len(loopbacks) != 2:
        raise TopologyContractError("two DUT Loopback0 IPv4 addresses are required")
    remote = (
        _configuration(tbinfo).get(NEIGHBOR_NAMES["remote_leaf"], {})
        .get("interfaces", {}).get("Loopback0", {}).get("ipv4")
    )
    if not remote:
        raise TopologyContractError("ARISTA04T1 lacks Loopback0 IPv4")
    return {
        "mh_leaf0": _strip_prefix(loopbacks[0]),
        "mh_leaf1": _strip_prefix(loopbacks[1]),
        "remote_leaf": _strip_prefix(remote),
    }


def _derive_underlay_peers(tbinfo):
    configuration = _configuration(tbinfo)
    peers = {role: [] for role in REQUIRED_DUT_ROLES}
    for neighbor_role in UNDERLAY_NEIGHBOR_ROLES:
        name = NEIGHBOR_NAMES[neighbor_role]
        interfaces = configuration.get(name, {}).get("interfaces", {})
        for dut_index, dut_role in enumerate(REQUIRED_DUT_ROLES, start=1):
            portchannel = interfaces.get("Port-Channel{}".format(dut_index), {})
            for family in ("ipv4", "ipv6"):
                value = portchannel.get(family)
                if not value:
                    raise TopologyContractError(
                        "{} Port-Channel{} lacks {}".format(
                            name, dut_index, family
                        )
                    )
                peers[dut_role].append(_strip_prefix(value))
    return peers


def evpn_mh_properties(tbinfo, service_model=None):
    """Augment validated service intent only with stock-derived facts."""
    validate_stock_topology(tbinfo)
    properties = (
        deepcopy(service_model) if service_model is not None else load_service_model()
    )
    properties["vtep_ip"] = _derive_vtep_addresses(tbinfo)
    properties["underlay_peers"] = _derive_underlay_peers(tbinfo)
    properties["underlay_neighbor_names"] = [
        NEIGHBOR_NAMES[role] for role in UNDERLAY_NEIGHBOR_ROLES
    ]
    properties["remote_neighbor_name"] = NEIGHBOR_NAMES["remote_leaf"]
    properties["topology_name"] = TOPOLOGY_NAME
    properties["ptf_backplane_index"] = backplane_ptf_index(tbinfo)
    properties["ethernet_segments"] = ethernet_segments(properties)
    return properties


def temporary_l3_orphan_endpoint(properties):
    """Build testcase 12's tagged orphan from service data."""
    explicit = properties.get("l3_orphan_endpoint")
    if explicit:
        endpoint = deepcopy(explicit)
    else:
        network = ipaddress.ip_network(properties["remote_ipv4_prefix"])
        used = {
            ipaddress.ip_address(value)
            for details in properties["endpoints"].values()
            for value in (details.get("ipv4"), details.get("gateway_ipv4"))
            if value
        }
        endpoint_address = None
        for offset in range(2, min(int(network.num_addresses) - 1, 256)):
            candidate = network.network_address + offset
            if candidate not in used:
                endpoint_address = candidate
                break
        if endpoint_address is None:
            raise TopologyContractError("no free address for the tagged orphan")
        vlan = int(properties["remote_vlan"])
        vni = int(properties["remote_l2vni"])
        endpoint = {
            "mac": "02:00:{:02x}:{:02x}:{:02x}:{:02x}".format(
                (vlan >> 8) & 0xff, vlan & 0xff,
                (vni >> 8) & 0xff, vni & 0xff,
            ),
            "ipv4": str(endpoint_address),
        }
    gateway = properties["endpoints"]["h4"].get("gateway_ipv4")
    network = ipaddress.ip_network(properties["remote_ipv4_prefix"])
    if not gateway or ipaddress.ip_address(gateway) not in network:
        raise TopologyContractError("H4 gateway is outside remote_ipv4_prefix")
    if ipaddress.ip_address(endpoint["ipv4"]) not in network:
        raise TopologyContractError("tagged orphan is outside remote_ipv4_prefix")
    endpoint.update({
        "gateway_ipv4": gateway,
        "ipv4_prefixlen": network.prefixlen,
        "vlan": int(properties["remote_vlan"]),
        "tagged_vlan": int(properties["remote_vlan"]),
        "traffic_only": True,
    })
    return endpoint


def ethernet_segments(properties):
    """Normalize and validate the test-owned Ethernet Segment definition."""
    segments = deepcopy(properties.get("ethernet_segments", {}))
    expected_segments = {"es_h1", "es_h2"}
    if set(segments) != expected_segments:
        raise TopologyContractError(
            "service model must define exactly es_h1 and es_h2")
    required = (
        "leaf_roles", "esi", "portchannel", "ptf_member_roles",
        "ptf_bond_interface", "ptf_host_interface", "ptf_system_mac",
        "endpoint", "system_mac", "vlan", "l2vni", "redundancy_mode",
    )
    expected_members = {
        "es_h1": ("h1_leg0", "h1_leg1"),
        "es_h2": ("h2_leg0", "h2_leg1"),
    }
    unique_fields = (
        "esi", "portchannel", "ptf_bond_interface", "ptf_host_interface",
        "ptf_system_mac", "system_mac", "endpoint",
    )
    seen = {field: set() for field in unique_fields}
    used_members = set()
    endpoints = properties.get("endpoints", {})
    for name, segment in segments.items():
        missing = [field for field in required if field not in segment]
        if missing:
            raise TopologyContractError(
                "{} is missing {}".format(name, ", ".join(missing))
            )
        if tuple(segment["leaf_roles"]) != REQUIRED_DUT_ROLES:
            raise TopologyContractError(
                "{} must bind the two SONiC roles".format(name))
        members = tuple(segment["ptf_member_roles"])
        if members != expected_members[name]:
            raise TopologyContractError(
                "{} must use member roles {}".format(
                    name, ", ".join(expected_members[name])))
        if used_members.intersection(members):
            raise TopologyContractError(
                "Ethernet Segment member roles must be disjoint")
        used_members.update(members)
        for member, leaf_role in zip(members, segment["leaf_roles"]):
            if ENDPOINT_ATTACHMENTS.get(member) != leaf_role:
                raise TopologyContractError(
                    "{} member {} is not attached to {}".format(
                        name, member, leaf_role))
        endpoint_name = segment["endpoint"]
        endpoint = endpoints.get(endpoint_name)
        if not endpoint or endpoint.get("attachment_role") != name:
            raise TopologyContractError(
                "{} endpoint {} has the wrong attachment".format(
                    name, endpoint_name))
        if endpoint.get("ptf_port_role") != segment["ptf_bond_interface"]:
            raise TopologyContractError(
                "{} endpoint PTF role must match its bond".format(name))
        if int(segment["vlan"]) != int(endpoint.get("vlan", -1)):
            raise TopologyContractError(
                "{} endpoint VLAN differs from the segment".format(name))
        if str(segment.get("redundancy_mode")) != "all-active":
            raise TopologyContractError(
                "{} must use all-active redundancy".format(name))
        for field in unique_fields:
            value = str(segment[field]).lower()
            if value in seen[field]:
                raise TopologyContractError(
                    "Ethernet Segment {} values must be unique".format(field))
            seen[field].add(value)
    if "sh1" in used_members:
        raise TopologyContractError(
            "single-homed sh1 must not be an Ethernet Segment member")
    member_pairs = [ENDPOINT_PAIR_INDEX[role] for role in used_members]
    if len(member_pairs) != len(set(member_pairs)):
        raise TopologyContractError(
            "Ethernet Segment members must use distinct PTF pairs")
    if ENDPOINT_PAIR_INDEX["sh1"] in member_pairs:
        raise TopologyContractError(
            "single-homed sh1 must use a PTF pair outside both segments")
    return segments


def _host_link_indexes(tbinfo):
    links = {}
    for ptf_index, pair in enumerate(_topology(tbinfo).get("host_interfaces", ())):
        for dut_index, port_index in _split_host_pair(pair):
            links[(dut_index, ptf_index)] = port_index
    return links


def _vm_link_indexes(tbinfo, neighbor_names):
    links = {name: {} for name in neighbor_names}
    for name in neighbor_names:
        for link in _topology(tbinfo)["VMs"][name].get("vlans", ()):
            dut_port = str(link).split("@", 1)[0]
            dut_index, port_index = dut_port.split(".", 1)
            links[name][int(dut_index)] = int(port_index)
    return links


def _running_port_facts(duthost, tbinfo):
    if hasattr(duthost, "get_extended_minigraph_facts"):
        facts = duthost.get_extended_minigraph_facts(tbinfo)
        if facts.get("minigraph_port_indices"):
            return facts
    result = duthost.config_facts(host=duthost.hostname, source="running")
    return result.get("ansible_facts", result)


def _port_name_by_index(facts, port_index):
    matches = []
    for index_map in (
            facts.get("minigraph_port_indices", {}),
            facts.get("port_index_map", {})):
        matches.extend(
            name for name, index in index_map.items()
            if int(index) == int(port_index)
        )
    if not matches:
        matches = [
            name for name, attrs in facts.get("PORT", {}).items()
            if int(attrs.get("index", -1)) == int(port_index)
        ]
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise TopologyContractError(
            "cannot resolve front-panel index {}".format(port_index)
        )
    return unique[0]


def resolve_dut_interfaces(duts, tbinfo, ptf_ports):
    """Resolve selected endpoint and T1 interfaces to physical DUT names."""
    validate_stock_topology(tbinfo)
    if set(duts) != set(REQUIRED_DUT_ROLES):
        raise TopologyContractError("DUT map must contain only the two MH leaves")
    facts_by_role = {
        role: _running_port_facts(duthost, tbinfo)
        for role, duthost in duts.items()
    }
    role_to_index = {"mh_leaf0": 0, "mh_leaf1": 1}
    host_links = _host_link_indexes(tbinfo)
    resolved = {}
    for endpoint, dut_role in ENDPOINT_ATTACHMENTS.items():
        ptf_index = int(ptf_ports[endpoint])
        dut_index = role_to_index[dut_role]
        port_index = host_links.get((dut_index, ptf_index))
        if port_index is None:
            raise TopologyContractError(
                "cannot resolve {} on {}".format(endpoint, dut_role)
            )
        resolved[endpoint] = {
            "dut_role": dut_role,
            "dut_index": dut_index,
            "ptf_index": ptf_index,
            "interface": _port_name_by_index(facts_by_role[dut_role], port_index),
        }

    underlay_names = [NEIGHBOR_NAMES[role] for role in UNDERLAY_NEIGHBOR_ROLES]
    underlay_links = _vm_link_indexes(tbinfo, underlay_names)
    remote_name = NEIGHBOR_NAMES["remote_leaf"]
    remote_links = _vm_link_indexes(tbinfo, (remote_name,))
    for dut_role, dut_index in role_to_index.items():
        resolved["{}_spine".format(dut_role)] = {
            "dut_role": dut_role,
            "interfaces": [
                _port_name_by_index(
                    facts_by_role[dut_role], underlay_links[name][dut_index]
                )
                for name in underlay_names
            ],
            "neighbors": list(underlay_names),
        }
        resolved["{}_remote_direct".format(dut_role)] = {
            "dut_role": dut_role,
            "interface": _port_name_by_index(
                facts_by_role[dut_role], remote_links[remote_name][dut_index]
            ),
            "neighbor": remote_name,
        }
    return resolved

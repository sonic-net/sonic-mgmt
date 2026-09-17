"""
Shared helpers for the disaggregated-T2 (UT2 / LT2, non-chassis) GCU neighbor tests.

Everything here is neighbor-centric: a ``neighbor_ctx`` (built by
``pick_target_neighbor``) describes one existing BGP neighbor, and the builders
derive per-neighbor GCU patches, expected CONFIG_DB state, route and traffic
checks from it. ``run_remove_and_readd_cycle`` is the flow shared by the uplink
(``test_add_t3.py``) and downstream (``test_add_downstream.py``) tests, which keep
only their scenario selection and fixtures. The generic CONFIG_DB formatting helpers
are imported from the chassis add-cluster suite rather than duplicated.
"""
import copy
import ipaddress
import json
import logging
import ptf.mask as mask
import ptf.packet as packet
import ptf.testutils as testutils
import pytest
from tests.common.config_reload import config_reload
from tests.common.gu_utils import apply_patch, delete_tmpfile, expect_op_success, generate_tmpfile
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import wait_until
from tests.generic_config_updater.add_cluster.helpers import (
    format_sonic_buffer_pg_dict,
    format_sonic_interface_dict,
    get_cfg_info_from_dut,
)

logger = logging.getLogger(__name__)
allure.logger = logger


def json_namespace_prefix(namespace):
    return "" if namespace is None else f"/{namespace}"


def vtysh_cmd(asic_index, cmd):
    if asic_index is None:
        return f'vtysh -c "{cmd}"'
    return f'vtysh -n {asic_index} -c "{cmd}"'


def run_json_cmd(duthost, cmd):
    out = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(out["rc"] == 0, f"Command failed: {cmd}\nstderr={out['stderr']}")
    stdout = out["stdout"].strip()
    pytest_assert(stdout, f"No output returned for command: {cmd}")
    return json.loads(stdout)


def get_local_asn(config_facts, mg_facts):
    for table_name in ("DEVICE_METADATA",):
        table = config_facts.get(table_name, {})
        localhost = table.get("localhost", {})
        for key in ("bgp_asn", "asn"):
            if localhost.get(key):
                return str(localhost[key])
    if mg_facts.get("minigraph_bgp_asn"):
        return str(mg_facts["minigraph_bgp_asn"])
    return None


def flatten_vrf_table(config_facts, table_name):
    """
    Rows of a BGP table keyed exactly as in CONFIG_DB. Newer images qualify the key with the
    VRF ("default|10.0.0.1", "default|10.0.0.1|ipv4_unicast"), and config_facts nests such
    keys as {vrf: {rest: row}}, so flatten them back; plain keys pass through.
    """
    flat = {}
    for key, value in (config_facts.get(table_name, {}) or {}).items():
        if isinstance(value, dict) and value and all(isinstance(row, dict) for row in value.values()):
            for rest, row in value.items():
                flat[f"{key}|{rest}"] = row
        else:
            flat[key] = value
    return flat


def bgp_neighbor_table(config_facts):
    return flatten_vrf_table(config_facts, "BGP_NEIGHBOR")


def bgp_neighbor_af_rows(config_facts, neighbor_ips):
    """
    BGP_NEIGHBOR_AF rows ("<vrf>|<ip>|<afi_safi>") of the given neighbor IPs. Present on
    images running the FRR management framework; they reference BGP_NEIGHBOR through a YANG
    leafref, so they must travel with the neighbor in every GCU patch.
    """
    ips = set(neighbor_ips)
    rows = {}
    for key, row in flatten_vrf_table(config_facts, "BGP_NEIGHBOR_AF").items():
        parts = key.split("|")
        if len(parts) >= 2 and parts[-2] in ips:
            rows[key] = row
    return rows


def bgp_key_ip(key):
    """Neighbor IP from a BGP_NEIGHBOR key, with or without a VRF prefix."""
    return key.rsplit("|", 1)[-1]


def find_neighbor_ports(config_facts, neighbor_name):
    ports = []
    for port, info in config_facts.get("DEVICE_NEIGHBOR", {}).items():
        if isinstance(info, dict) and info.get("name") == neighbor_name:
            ports.append(port)
    return ports


def pick_target_neighbor(config_facts, config_facts_localhost, mg_facts, scenario):
    local_asn = get_local_asn(config_facts, mg_facts)
    expected_types = set(scenario["device_types"])
    bgp_neighbors = bgp_neighbor_table(config_facts)
    keys_by_ip = {bgp_key_ip(key): key for key in bgp_neighbors}
    alias_map = mg_facts["minigraph_port_name_to_alias_map"]
    ips_by_name = {}
    for key, cfg in bgp_neighbors.items():
        name = cfg.get("name")
        if name:
            ips_by_name.setdefault(name, []).append(bgp_key_ip(key))
    candidates = []
    for neigh_key, neigh_cfg in bgp_neighbors.items():
        neigh_ip = bgp_key_ip(neigh_key)
        neigh_name = neigh_cfg.get("name")
        if not neigh_name:
            continue
        metadata = config_facts.get("DEVICE_NEIGHBOR_METADATA", {}).get(neigh_name, {})
        if not isinstance(metadata, dict):
            continue
        neigh_type = metadata.get("type")
        if neigh_type not in expected_types:
            continue
        ports = find_neighbor_ports(config_facts, neigh_name)
        if not ports:
            continue
        remote_asn = str(neigh_cfg.get("asn", "")) if neigh_cfg.get("asn") is not None else ""
        ebgp = local_asn is not None and remote_asn and remote_asn != str(local_asn)
        if scenario["expect_ebgp"] != ebgp:
            continue
        ports_sorted = sorted(ports)
        port = ports_sorted[0]
        port_localhost = port if port.startswith("PortChannel") else alias_map.get(port, port)
        candidates.append({
            "neighbor_ip": neigh_ip,
            "neighbor_name": neigh_name,
            "neighbor_ips": sorted(ips_by_name[neigh_name]),
            "port": port,
            "port_localhost": port_localhost,
            "all_ports": ports_sorted,
            "remote_asn": remote_asn,
            "ebgp": ebgp,
            "metadata": metadata,
            "device_type": neigh_type,
            "scenario_id": scenario["id"],
            "neighbor_role": scenario["neighbor_role"],
        })
    if not candidates:
        pytest.skip(
            f"No BGP neighbor found for scenario {scenario['id']} "
            f"(role={scenario['neighbor_role']}, "
            f"device_types={sorted(expected_types)}, "
            f"expect_ebgp={scenario['expect_ebgp']})",
        )
    candidates.sort(key=lambda c: (c["neighbor_name"], c["neighbor_ip"]))
    selected = candidates[0]
    is_portchannel = selected["port"].startswith("PortChannel")
    if is_portchannel:
        members = sorted(config_facts.get("PORTCHANNEL_MEMBER", {}).get(selected["port"], {}).keys())
        neighbor_ports = [selected["port"]]
        neighbor_ports_localhost = [selected["port_localhost"]]
    else:
        members = list(selected["all_ports"])
        neighbor_ports = list(selected["all_ports"])
        neighbor_ports_localhost = [alias_map.get(p, p) for p in selected["all_ports"]]
    selected["member_ports"] = members
    selected["neighbor_ports"] = neighbor_ports
    selected["neighbor_ports_localhost"] = neighbor_ports_localhost
    selected["is_portchannel"] = is_portchannel
    # CONFIG_DB keys per neighbor IP, for expectations and GCU patch paths.
    selected["bgp_keys"] = {ip: keys_by_ip[ip] for ip in selected["neighbor_ips"]}
    localhost_keys_by_ip = {bgp_key_ip(key): key for key in bgp_neighbor_table(config_facts_localhost)}
    selected["localhost_neighbor_ips"] = [ip for ip in selected["neighbor_ips"] if ip in localhost_keys_by_ip]
    selected["localhost_bgp_keys"] = {ip: localhost_keys_by_ip[ip] for ip in selected["localhost_neighbor_ips"]}
    selected["bgp_af_keys"] = sorted(bgp_neighbor_af_rows(config_facts, selected["neighbor_ips"]))
    selected["localhost_bgp_af_keys"] = sorted(
        bgp_neighbor_af_rows(config_facts_localhost, selected["localhost_neighbor_ips"])
    )
    logger.info("Selected neighbor context for %s: %s", scenario["id"], selected)
    return selected


def get_bgp_routes(duthost, asic_index, ip_version):
    cmd = "show ip route bgp json" if ip_version == 4 else "show ipv6 route bgp json"
    return run_json_cmd(duthost, vtysh_cmd(asic_index, cmd))


def get_received_prefixes(duthost, asic_index, neighbor_ip, ip_version):
    """
    Prefixes the DUT holds in its BGP table from ``neighbor_ip``. Empty when the neighbor
    does not exist (e.g. after the remove patch) or announces nothing.
    """
    afi = "ipv4" if ip_version == 4 else "ipv6"
    out = duthost.shell(vtysh_cmd(asic_index, f"show bgp {afi} unicast neighbors {neighbor_ip} routes json"),
                        module_ignore_errors=True)
    try:
        data = json.loads(out["stdout"].strip() or "{}")
    except json.JSONDecodeError:
        return set()
    return set((data.get("routes") or {}).keys()) if isinstance(data, dict) else set()


def forwarding_nexthops(route_body):
    """
    Next-hop IPs the FIB actually uses. Recursive entries (a third-party BGP next hop that is
    itself resolved through other neighbors) are skipped; their resolver entries are kept.
    """
    result = set()
    for path in route_body or []:
        for nh in path.get("nexthops", []) or []:
            if nh.get("recursive"):
                continue
            ip = nh.get("ip")
            if ip:
                result.add(ip)
    return result


def pick_prefix_for_neighbor(duthost, asic_index, neighbor_ctx, ip_version):
    """
    Select a prefix for route and forwarding checks. Returns None when nothing qualifies
    (callers treat IPv4 as mandatory and IPv6 as best-effort), otherwise a dict:
      prefix, dst_ip                 - the route and a host address inside it for probes
      ecmp                           - True when other neighbors share the forwarding path
      forwards_via_neighbor          - True when the FIB sends traffic out via this neighbor
    Preference: a prefix forwarded exclusively via the neighbor, then an ECMP prefix that
    includes it, then a prefix merely received from it. The last case happens when the
    neighbor announces a third-party next hop that the DUT resolves through other links
    (typical for a LowerSpineRouter on the single-node T2 topology): route presence is then
    checked in the BGP table and the dataplane check is skipped.
    """
    neighbor_ips = {ip for ip in neighbor_ctx["neighbor_ips"] if ipaddress.ip_address(ip).version == ip_version}
    too_narrow_prefixlen = 31 if ip_version == 4 else 127

    def usable(prefix):
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return None
        if network.version != ip_version or network.prefixlen >= too_narrow_prefixlen or network.prefixlen == 0:
            return None
        return network

    exclusive, ecmp = [], []
    for prefix, route_body in get_bgp_routes(duthost, asic_index, ip_version).items():
        network = usable(prefix)
        if network is None:
            continue
        nexthops = forwarding_nexthops(route_body)
        if not nexthops or not (nexthops & neighbor_ips):
            continue
        (exclusive if nexthops <= neighbor_ips else ecmp).append((network.prefixlen, prefix, network))
    for candidates, is_ecmp in ((exclusive, False), (ecmp, True)):
        if candidates:
            _, prefix, network = sorted(candidates)[0]
            logger.info("Using %s prefix %s forwarded via neighbor %s",
                        "ECMP" if is_ecmp else "exclusive", prefix, neighbor_ctx["neighbor_name"])
            return {"prefix": prefix, "dst_ip": str(next(network.hosts())), "ecmp": is_ecmp,
                    "forwards_via_neighbor": True}

    received = []
    for ip in sorted(neighbor_ips):
        for prefix in get_received_prefixes(duthost, asic_index, ip, ip_version):
            network = usable(prefix)
            if network is not None:
                received.append((network.prefixlen, prefix, network))
    if received:
        _, prefix, network = sorted(received)[0]
        logger.warning(
            "No IPv%d prefix is forwarded via neighbor %s; using received prefix %s for BGP-table "
            "checks only, dataplane checks for this family are skipped.",
            ip_version, neighbor_ctx["neighbor_name"], prefix,
        )
        return {"prefix": prefix, "dst_ip": str(next(network.hosts())), "ecmp": False,
                "forwards_via_neighbor": False}
    logger.warning("No IPv%d BGP prefix learned via neighbor %s (%s)",
                   ip_version, neighbor_ctx["neighbor_name"], sorted(neighbor_ips))
    return None


def verify_prefix_present(duthost, asic_index, target, neighbor_ctx, should_exist=True):
    """
    Route-level check for a target from pick_prefix_for_neighbor.
    * forwarded via the neighbor: the FIB path must include the neighbor (should_exist) or
      no longer include it (ECMP) / be gone entirely (exclusive) when not should_exist;
    * merely received: the prefix must be present in / absent from the BGP table entries
      received from the neighbor.
    """
    ip_version = ipaddress.ip_network(target["prefix"], strict=False).version
    neighbor_ips = {ip for ip in neighbor_ctx["neighbor_ips"] if ipaddress.ip_address(ip).version == ip_version}
    if not target["forwards_via_neighbor"]:
        present = any(target["prefix"] in get_received_prefixes(duthost, asic_index, ip, ip_version)
                      for ip in neighbor_ips)
        return present == should_exist
    route_body = get_bgp_routes(duthost, asic_index, ip_version).get(target["prefix"])
    via_neighbor = bool(route_body) and bool(forwarding_nexthops(route_body) & neighbor_ips)
    if should_exist:
        return via_neighbor
    return not via_neighbor if target["ecmp"] else not route_body


PROBE_FLOWS = 64


def verify_forwarding(tbinfo, duthost_up, src_asic_index, ptfadapter, neighbor_ctx, ptf_dst_ports, dst_ip,
                      expect_traffic, timeout=30):
    """
    Send PROBE_FLOWS distinct TCP flows towards dst_ip from a PTF port of the upstream DUT that
    is not one of the neighbor's links, and count arrivals on the neighbor's PTF ports.
    With expect_traffic at least one flow must egress via the neighbor: the prefix may be ECMP
    across several neighbors, so a single flow could legitimately hash elsewhere (64 flows over
    a 3-way ECMP miss the neighbor with probability (2/3)^64). Flows differ in source IP and
    TCP source port so they spread under both L3-only and L4 hashing, and carry TTL 2 so the
    neighbor cannot forward them back into the DUT (test prefixes are often reachable from the
    neighbor via the DUT itself, which would loop each probe and inflate the count). Without
    expect_traffic no flow may egress via the neighbor. Retried with wait_until so the ASIC has
    time to program.
    """
    ip_version = ipaddress.ip_address(dst_ip).version
    src_ns = None if src_asic_index is None else f"asic{src_asic_index}"
    router_mac = duthost_up.asic_instance(src_asic_index).get_router_mac()
    ptf_indices = duthost_up.get_extended_minigraph_facts(tbinfo, src_ns)["minigraph_ptf_indices"]
    excluded = set(neighbor_ctx["member_ports"])
    sources = sorted(idx for port, idx in ptf_indices.items() if port not in excluded and idx not in ptf_dst_ports)
    pytest_assert(sources, f"No PTF source port outside the links of neighbor {neighbor_ctx['neighbor_name']}")
    ptf_sport = sources[0]
    src_mac = ptfadapter.dataplane.get_mac(0, ptf_sport)

    def build(flow):
        if ip_version == 4:
            src_ip = str(ipaddress.ip_address("30.0.0.10") + flow)
            return testutils.simple_tcp_packet(eth_src=src_mac, eth_dst=router_mac, ip_src=src_ip,
                                               ip_dst=dst_ip, ip_ttl=2, tcp_sport=10000 + flow, tcp_dport=80)
        src_ip = str(ipaddress.ip_address("2001:db8::1") + flow)
        return testutils.simple_tcpv6_packet(eth_src=src_mac, eth_dst=router_mac, ipv6_src=src_ip,
                                             ipv6_dst=dst_ip, ipv6_hlim=2, tcp_sport=10000 + flow, tcp_dport=80)

    exp_pkt = mask.Mask(build(0))
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
    if ip_version == 4:
        exp_pkt.set_do_not_care_scapy(packet.IP, "src")
        exp_pkt.set_do_not_care_scapy(packet.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
    else:
        exp_pkt.set_do_not_care_scapy(packet.IPv6, "src")
        exp_pkt.set_do_not_care_scapy(packet.IPv6, "hlim")
    exp_pkt.set_do_not_care_scapy(packet.TCP, "sport")
    exp_pkt.set_do_not_care_scapy(packet.TCP, "chksum")

    def probe():
        ptfadapter.dataplane.flush()
        for flow in range(PROBE_FLOWS):
            testutils.send(ptfadapter, ptf_sport, build(flow), count=1)
        # Poll with exp_pkt rather than count_matched_packets_all_ports: the sonic-mgmt ptfadapter
        # stamps a per-test payload into every sent packet and applies the same stamp to exp_pkt
        # inside dp_poll, so a comparison made outside dp_poll never matches.
        received = 0
        while True:
            result = testutils.dp_poll(ptfadapter, device_number=0, timeout=2, exp_pkt=exp_pkt)
            if not isinstance(result, ptfadapter.dataplane.PollSuccess):
                break
            if result.port in ptf_dst_ports:
                received += 1
        logger.info("%d/%d flows to %s egressed via neighbor %s (PTF ports %s, from PTF port %s)",
                    received, PROBE_FLOWS, dst_ip, neighbor_ctx["neighbor_name"], ptf_dst_ports, ptf_sport)
        return received > 0 if expect_traffic else received == 0

    pytest_assert(
        wait_until(timeout, 5, 0, probe),
        "Expected {} traffic to {} via neighbor {} on PTF ports {}".format(
            "some" if expect_traffic else "no", dst_ip, neighbor_ctx["neighbor_name"], ptf_dst_ports,
        ),
    )


def append_remove_if_present(patch, path, table, key):
    if key in table:
        patch.append({"op": "remove", "path": f"{path}{key}"})


def aliasify_interface_dict(interface_dict, alias_map):
    """Translate asic-namespace INTERFACE keys (``Port`` or ``Port|IP``) to their
    localhost alias-based equivalents using the minigraph alias map."""
    result = {}
    for key, value in interface_dict.items():
        parts = key.split("|")
        if len(parts) == 2:
            alias = alias_map.get(parts[0], parts[0])
            result[f"{alias}|{parts[1]}"] = value
        else:
            result[alias_map.get(key, key)] = value
    return result


def normalize_acl_ports(ports):
    if ports is None:
        return []
    if isinstance(ports, str):
        return sorted([p.strip() for p in ports.split(",") if p.strip()])
    if isinstance(ports, (list, tuple, set)):
        return sorted(list(ports))
    return [ports]


def peer_port_targets(neighbor_ctx):
    return set(neighbor_ctx["neighbor_ports"]) | set(neighbor_ctx["member_ports"])


def matching_acl_tables(config_facts, neighbor_ctx):
    target_ports = peer_port_targets(neighbor_ctx)
    matching = {}
    for acl_name, acl_entry in config_facts.get("ACL_TABLE", {}).items():
        if not isinstance(acl_entry, dict):
            continue
        acl_ports = normalize_acl_ports(acl_entry.get("ports"))
        if target_ports.intersection(set(acl_ports)):
            normalized_entry = copy.deepcopy(acl_entry)
            if "ports" in normalized_entry:
                normalized_entry["ports"] = acl_ports
            matching[acl_name] = normalized_entry
    return matching


def filter_acl_entry_for_neighbor(acl_entry, neighbor_ctx):
    filtered = copy.deepcopy(acl_entry)
    remaining_ports = [
        p for p in normalize_acl_ports(filtered.get("ports"))
        if p not in peer_port_targets(neighbor_ctx)
    ]
    if not remaining_ports:
        return None
    filtered["ports"] = remaining_ports
    return filtered


def matching_pfc_wd_keys(config_facts, neighbor_ctx):
    targets = peer_port_targets(neighbor_ctx)
    return sorted(k for k in config_facts.get("PFC_WD", {}) if k in targets)


def normalize_table_data(table_name, raw_table):
    if not isinstance(raw_table, dict):
        return {}
    if table_name in ("INTERFACE", "PORTCHANNEL_INTERFACE", "PORTCHANNEL_MEMBER"):
        return format_sonic_interface_dict(
            raw_table, single_entry=(table_name != "PORTCHANNEL_MEMBER"),
        )
    if table_name == "ACL_TABLE":
        normalized = {}
        for key, value in raw_table.items():
            if not isinstance(value, dict):
                normalized[key] = value
                continue
            entry = copy.deepcopy(value)
            if "ports" in entry:
                entry["ports"] = normalize_acl_ports(entry["ports"])
            normalized[key] = entry
        return normalized
    return copy.deepcopy(raw_table)


def normalize_expected_value(table_name, value):
    if table_name == "ACL_TABLE" and isinstance(value, dict):
        entry = copy.deepcopy(value)
        if "ports" in entry:
            entry["ports"] = normalize_acl_ports(entry["ports"])
        return entry
    return copy.deepcopy(value)


def collect_interface_entries(config_facts, neighbor_ctx):
    interface_table = format_sonic_interface_dict(config_facts.get("INTERFACE", {}))
    expected = {}
    for p in neighbor_ctx["neighbor_ports"]:
        for key, value in interface_table.items():
            if key == p or key.startswith(f"{p}|"):
                expected[key] = value
    return expected


def collect_portchannel_interface_entries(config_facts, neighbor_ctx):
    if not neighbor_ctx["is_portchannel"]:
        return {}
    pc_if_table = format_sonic_interface_dict(config_facts.get("PORTCHANNEL_INTERFACE", {}))
    expected = {}
    for key, value in pc_if_table.items():
        if key == neighbor_ctx["port"] or key.startswith(f"{neighbor_ctx['port']}|"):
            expected[key] = value
    return expected


def collect_portchannel_member_entries(config_facts, neighbor_ctx):
    if not neighbor_ctx["is_portchannel"]:
        return {}
    pc_member_table = format_sonic_interface_dict(
        config_facts.get("PORTCHANNEL_MEMBER", {}), single_entry=False,
    )
    expected = {}
    for key, value in pc_member_table.items():
        if key.startswith(f"{neighbor_ctx['port']}|"):
            expected[key] = value
    return expected


def collect_buffer_pg_entries(config_facts, neighbor_ctx, include_lossless=True):
    buffer_pg_dict = format_sonic_buffer_pg_dict(config_facts.get("BUFFER_PG", {}))
    expected = {}
    for member in neighbor_ctx["member_ports"]:
        for key, value in buffer_pg_dict.items():
            if not key.startswith(f"{member}|"):
                continue
            if not include_lossless and isinstance(value, dict) and "profile" in value \
                    and "pg_lossless" in value["profile"]:
                continue
            expected[key] = value
    return expected


def collect_port_qos_entries(config_facts, neighbor_ctx):
    expected = {}
    for member in neighbor_ctx["member_ports"]:
        if member in config_facts.get("PORT_QOS_MAP", {}):
            expected[member] = copy.deepcopy(config_facts["PORT_QOS_MAP"][member])
    return expected


def collect_port_entries(config_facts, neighbor_ctx, admin_status=None):
    expected = {}
    for member in neighbor_ctx["member_ports"]:
        if member in config_facts.get("PORT", {}):
            value = copy.deepcopy(config_facts["PORT"][member])
            if admin_status is not None:
                value["admin_status"] = admin_status
            expected[member] = value
    return expected


def collect_cable_length_entries(config_facts, neighbor_ctx, override_value=None):
    azure = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {})
    expected = {}
    for member in neighbor_ctx["member_ports"]:
        if member in azure:
            expected[member] = override_value if override_value is not None else azure[member]
    return {"AZURE": expected} if expected else {}


def collect_pfc_wd_entries(config_facts, neighbor_ctx):
    expected = {}
    for key in matching_pfc_wd_keys(config_facts, neighbor_ctx):
        expected[key] = copy.deepcopy(config_facts["PFC_WD"][key])
    return expected


def build_add_expectations(config_facts, neighbor_ctx):
    expected_present = {}
    bgp_table = bgp_neighbor_table(config_facts)
    bgp = {
        key: copy.deepcopy(bgp_table[key])
        for key in neighbor_ctx["bgp_keys"].values()
        if key in bgp_table
    }
    if bgp:
        expected_present["BGP_NEIGHBOR"] = bgp
    bgp_af = bgp_neighbor_af_rows(config_facts, neighbor_ctx["neighbor_ips"])
    if bgp_af:
        expected_present["BGP_NEIGHBOR_AF"] = copy.deepcopy(bgp_af)
    device_neighbor = {
        p: copy.deepcopy(config_facts["DEVICE_NEIGHBOR"][p])
        for p in neighbor_ctx["neighbor_ports"]
        if p in config_facts.get("DEVICE_NEIGHBOR", {})
    }
    if device_neighbor:
        expected_present["DEVICE_NEIGHBOR"] = device_neighbor
    neigh_name = neighbor_ctx["neighbor_name"]
    if neigh_name in config_facts.get("DEVICE_NEIGHBOR_METADATA", {}):
        expected_present["DEVICE_NEIGHBOR_METADATA"] = {
            neigh_name: copy.deepcopy(config_facts["DEVICE_NEIGHBOR_METADATA"][neigh_name])
        }
    interface_entries = collect_interface_entries(config_facts, neighbor_ctx)
    if interface_entries:
        expected_present["INTERFACE"] = interface_entries
    portchannel_entries = {}
    if neighbor_ctx["is_portchannel"] and neighbor_ctx["port"] in config_facts.get("PORTCHANNEL", {}):
        portchannel_entries[neighbor_ctx["port"]] = copy.deepcopy(
            config_facts["PORTCHANNEL"][neighbor_ctx["port"]]
        )
    if portchannel_entries:
        expected_present["PORTCHANNEL"] = portchannel_entries
    portchannel_if_entries = collect_portchannel_interface_entries(config_facts, neighbor_ctx)
    if portchannel_if_entries:
        expected_present["PORTCHANNEL_INTERFACE"] = portchannel_if_entries
    portchannel_member_entries = collect_portchannel_member_entries(config_facts, neighbor_ctx)
    if portchannel_member_entries:
        expected_present["PORTCHANNEL_MEMBER"] = portchannel_member_entries
    buffer_pg_entries = collect_buffer_pg_entries(config_facts, neighbor_ctx, include_lossless=False)
    if buffer_pg_entries:
        expected_present["BUFFER_PG"] = buffer_pg_entries
    port_qos_entries = collect_port_qos_entries(config_facts, neighbor_ctx)
    if port_qos_entries:
        expected_present["PORT_QOS_MAP"] = port_qos_entries
    port_entries = collect_port_entries(config_facts, neighbor_ctx)
    if port_entries:
        expected_present["PORT"] = port_entries
    cable_length_entries = collect_cable_length_entries(config_facts, neighbor_ctx)
    if cable_length_entries:
        expected_present["CABLE_LENGTH"] = cable_length_entries
    pfc_wd_entries = collect_pfc_wd_entries(config_facts, neighbor_ctx)
    if pfc_wd_entries:
        expected_present["PFC_WD"] = pfc_wd_entries
    acl_entries = matching_acl_tables(config_facts, neighbor_ctx)
    if acl_entries:
        expected_present["ACL_TABLE"] = acl_entries
    return expected_present


def build_remove_expectations(config_facts, neighbor_ctx):
    expected_present = {}
    expected_absent = {}
    bgp_table = bgp_neighbor_table(config_facts)
    bgp_keys = {key for key in neighbor_ctx["bgp_keys"].values() if key in bgp_table}
    if bgp_keys:
        expected_absent["BGP_NEIGHBOR"] = bgp_keys
    if neighbor_ctx["bgp_af_keys"]:
        expected_absent["BGP_NEIGHBOR_AF"] = set(neighbor_ctx["bgp_af_keys"])
    device_neighbor_keys = {p for p in neighbor_ctx["neighbor_ports"] if p in config_facts.get("DEVICE_NEIGHBOR", {})}
    if device_neighbor_keys:
        expected_absent["DEVICE_NEIGHBOR"] = device_neighbor_keys
    neigh_name = neighbor_ctx["neighbor_name"]
    if neigh_name in config_facts.get("DEVICE_NEIGHBOR_METADATA", {}):
        expected_absent["DEVICE_NEIGHBOR_METADATA"] = {neigh_name}
    interface_keys = set(collect_interface_entries(config_facts, neighbor_ctx).keys())
    if interface_keys:
        expected_absent["INTERFACE"] = interface_keys
    portchannel_keys = set()
    if neighbor_ctx["is_portchannel"] and neighbor_ctx["port"] in config_facts.get("PORTCHANNEL", {}):
        portchannel_keys.add(neighbor_ctx["port"])
    if portchannel_keys:
        expected_absent["PORTCHANNEL"] = portchannel_keys
    portchannel_if_keys = set(collect_portchannel_interface_entries(config_facts, neighbor_ctx).keys())
    if portchannel_if_keys:
        expected_absent["PORTCHANNEL_INTERFACE"] = portchannel_if_keys
    portchannel_member_keys = set(collect_portchannel_member_entries(config_facts, neighbor_ctx).keys())
    if portchannel_member_keys:
        expected_absent["PORTCHANNEL_MEMBER"] = portchannel_member_keys
    # Lossless PGs are generated dynamically by buffermgrd and can reappear while the
    # patch is still settling, so only static entries are expected to be absent.
    buffer_pg_keys = set(collect_buffer_pg_entries(config_facts, neighbor_ctx, include_lossless=False).keys())
    if buffer_pg_keys:
        expected_absent["BUFFER_PG"] = buffer_pg_keys
    port_qos_keys = set(collect_port_qos_entries(config_facts, neighbor_ctx).keys())
    if port_qos_keys:
        expected_absent["PORT_QOS_MAP"] = port_qos_keys
    pfc_wd_keys = set(collect_pfc_wd_entries(config_facts, neighbor_ctx).keys())
    if pfc_wd_keys:
        expected_absent["PFC_WD"] = pfc_wd_keys
    port_entries = collect_port_entries(config_facts, neighbor_ctx, admin_status="down")
    if port_entries:
        expected_present["PORT"] = port_entries
    azure = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {})
    if azure:
        lowest_cable = "{}m".format(min(int(v.rstrip("m")) for v in azure.values()))
        cable_length_entries = collect_cable_length_entries(
            config_facts, neighbor_ctx, override_value=lowest_cable,
        )
        if cable_length_entries:
            expected_present["CABLE_LENGTH"] = cable_length_entries
    acl_present = {}
    acl_absent = set()
    for acl_name, acl_entry in matching_acl_tables(config_facts, neighbor_ctx).items():
        filtered = filter_acl_entry_for_neighbor(acl_entry, neighbor_ctx)
        if filtered is None:
            acl_absent.add(acl_name)
        else:
            acl_present[acl_name] = filtered
    if acl_present:
        expected_present["ACL_TABLE"] = acl_present
    if acl_absent:
        expected_absent["ACL_TABLE"] = acl_absent
    return expected_present, expected_absent


def assert_peer_config_state(duthost, namespace, neighbor_ctx, expected_present, expected_absent, phase):
    mismatches = []
    tables = set(expected_present.keys()) | set(expected_absent.keys())
    for table in tables:
        running = normalize_table_data(table, get_cfg_info_from_dut(duthost, table, namespace) or {})
        if table == "CABLE_LENGTH":
            expected_azure = expected_present.get("CABLE_LENGTH", {}).get("AZURE", {})
            running_azure = running.get("AZURE", {}) if isinstance(running, dict) else {}
            for key, expected_value in expected_azure.items():
                if key not in running_azure:
                    mismatches.append(f"{table}: expected present, missing {key}")
                    continue
                if running_azure[key] != expected_value:
                    mismatches.append(
                        f"{table}: key {key} expected {expected_value}, got {running_azure[key]}"
                    )
            for key in expected_absent.get("CABLE_LENGTH", set()):
                if key in running_azure:
                    mismatches.append(f"{table}: expected absent, still present {key}")
            continue
        for key, expected_value in expected_present.get(table, {}).items():
            if key not in running:
                mismatches.append(f"{table}: expected present, missing {key}")
                continue
            if normalize_expected_value(table, running[key]) != normalize_expected_value(table, expected_value):
                mismatches.append(
                    f"{table}: key {key} expected {normalize_expected_value(table, expected_value)}, "
                    f"got {normalize_expected_value(table, running[key])}"
                )
        for key in expected_absent.get(table, set()):
            if key in running:
                mismatches.append(f"{table}: expected absent, still present {key}")
    pytest_assert(
        not mismatches,
        "Peer {} CONFIG_DB state assertion failed during {}: {}".format(
            neighbor_ctx["neighbor_name"], phase, "; ".join(mismatches),
        ),
    )
    logger.info(
        "Peer %s CONFIG_DB state OK during %s. Checked tables: %s",
        neighbor_ctx["neighbor_name"], phase, sorted(tables),
    )


def build_remove_patch(config_facts, config_facts_localhost, mg_facts, namespace, neighbor_ctx):
    json_namespace = json_namespace_prefix(namespace)
    emit_localhost = namespace is not None
    patch_main = []
    patch_extra = []
    for key in neighbor_ctx["bgp_af_keys"]:
        patch_main.append({"op": "remove", "path": f"{json_namespace}/BGP_NEIGHBOR_AF/{key}"})
    bgp_table = bgp_neighbor_table(config_facts)
    for key in neighbor_ctx["bgp_keys"].values():
        append_remove_if_present(patch_main, f"{json_namespace}/BGP_NEIGHBOR/", bgp_table, key)
    if emit_localhost:
        for key in neighbor_ctx["localhost_bgp_af_keys"]:
            patch_main.append({"op": "remove", "path": f"/localhost/BGP_NEIGHBOR_AF/{key}"})
        localhost_bgp_table = bgp_neighbor_table(config_facts_localhost)
        for key in neighbor_ctx["localhost_bgp_keys"].values():
            append_remove_if_present(patch_main, "/localhost/BGP_NEIGHBOR/", localhost_bgp_table, key)
    neigh_name = neighbor_ctx["neighbor_name"]
    append_remove_if_present(
        patch_main,
        f"{json_namespace}/DEVICE_NEIGHBOR_METADATA/",
        config_facts.get("DEVICE_NEIGHBOR_METADATA", {}),
        neigh_name,
    )
    if emit_localhost:
        append_remove_if_present(
            patch_main,
            "/localhost/DEVICE_NEIGHBOR_METADATA/",
            config_facts_localhost.get("DEVICE_NEIGHBOR_METADATA", {}),
            neigh_name,
        )
    for acl_name, acl_entry in matching_acl_tables(config_facts, neighbor_ctx).items():
        filtered_acl_entry = filter_acl_entry_for_neighbor(acl_entry, neighbor_ctx)
        if filtered_acl_entry is None:
            append_remove_if_present(
                patch_main,
                f"{json_namespace}/ACL_TABLE/",
                config_facts.get("ACL_TABLE", {}),
                acl_name,
            )
        else:
            patch_main.append({
                "op": "add",
                "path": f"{json_namespace}/ACL_TABLE/{acl_name}/ports",
                "value": filtered_acl_entry["ports"],
            })
    for p in neighbor_ctx["neighbor_ports"]:
        append_remove_if_present(
            patch_main,
            f"{json_namespace}/DEVICE_NEIGHBOR/",
            config_facts.get("DEVICE_NEIGHBOR", {}),
            p.replace("/", "~1"),
        )
    if emit_localhost:
        for p in neighbor_ctx["neighbor_ports_localhost"]:
            append_remove_if_present(
                patch_main,
                "/localhost/DEVICE_NEIGHBOR/",
                config_facts_localhost.get("DEVICE_NEIGHBOR", {}),
                p.replace("/", "~1"),
            )
    interface_dict = format_sonic_interface_dict(config_facts.get("INTERFACE", {}))
    localhost_interface_dict = aliasify_interface_dict(
        interface_dict, mg_facts["minigraph_port_name_to_alias_map"],
    )
    interface_keys = []
    for p in neighbor_ctx["neighbor_ports"]:
        interface_keys.extend(
            k for k in interface_dict if k == p or k.startswith(f"{p}|")
        )
    localhost_interface_keys = []
    for p in neighbor_ctx["neighbor_ports_localhost"]:
        localhost_interface_keys.extend(
            k for k in localhost_interface_dict if k == p or k.startswith(f"{p}|")
        )
    for key in interface_keys:
        target = patch_main if "|" in key else patch_extra
        target.append({"op": "remove", "path": f"{json_namespace}/INTERFACE/{key.replace('/', '~1')}"})
    if emit_localhost:
        for key in localhost_interface_keys:
            target = patch_main if "|" in key else patch_extra
            target.append({"op": "remove", "path": f"/localhost/INTERFACE/{key.replace('/', '~1')}"})
    if neighbor_ctx["is_portchannel"]:
        pc_if_dict = format_sonic_interface_dict(config_facts.get("PORTCHANNEL_INTERFACE", {}))
        pc_member_dict = format_sonic_interface_dict(config_facts.get("PORTCHANNEL_MEMBER", {}), single_entry=False)
        for key in [k for k in pc_member_dict if k.startswith(f"{neighbor_ctx['port']}|")]:
            patch_main.append({"op": "remove", "path": f"{json_namespace}/PORTCHANNEL_MEMBER/{key.replace('/', '~1')}"})
        for key in [k for k in pc_if_dict if k == neighbor_ctx["port"] or k.startswith(f"{neighbor_ctx['port']}|")]:
            target = patch_main if "|" in key else patch_extra
            target.append({"op": "remove", "path": f"{json_namespace}/PORTCHANNEL_INTERFACE/{key.replace('/', '~1')}"})
        if neighbor_ctx["port"] in config_facts.get("PORTCHANNEL", {}):
            patch_extra.append({"op": "remove", "path": f"{json_namespace}/PORTCHANNEL/{neighbor_ctx['port']}"})
        if emit_localhost:
            localhost_pc_if_dict = format_sonic_interface_dict(
                config_facts_localhost.get("PORTCHANNEL_INTERFACE", {})
            )
            localhost_pc_member_dict = {}
            for key, value in format_sonic_interface_dict(
                config_facts_localhost.get("PORTCHANNEL_MEMBER", {}),
                single_entry=False,
            ).items():
                parts = key.split("|")
                if len(parts) == 2:
                    alias = mg_facts["minigraph_port_name_to_alias_map"].get(parts[1], parts[1])
                    localhost_pc_member_dict[f"{parts[0]}|{alias}"] = value
                else:
                    localhost_pc_member_dict[key] = value
            for key in [k for k in localhost_pc_member_dict if k.startswith(f"{neighbor_ctx['port_localhost']}|")]:
                patch_main.append({"op": "remove", "path": f"/localhost/PORTCHANNEL_MEMBER/{key.replace('/', '~1')}"})
            for key in [
                k for k in localhost_pc_if_dict
                if k == neighbor_ctx["port_localhost"] or k.startswith(f"{neighbor_ctx['port_localhost']}|")
            ]:
                target = patch_main if "|" in key else patch_extra
                target.append({"op": "remove", "path": f"/localhost/PORTCHANNEL_INTERFACE/{key.replace('/', '~1')}"})
            if neighbor_ctx["port_localhost"] in config_facts_localhost.get("PORTCHANNEL", {}):
                patch_extra.append({"op": "remove", "path": f"/localhost/PORTCHANNEL/{neighbor_ctx['port_localhost']}"})
    buffer_pg_dict = format_sonic_buffer_pg_dict(config_facts.get("BUFFER_PG", {}))
    azure = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {})
    lowest_cable = min(int(v.rstrip("m")) for v in azure.values()) if azure else None
    for member in neighbor_ctx["member_ports"]:
        for key in [k for k in buffer_pg_dict if k.startswith(f"{member}|")]:
            patch_main.append({"op": "remove", "path": f"{json_namespace}/BUFFER_PG/{key.replace('/', '~1')}"})
        if member in config_facts.get("PORT_QOS_MAP", {}):
            patch_main.append({"op": "remove", "path": f"{json_namespace}/PORT_QOS_MAP/{member}"})
        if member in config_facts.get("PFC_WD", {}):
            patch_main.append({"op": "remove", "path": f"{json_namespace}/PFC_WD/{member}"})
        patch_main.append({
            "op": "add",
            "path": f"{json_namespace}/PORT/{member}/admin_status",
            "value": "down",
        })
        if lowest_cable is not None and member in azure:
            patch_main.append({
                "op": "add",
                "path": f"{json_namespace}/CABLE_LENGTH/AZURE/{member}",
                "value": f"{lowest_cable}m",
            })
    return patch_main, patch_extra


def build_add_patches(config_facts, config_facts_localhost, mg_facts, namespace, neighbor_ctx):
    """
    Apply patch to add cluster information for a given ASIC namespace.
    Changes are performed to below tables:
    ACL_TABLE
    BGP_NEIGHBOR
    DEVICE_NEIGHBOR
    DEVICE_NEIGHBOR_METADATA
    PORTCHANNEL
    PORTCHANNEL_INTERFACE
    PORTCHANNEL_MEMBER
    INTERFACE
    BUFFER_PG
    CABLE_LENGTH
    PORT
    PORT_QOS_MAP
    """
    json_namespace = json_namespace_prefix(namespace)
    emit_localhost = namespace is not None
    patch_pc = []
    patch_rest = []
    if neighbor_ctx["is_portchannel"]:
        portchannel_value = {
            k: v for k, v in config_facts["PORTCHANNEL"][neighbor_ctx["port"]].items() if k != "members"
        }
        patch_pc.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL/{neighbor_ctx['port']}",
            "value": portchannel_value,
        })
        if emit_localhost and neighbor_ctx["port_localhost"] in config_facts_localhost.get("PORTCHANNEL", {}):
            localhost_pc_value = {
                k: v for k, v in config_facts_localhost["PORTCHANNEL"][neighbor_ctx["port_localhost"]].items()
                if k != "members"
            }
            patch_pc.append({
                "op": "add",
                "path": f"/localhost/PORTCHANNEL/{neighbor_ctx['port_localhost']}",
                "value": localhost_pc_value,
            })
    bgp_table = bgp_neighbor_table(config_facts)
    for key in neighbor_ctx["bgp_keys"].values():
        if key in bgp_table:
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/BGP_NEIGHBOR/{key}",
                "value": bgp_table[key],
            })
    for key, row in bgp_neighbor_af_rows(config_facts, neighbor_ctx["neighbor_ips"]).items():
        patch_rest.append({"op": "add", "path": f"{json_namespace}/BGP_NEIGHBOR_AF/{key}", "value": row})
    if emit_localhost:
        localhost_bgp_table = bgp_neighbor_table(config_facts_localhost)
        for key in neighbor_ctx["localhost_bgp_keys"].values():
            patch_rest.append({
                "op": "add",
                "path": f"/localhost/BGP_NEIGHBOR/{key}",
                "value": localhost_bgp_table[key],
            })
        for key, row in bgp_neighbor_af_rows(config_facts_localhost, neighbor_ctx["localhost_neighbor_ips"]).items():
            patch_rest.append({"op": "add", "path": f"/localhost/BGP_NEIGHBOR_AF/{key}", "value": row})
    neigh_name = neighbor_ctx["neighbor_name"]
    if neigh_name in config_facts.get("DEVICE_NEIGHBOR_METADATA", {}):
        patch_rest.append({
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA/{neigh_name}",
            "value": config_facts["DEVICE_NEIGHBOR_METADATA"][neigh_name],
        })
    if emit_localhost and neigh_name in config_facts_localhost.get("DEVICE_NEIGHBOR_METADATA", {}):
        patch_rest.append({
            "op": "add",
            "path": f"/localhost/DEVICE_NEIGHBOR_METADATA/{neigh_name}",
            "value": config_facts_localhost["DEVICE_NEIGHBOR_METADATA"][neigh_name],
        })
    for p in neighbor_ctx["neighbor_ports"]:
        if p in config_facts.get("DEVICE_NEIGHBOR", {}):
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/DEVICE_NEIGHBOR/{p.replace('/', '~1')}",
                "value": config_facts["DEVICE_NEIGHBOR"][p],
            })
    if emit_localhost:
        for p in neighbor_ctx["neighbor_ports_localhost"]:
            if p in config_facts_localhost.get("DEVICE_NEIGHBOR", {}):
                patch_rest.append({
                    "op": "add",
                    "path": f"/localhost/DEVICE_NEIGHBOR/{p.replace('/', '~1')}",
                    "value": config_facts_localhost["DEVICE_NEIGHBOR"][p],
                })
    interface_dict = format_sonic_interface_dict(config_facts.get("INTERFACE", {}))
    localhost_interface_dict = aliasify_interface_dict(
        interface_dict, mg_facts["minigraph_port_name_to_alias_map"],
    )
    interface_add_keys = []
    for p in neighbor_ctx["neighbor_ports"]:
        interface_add_keys.extend(
            k for k in interface_dict if k == p or k.startswith(f"{p}|")
        )
    for key in interface_add_keys:
        patch_rest.append({
            "op": "add",
            "path": f"{json_namespace}/INTERFACE/{key.replace('/', '~1')}",
            "value": interface_dict[key],
        })
    if emit_localhost:
        localhost_interface_add_keys = []
        for p in neighbor_ctx["neighbor_ports_localhost"]:
            localhost_interface_add_keys.extend(
                k for k in localhost_interface_dict if k == p or k.startswith(f"{p}|")
            )
        for key in localhost_interface_add_keys:
            patch_rest.append({
                "op": "add",
                "path": f"/localhost/INTERFACE/{key.replace('/', '~1')}",
                "value": localhost_interface_dict[key],
            })
    if neighbor_ctx["is_portchannel"]:
        pc_if_dict = format_sonic_interface_dict(config_facts.get("PORTCHANNEL_INTERFACE", {}))
        for key in [k for k in pc_if_dict if k == neighbor_ctx["port"] or k.startswith(f"{neighbor_ctx['port']}|")]:
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE/{key.replace('/', '~1')}",
                "value": pc_if_dict[key],
            })
        pc_member_dict = format_sonic_interface_dict(config_facts.get("PORTCHANNEL_MEMBER", {}), single_entry=False)
        for key in [k for k in pc_member_dict if k.startswith(f"{neighbor_ctx['port']}|")]:
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/PORTCHANNEL_MEMBER/{key.replace('/', '~1')}",
                "value": pc_member_dict[key],
            })
        if emit_localhost:
            localhost_pc_if_dict = format_sonic_interface_dict(
                config_facts_localhost.get("PORTCHANNEL_INTERFACE", {})
            )
            for key in [
                k for k in localhost_pc_if_dict
                if k == neighbor_ctx["port_localhost"] or k.startswith(f"{neighbor_ctx['port_localhost']}|")
            ]:
                patch_rest.append({
                    "op": "add",
                    "path": f"/localhost/PORTCHANNEL_INTERFACE/{key.replace('/', '~1')}",
                    "value": localhost_pc_if_dict[key],
                })
            localhost_pc_member_dict = format_sonic_interface_dict(
                config_facts_localhost.get("PORTCHANNEL_MEMBER", {}),
                single_entry=False,
            )
            for key, value in localhost_pc_member_dict.items():
                parts = key.split("|")
                normalized = key
                if len(parts) == 2:
                    alias = mg_facts["minigraph_port_name_to_alias_map"].get(parts[1], parts[1])
                    normalized = f"{parts[0]}|{alias}"
                if normalized.startswith(f"{neighbor_ctx['port_localhost']}|"):
                    patch_rest.append({
                        "op": "add",
                        "path": f"/localhost/PORTCHANNEL_MEMBER/{normalized.replace('/', '~1')}",
                        "value": value,
                    })
    buffer_pg_dict = format_sonic_buffer_pg_dict(config_facts.get("BUFFER_PG", {}))
    azure = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {})
    for member in neighbor_ctx["member_ports"]:
        for key in [k for k in buffer_pg_dict if k.startswith(f"{member}|")]:
            value = buffer_pg_dict[key]
            if isinstance(value, dict) and "profile" in value and "pg_lossless" in value["profile"]:
                continue
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/BUFFER_PG/{key.replace('/', '~1')}",
                "value": value,
            })
        if member in config_facts.get("PORT_QOS_MAP", {}):
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/PORT_QOS_MAP/{member}",
                "value": config_facts["PORT_QOS_MAP"][member],
            })
        if member in config_facts.get("PFC_WD", {}):
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/PFC_WD/{member}",
                "value": config_facts["PFC_WD"][member],
            })
        patch_rest.append({
            "op": "add",
            "path": f"{json_namespace}/PORT/{member}/admin_status",
            "value": "up",
        })
        if member in azure:
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/CABLE_LENGTH/AZURE/{member}",
                "value": azure[member],
            })
    for acl_name, acl_entry in matching_acl_tables(config_facts, neighbor_ctx).items():
        patch_rest.append({
            "op": "add",
            "path": f"{json_namespace}/ACL_TABLE/{acl_name}",
            "value": acl_entry,
        })
    return patch_pc, patch_rest


def compute_egress_ptf_ports(dst_mg_facts, neighbor_ctx):
    ptf_indices = dst_mg_facts["minigraph_ptf_indices"]
    member_ports = neighbor_ctx["member_ports"]
    ptf_dst_interfaces = [p for p in member_ports if p in ptf_indices]
    ptf_dst_ports = [ptf_indices[p] for p in ptf_dst_interfaces]
    pytest_assert(
        ptf_dst_ports,
        "No PTF indices found for neighbor member ports {} (neighbor={})".format(
            member_ports, neighbor_ctx["neighbor_name"]
        ),
    )
    logger.info(
        "Egress PTF ports for neighbor %s (role=%s, type=%s): "
        "dst_ports=%s dst_interfaces=%s",
        neighbor_ctx["neighbor_name"],
        neighbor_ctx["neighbor_role"],
        neighbor_ctx.get("device_type"),
        ptf_dst_ports,
        ptf_dst_interfaces,
    )
    return ptf_dst_ports, ptf_dst_interfaces


def pick_upstream_src_asic(duthost_up, duthost_dst, dst_asic):
    asic_ids = sorted(duthost_up.get_asic_ids() or [])
    if duthost_up.hostname != duthost_dst.hostname:
        return asic_ids[0] if asic_ids else None
    if not asic_ids:
        return None
    other = [a for a in asic_ids if a != dst_asic]
    return other[0] if other else dst_asic


def apply_patch_or_assert(duthost, patch):
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


# -----------------------------
# Scenarios and shared test flow
# -----------------------------

# Expected, benign syslog errors while a neighbor's ports / LAG are torn down and re-created
# via GCU. On VoQ (DNX) platforms syncd logs at ERR while the TC-to-VOQ map of a re-created
# port is not programmed yet. Shared by every test in this directory.
LOGANALYZER_IGNORE_REGEX = [
    r"querySwitchLagHashAttrCapabilities",
    r"SRV6.*unsupported",
    r"brcm_sai_dnx_get_tc_to_voqid.*No voq map for port",
]

# Uplink (T3) neighbors of a UT2. AZNGHub and RegionalHub differ in PFC, cable length and
# MACsec, so they are separate scenarios; each skips when the testbed has no such neighbor.
T3_SCENARIOS = [
    {"id": "ah", "neighbor_role": "AH", "device_types": ["AZNGHub"], "expect_ebgp": True},
    {"id": "rh", "neighbor_role": "RH", "device_types": ["RegionalHub"], "expect_ebgp": True},
]

# Downstream neighbors: the LowerSpineRouter when the DUT is a UT2, the T1 LeafRouter when
# the DUT is an LT2 (the non-chassis counterpart of the chassis add-cluster test).
DOWNSTREAM_SCENARIOS = [
    {"id": "lt2", "neighbor_role": "LT2", "device_types": ["LowerSpineRouter"], "expect_ebgp": True},
    {"id": "t1", "neighbor_role": "T1", "device_types": ["LeafRouter"], "expect_ebgp": True},
]


def run_remove_and_readd_cycle(
    tbinfo,
    duthosts,
    ptfadapter,
    loganalyzer,
    dut_hostname,
    upstream_dut_hostname,
    asic_index,
    namespace,
    mg_facts,
    config_facts,
    config_facts_localhost,
    scenario,
    neighbor_ctx,
):
    """
    Remove one existing BGP neighbor via GCU and add it back, verifying CONFIG_DB, routes and
    forwarding through the cycle. Shared by the uplink (T3) and downstream tests.

      1. Find one IPv4 prefix reachable through the neighbor (mandatory) and one IPv6
         prefix (best-effort: when none qualifies the IPv6 checks are skipped).
      2. Baseline: BGP established, expected CONFIG_DB state, prefixes present, traffic
         forwarded towards them.
      3. Remove the neighbor via a two-stage GCU JSON patch; assert: neighbor config removed
         from all relevant tables, PORT/CABLE_LENGTH reflect the reduced state, the prefixes
         are withdrawn and traffic towards them is dropped.
      4. Re-add the same neighbor via GCU; assert: config restored across the same tables,
         the prefixes are relearned and traffic recovers.
      5. ``config save`` on success; ``config_reload`` always runs in ``finally`` so a
         mid-test failure never leaves the DUT with the neighbor removed.
    """
    duthost = duthosts[dut_hostname]
    dut_basic_facts = duthost.dut_basic_facts()["ansible_facts"]["dut_basic_facts"]
    if dut_basic_facts.get("is_chassis"):
        pytest.skip("Disaggregated-T2 neighbor remove/re-add workflow is skipped on chassis systems")
    duthost_up = duthosts[upstream_dut_hostname]
    dst_asic = asic_index
    pytest_assert(
        neighbor_ctx["device_type"] in scenario["device_types"],
        "Scenario {} expected device_type in {}, got {} for neighbor {}".format(
            scenario["id"],
            scenario["device_types"],
            neighbor_ctx["device_type"],
            neighbor_ctx["neighbor_name"],
        ),
    )
    logger.info(
        "scenario=%s role=%s: GCU remove-and-readd of cluster peer %s "
        "(device_type=%s, ebgp=%s, ports=%s)",
        scenario["id"],
        scenario["neighbor_role"],
        neighbor_ctx["neighbor_name"],
        neighbor_ctx["device_type"],
        neighbor_ctx["ebgp"],
        neighbor_ctx["neighbor_ports"],
    )
    src_asic_on_upstream = pick_upstream_src_asic(duthost_up, duthost, dst_asic)
    logger.info(
        "Ingress ASIC on upstream DUT %s for peer path to %s: %s "
        "(dst DUT=%s asic=%s)",
        duthost_up.hostname, neighbor_ctx["neighbor_name"],
        src_asic_on_upstream, duthost.hostname, dst_asic,
    )

    target_v4 = pick_prefix_for_neighbor(duthost, dst_asic, neighbor_ctx, ip_version=4)
    pytest_assert(target_v4, f"No IPv4 BGP prefix learned via neighbor {neighbor_ctx['neighbor_name']}")
    target_v6 = pick_prefix_for_neighbor(duthost, dst_asic, neighbor_ctx, ip_version=6)
    targets = [t for t in (target_v4, target_v6) if t]
    forwarded = [t for t in targets if t["forwards_via_neighbor"]]
    ptf_dst_ports, _ = compute_egress_ptf_ports(mg_facts, neighbor_ctx)

    expected_add_state = build_add_expectations(config_facts, neighbor_ctx)
    expected_remove_present, expected_remove_absent = build_remove_expectations(config_facts, neighbor_ctx)

    def check_routes(should_exist, timeout, phase):
        for target in targets:
            pytest_assert(
                wait_until(timeout, 5, 0, verify_prefix_present, duthost, dst_asic, target, neighbor_ctx, should_exist),
                "Prefix {} via neighbor {} {} {}".format(
                    target["prefix"], neighbor_ctx["neighbor_name"],
                    "missing" if should_exist else "still present", phase,
                ),
            )

    def check_forwarding(expect_traffic):
        for target in forwarded:
            verify_forwarding(tbinfo, duthost_up, src_asic_on_upstream, ptfadapter, neighbor_ctx,
                              ptf_dst_ports, target["dst_ip"], expect_traffic)

    with allure.step(
        f"[{scenario['id']}] Verify selected {neighbor_ctx['neighbor_role']} "
        f"neighbor and learned prefix before removal"
    ):
        # Control-plane gate: Wait for BGP sessions to establish
        logger.info("Waiting for BGP neighbor sessions to establish")
        bgp_ok = wait_until(120, 10, 0, duthost.check_bgp_session_state, neighbor_ctx["neighbor_ips"])
        pytest_assert(bgp_ok, f"BGP sessions with neighbors {neighbor_ctx['neighbor_ips']} failed to establish")

        assert_peer_config_state(
            duthost,
            namespace,
            neighbor_ctx,
            expected_add_state,
            {},
            "pre-remove baseline",
        )
        check_routes(True, 30, "before removal")
        check_forwarding(True)

    la_entry = loganalyzer[duthost.hostname] if loganalyzer else None
    if la_entry:
        la_entry.ignore_regex.extend(LOGANALYZER_IGNORE_REGEX)
    try:
        with allure.step(
            f"[{scenario['id']}] Remove selected cluster peer via GCU and validate route withdrawal / traffic loss"
        ):
            remove_patch_main, remove_patch_extra = build_remove_patch(
                config_facts,
                config_facts_localhost,
                mg_facts,
                namespace,
                neighbor_ctx,
            )
            apply_patch_or_assert(duthost, remove_patch_main)
            if remove_patch_extra:
                apply_patch_or_assert(duthost, remove_patch_extra)
            assert_peer_config_state(
                duthost,
                namespace,
                neighbor_ctx,
                expected_remove_present,
                expected_remove_absent,
                "post-remove",
            )
            check_routes(False, 60, "after removing the neighbor")
            check_forwarding(False)

        with allure.step(
            f"[{scenario['id']}] Add selected cluster peer back via GCU and validate route / traffic recovery"
        ):
            patch_pc, patch_rest = build_add_patches(
                config_facts,
                config_facts_localhost,
                mg_facts,
                namespace,
                neighbor_ctx,
            )
            if patch_pc:
                apply_patch_or_assert(duthost, patch_pc)
            apply_patch_or_assert(duthost, patch_rest)
            assert_peer_config_state(
                duthost,
                namespace,
                neighbor_ctx,
                expected_add_state,
                {},
                "post-add",
            )

            # Control-plane gate: Wait for BGP sessions to establish
            logger.info("Waiting for BGP neighbor sessions to establish after re-add")
            bgp_up = wait_until(
                120, 10, 0,
                duthost.check_bgp_session_state,
                neighbor_ctx["neighbor_ips"],
            )
            pytest_assert(
                bgp_up,
                f"BGP sessions with neighbors {neighbor_ctx['neighbor_ips']} failed to establish after re-add",
            )
            check_routes(True, 120, "after re-adding the neighbor")
            check_forwarding(True)

        with allure.step(f"[{scenario['id']}] Persist the restored configuration"):
            duthost.shell("config save -y")
    finally:
        # Reload the last persisted configuration even when a validation fails after the
        # peer has been removed. Only the reload window is hidden from the loganalyzer.
        if la_entry:
            la_entry.add_start_ignore_mark()
        try:
            config_reload(duthost, config_source="config_db", safe_reload=True)
        finally:
            if la_entry:
                la_entry.add_end_ignore_mark()

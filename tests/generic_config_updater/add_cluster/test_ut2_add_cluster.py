import copy
import ipaddress
import json
import logging
import random

import ptf.mask as mask
import ptf.packet as packet
import ptf.testutils as testutils
import pytest

from tests.common.config_reload import config_reload
from tests.common.gu_utils import apply_patch, delete_tmpfile, expect_op_success, generate_tmpfile
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import wait_until
from tests.generic_config_updater.add_cluster.test_add_cluster import (
    format_sonic_buffer_pg_dict,
    format_sonic_interface_dict,
)
from tests.generic_config_updater.add_cluster.helpers import (
    get_cfg_info_from_dut,
    send_and_verify_traffic,
)

pytestmark = [
    pytest.mark.topology("ut2", "t2"),
]

logger = logging.getLogger(__name__)
allure.logger = logger

UT2_SCENARIOS = [
    {
        "id": "ut2_rh_ah_ebgp",
        "neighbor_role": "RH_AH",
        "device_types": ["RegionalHub", "AZNGHub"],
        "expect_ebgp": True
    },
    {
        "id": "ut2_lt2_ebgp",
        "neighbor_role": "LT2",
        "device_types": ["LowerSpineRouter"],
        "expect_ebgp": True
    },
]


def _json_namespace(namespace):
    return "" if namespace is None else f"/{namespace}"


def _vtysh_cmd(asic_index, cmd):
    if asic_index is None:
        return f'vtysh -c "{cmd}"'
    return f'vtysh -n {asic_index} -c "{cmd}"'


def _run_json_cmd(duthost, cmd):
    out = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(out["rc"] == 0, f"Command failed: {cmd}\nstderr={out['stderr']}")
    stdout = out["stdout"].strip()
    pytest_assert(stdout, f"No output returned for command: {cmd}")
    return json.loads(stdout)


def _get_local_asn(config_facts, mg_facts):
    for table_name in ("DEVICE_METADATA",):
        table = config_facts.get(table_name, {})
        localhost = table.get("localhost", {})
        for key in ("bgp_asn", "asn"):
            if localhost.get(key):
                return str(localhost[key])
    if mg_facts.get("minigraph_bgp_asn"):
        return str(mg_facts["minigraph_bgp_asn"])
    return None


def _find_neighbor_ports(config_facts, neighbor_name):
    ports = []
    for port, info in config_facts.get("DEVICE_NEIGHBOR", {}).items():
        if isinstance(info, dict) and info.get("name") == neighbor_name:
            ports.append(port)
    return ports


def _pick_target_neighbor(config_facts, config_facts_localhost, mg_facts, scenario):
    local_asn = _get_local_asn(config_facts, mg_facts)
    expected_types = set(scenario["device_types"])
    bgp_neighbors = config_facts.get("BGP_NEIGHBOR", {})
    alias_map = mg_facts["minigraph_port_name_to_alias_map"]

    ips_by_name = {}
    for ip, cfg in bgp_neighbors.items():
        name = cfg.get("name")
        if name:
            ips_by_name.setdefault(name, []).append(ip)

    candidates = []
    for neigh_ip, neigh_cfg in bgp_neighbors.items():
        neigh_name = neigh_cfg.get("name")
        if not neigh_name:
            continue

        metadata = config_facts.get("DEVICE_NEIGHBOR_METADATA", {}).get(neigh_name, {})
        if not isinstance(metadata, dict):
            continue
        neigh_type = metadata.get("type")
        if neigh_type not in expected_types:
            continue

        ports = _find_neighbor_ports(config_facts, neigh_name)
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

    pytest_assert(
        candidates,
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

    localhost_bgp = config_facts_localhost.get("BGP_NEIGHBOR", {})
    selected["localhost_neighbor_ips"] = [ip for ip in selected["neighbor_ips"] if ip in localhost_bgp]

    logger.info("Selected neighbor context for %s: %s", scenario["id"], selected)
    return selected


def _get_bgp_routes(duthost, asic_index, ip_version):
    cmd = "show ip route bgp json" if ip_version == 4 else "show ipv6 route bgp json"
    return _run_json_cmd(duthost, _vtysh_cmd(asic_index, cmd))


def _prefix_has_nexthop(route_body, neighbor_ips):
    for path in route_body or []:
        for nh in path.get("nexthops", []) or []:
            ip = nh.get("ip")
            if ip and ip in neighbor_ips:
                return True
    return False


def _prefix_only_via_neighbor(route_body, neighbor_ips):
    seen = False
    for path in route_body or []:
        for nh in path.get("nexthops", []) or []:
            ip = nh.get("ip")
            if not ip:
                continue
            if ip not in neighbor_ips:
                return False
            seen = True
    return seen


def _pick_prefix_for_neighbor(duthost, asic_index, neighbor_ctx, ip_version):
    routes = _get_bgp_routes(duthost, asic_index, ip_version)
    neighbor_ips = set(neighbor_ctx["neighbor_ips"])
    too_narrow_prefixlen = 31 if ip_version == 4 else 127

    candidates = []
    for prefix, route_body in routes.items():
        if not _prefix_only_via_neighbor(route_body, neighbor_ips):
            continue
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if network.version != ip_version or network.prefixlen >= too_narrow_prefixlen:
            continue
        dst_ip = str(next(network.hosts()))
        candidates.append((network.prefixlen, prefix, dst_ip))

    if not candidates:
        msg = (
            f"No IPv{ip_version} BGP prefix learned ONLY via neighbor "
            f"{neighbor_ctx['neighbor_name']} ({sorted(neighbor_ips)})"
        )
        if ip_version == 6:
            pytest.skip(msg + " — IPv6 BGP may not be configured for this peer on this testbed")
        pytest_assert(
            False, msg + ", withdrawing this peer would not uniquely remove any route.",
        )

    candidates.sort(key=lambda item: item[0])
    _prefixlen, prefix, dst_ip = candidates[0]
    logger.info(
        "Using IPv%d prefix %s (dst_ip=%s) uniquely learned via neighbor %s",
        ip_version, prefix, dst_ip, neighbor_ctx["neighbor_name"],
    )
    return prefix, dst_ip


def _verify_prefix_present(duthost, asic_index, prefix, neighbor_ctx, should_exist=True):
    ip_version = ipaddress.ip_network(prefix, strict=False).version
    routes = _get_bgp_routes(duthost, asic_index, ip_version)
    route_body = routes.get(prefix)
    exists = bool(route_body and _prefix_has_nexthop(route_body, set(neighbor_ctx["neighbor_ips"])))
    return exists if should_exist else not exists


def _send_v6_and_verify(tbinfo, src_duthost, src_asic_index, ptfadapter,
                        ptf_dst_ports, dst_ip, count=100, expect_error=False):
    src_ns = None if src_asic_index is None else "asic{}".format(src_asic_index)
    router_mac = src_duthost.asic_instance(src_asic_index).get_router_mac()
    src_mg_facts = src_duthost.get_extended_minigraph_facts(tbinfo, src_ns)
    ptf_sport = random.choice(list(src_mg_facts["minigraph_ptf_indices"].values()))

    pkt = testutils.simple_tcpv6_packet(
        eth_src=ptfadapter.dataplane.get_mac(0, ptf_sport),
        eth_dst=router_mac,
        ipv6_src="2001:db8::1",
        ipv6_dst=dst_ip,
        ipv6_hlim=64,
    )
    exp_pkt = mask.Mask(pkt.copy())
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
    exp_pkt.set_do_not_care_scapy(packet.IPv6, "hlim")

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_sport, pkt, count=count)

    if expect_error:
        with pytest.raises(AssertionError):
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_ports)
    else:
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_ports)


def _append_remove_if_present(patch, path, table, key):
    if key in table:
        patch.append({"op": "remove", "path": f"{path}{key}"})


def _aliasify_interface_dict(interface_dict, alias_map):
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


def _normalize_acl_ports(ports):
    if ports is None:
        return []
    if isinstance(ports, str):
        return sorted([p.strip() for p in ports.split(",") if p.strip()])
    if isinstance(ports, (list, tuple, set)):
        return sorted(list(ports))
    return [ports]


def _peer_port_targets(neighbor_ctx):
    return set(neighbor_ctx["neighbor_ports"]) | set(neighbor_ctx["member_ports"])


def _matching_acl_tables(config_facts, neighbor_ctx):
    target_ports = _peer_port_targets(neighbor_ctx)
    matching = {}
    for acl_name, acl_entry in config_facts.get("ACL_TABLE", {}).items():
        if not isinstance(acl_entry, dict):
            continue
        acl_ports = _normalize_acl_ports(acl_entry.get("ports"))
        if target_ports.intersection(set(acl_ports)):
            normalized_entry = copy.deepcopy(acl_entry)
            if "ports" in normalized_entry:
                normalized_entry["ports"] = acl_ports
            matching[acl_name] = normalized_entry
    return matching


def _filter_acl_entry_for_neighbor(acl_entry, neighbor_ctx):
    filtered = copy.deepcopy(acl_entry)
    remaining_ports = [
        p for p in _normalize_acl_ports(filtered.get("ports"))
        if p not in _peer_port_targets(neighbor_ctx)
    ]
    if not remaining_ports:
        return None
    filtered["ports"] = remaining_ports
    return filtered


def _matching_pfc_wd_keys(config_facts, neighbor_ctx):
    targets = _peer_port_targets(neighbor_ctx)
    return sorted(k for k in config_facts.get("PFC_WD", {}) if k in targets)


def _normalize_table_data(table_name, raw_table):
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
                entry["ports"] = _normalize_acl_ports(entry["ports"])
            normalized[key] = entry
        return normalized

    return copy.deepcopy(raw_table)


def _normalize_expected_value(table_name, value):
    if table_name == "ACL_TABLE" and isinstance(value, dict):
        entry = copy.deepcopy(value)
        if "ports" in entry:
            entry["ports"] = _normalize_acl_ports(entry["ports"])
        return entry
    return copy.deepcopy(value)


def _collect_interface_entries(config_facts, neighbor_ctx):
    interface_table = format_sonic_interface_dict(config_facts.get("INTERFACE", {}))
    expected = {}
    for p in neighbor_ctx["neighbor_ports"]:
        for key, value in interface_table.items():
            if key == p or key.startswith(f"{p}|"):
                expected[key] = value
    return expected


def _collect_portchannel_interface_entries(config_facts, neighbor_ctx):
    if not neighbor_ctx["is_portchannel"]:
        return {}
    pc_if_table = format_sonic_interface_dict(config_facts.get("PORTCHANNEL_INTERFACE", {}))
    expected = {}
    for key, value in pc_if_table.items():
        if key == neighbor_ctx["port"] or key.startswith(f"{neighbor_ctx['port']}|"):
            expected[key] = value
    return expected


def _collect_portchannel_member_entries(config_facts, neighbor_ctx):
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


def _collect_buffer_pg_entries(config_facts, neighbor_ctx, include_lossless=True):
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


def _collect_port_qos_entries(config_facts, neighbor_ctx):
    expected = {}
    for member in neighbor_ctx["member_ports"]:
        if member in config_facts.get("PORT_QOS_MAP", {}):
            expected[member] = copy.deepcopy(config_facts["PORT_QOS_MAP"][member])
    return expected


def _collect_port_entries(config_facts, neighbor_ctx, admin_status=None):
    expected = {}
    for member in neighbor_ctx["member_ports"]:
        if member in config_facts.get("PORT", {}):
            value = copy.deepcopy(config_facts["PORT"][member])
            if admin_status is not None:
                value["admin_status"] = admin_status
            expected[member] = value
    return expected


def _collect_cable_length_entries(config_facts, neighbor_ctx, override_value=None):
    azure = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {})
    expected = {}
    for member in neighbor_ctx["member_ports"]:
        if member in azure:
            expected[member] = override_value if override_value is not None else azure[member]
    return {"AZURE": expected} if expected else {}


def _collect_pfc_wd_entries(config_facts, neighbor_ctx):
    expected = {}
    for key in _matching_pfc_wd_keys(config_facts, neighbor_ctx):
        expected[key] = copy.deepcopy(config_facts["PFC_WD"][key])
    return expected


def _build_add_expectations(config_facts, neighbor_ctx):
    expected_present = {}

    bgp = {
        ip: copy.deepcopy(config_facts["BGP_NEIGHBOR"][ip])
        for ip in neighbor_ctx["neighbor_ips"]
        if ip in config_facts.get("BGP_NEIGHBOR", {})
    }
    if bgp:
        expected_present["BGP_NEIGHBOR"] = bgp

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

    interface_entries = _collect_interface_entries(config_facts, neighbor_ctx)
    if interface_entries:
        expected_present["INTERFACE"] = interface_entries

    portchannel_entries = {}
    if neighbor_ctx["is_portchannel"] and neighbor_ctx["port"] in config_facts.get("PORTCHANNEL", {}):
        portchannel_entries[neighbor_ctx["port"]] = copy.deepcopy(
            config_facts["PORTCHANNEL"][neighbor_ctx["port"]]
        )
    if portchannel_entries:
        expected_present["PORTCHANNEL"] = portchannel_entries

    portchannel_if_entries = _collect_portchannel_interface_entries(config_facts, neighbor_ctx)
    if portchannel_if_entries:
        expected_present["PORTCHANNEL_INTERFACE"] = portchannel_if_entries

    portchannel_member_entries = _collect_portchannel_member_entries(config_facts, neighbor_ctx)
    if portchannel_member_entries:
        expected_present["PORTCHANNEL_MEMBER"] = portchannel_member_entries

    buffer_pg_entries = _collect_buffer_pg_entries(config_facts, neighbor_ctx, include_lossless=False)
    if buffer_pg_entries:
        expected_present["BUFFER_PG"] = buffer_pg_entries

    port_qos_entries = _collect_port_qos_entries(config_facts, neighbor_ctx)
    if port_qos_entries:
        expected_present["PORT_QOS_MAP"] = port_qos_entries

    port_entries = _collect_port_entries(config_facts, neighbor_ctx)
    if port_entries:
        expected_present["PORT"] = port_entries

    cable_length_entries = _collect_cable_length_entries(config_facts, neighbor_ctx)
    if cable_length_entries:
        expected_present["CABLE_LENGTH"] = cable_length_entries

    pfc_wd_entries = _collect_pfc_wd_entries(config_facts, neighbor_ctx)
    if pfc_wd_entries:
        expected_present["PFC_WD"] = pfc_wd_entries

    acl_entries = _matching_acl_tables(config_facts, neighbor_ctx)
    if acl_entries:
        expected_present["ACL_TABLE"] = acl_entries

    return expected_present


def _build_remove_expectations(config_facts, neighbor_ctx):
    expected_present = {}
    expected_absent = {}

    bgp_keys = {ip for ip in neighbor_ctx["neighbor_ips"] if ip in config_facts.get("BGP_NEIGHBOR", {})}
    if bgp_keys:
        expected_absent["BGP_NEIGHBOR"] = bgp_keys

    device_neighbor_keys = {p for p in neighbor_ctx["neighbor_ports"] if p in config_facts.get("DEVICE_NEIGHBOR", {})}
    if device_neighbor_keys:
        expected_absent["DEVICE_NEIGHBOR"] = device_neighbor_keys

    neigh_name = neighbor_ctx["neighbor_name"]
    if neigh_name in config_facts.get("DEVICE_NEIGHBOR_METADATA", {}):
        expected_absent["DEVICE_NEIGHBOR_METADATA"] = {neigh_name}

    interface_keys = set(_collect_interface_entries(config_facts, neighbor_ctx).keys())
    if interface_keys:
        expected_absent["INTERFACE"] = interface_keys

    portchannel_keys = set()
    if neighbor_ctx["is_portchannel"] and neighbor_ctx["port"] in config_facts.get("PORTCHANNEL", {}):
        portchannel_keys.add(neighbor_ctx["port"])
    if portchannel_keys:
        expected_absent["PORTCHANNEL"] = portchannel_keys

    portchannel_if_keys = set(_collect_portchannel_interface_entries(config_facts, neighbor_ctx).keys())
    if portchannel_if_keys:
        expected_absent["PORTCHANNEL_INTERFACE"] = portchannel_if_keys

    portchannel_member_keys = set(_collect_portchannel_member_entries(config_facts, neighbor_ctx).keys())
    if portchannel_member_keys:
        expected_absent["PORTCHANNEL_MEMBER"] = portchannel_member_keys

    buffer_pg_keys = set(_collect_buffer_pg_entries(config_facts, neighbor_ctx, include_lossless=True).keys())
    if buffer_pg_keys:
        expected_absent["BUFFER_PG"] = buffer_pg_keys

    port_qos_keys = set(_collect_port_qos_entries(config_facts, neighbor_ctx).keys())
    if port_qos_keys:
        expected_absent["PORT_QOS_MAP"] = port_qos_keys

    pfc_wd_keys = set(_collect_pfc_wd_entries(config_facts, neighbor_ctx).keys())
    if pfc_wd_keys:
        expected_absent["PFC_WD"] = pfc_wd_keys

    port_entries = _collect_port_entries(config_facts, neighbor_ctx, admin_status="down")
    if port_entries:
        expected_present["PORT"] = port_entries

    azure = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {})
    if azure:
        lowest_cable = "{}m".format(min(int(v.rstrip("m")) for v in azure.values()))
        cable_length_entries = _collect_cable_length_entries(
            config_facts, neighbor_ctx, override_value=lowest_cable,
        )
        if cable_length_entries:
            expected_present["CABLE_LENGTH"] = cable_length_entries

    acl_present = {}
    acl_absent = set()
    for acl_name, acl_entry in _matching_acl_tables(config_facts, neighbor_ctx).items():
        filtered = _filter_acl_entry_for_neighbor(acl_entry, neighbor_ctx)
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
        running = _normalize_table_data(table, get_cfg_info_from_dut(duthost, table, namespace) or {})

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
            if _normalize_expected_value(table, running[key]) != _normalize_expected_value(table, expected_value):
                mismatches.append(
                    f"{table}: key {key} expected {_normalize_expected_value(table, expected_value)}, "
                    f"got {_normalize_expected_value(table, running[key])}"
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


def _build_remove_patch(config_facts, config_facts_localhost, mg_facts, namespace, neighbor_ctx):
    json_namespace = _json_namespace(namespace)
    emit_localhost = namespace is not None
    patch_main = []
    patch_extra = []

    for neigh_ip in neighbor_ctx["neighbor_ips"]:
        _append_remove_if_present(
            patch_main, f"{json_namespace}/BGP_NEIGHBOR/", config_facts.get("BGP_NEIGHBOR", {}), neigh_ip,
        )
    if emit_localhost:
        for neigh_ip in neighbor_ctx["localhost_neighbor_ips"]:
            _append_remove_if_present(
                patch_main, "/localhost/BGP_NEIGHBOR/", config_facts_localhost.get("BGP_NEIGHBOR", {}), neigh_ip,
            )

    neigh_name = neighbor_ctx["neighbor_name"]
    _append_remove_if_present(
        patch_main,
        f"{json_namespace}/DEVICE_NEIGHBOR_METADATA/",
        config_facts.get("DEVICE_NEIGHBOR_METADATA", {}),
        neigh_name,
    )
    if emit_localhost:
        _append_remove_if_present(
            patch_main,
            "/localhost/DEVICE_NEIGHBOR_METADATA/",
            config_facts_localhost.get("DEVICE_NEIGHBOR_METADATA", {}),
            neigh_name,
        )

    for acl_name, acl_entry in _matching_acl_tables(config_facts, neighbor_ctx).items():
        filtered_acl_entry = _filter_acl_entry_for_neighbor(acl_entry, neighbor_ctx)
        if filtered_acl_entry is None:
            _append_remove_if_present(
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
        _append_remove_if_present(
            patch_main,
            f"{json_namespace}/DEVICE_NEIGHBOR/",
            config_facts.get("DEVICE_NEIGHBOR", {}),
            p.replace("/", "~1"),
        )
    if emit_localhost:
        for p in neighbor_ctx["neighbor_ports_localhost"]:
            _append_remove_if_present(
                patch_main,
                "/localhost/DEVICE_NEIGHBOR/",
                config_facts_localhost.get("DEVICE_NEIGHBOR", {}),
                p.replace("/", "~1"),
            )

    interface_dict = format_sonic_interface_dict(config_facts.get("INTERFACE", {}))
    localhost_interface_dict = _aliasify_interface_dict(
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


def _build_add_patches(config_facts, config_facts_localhost, mg_facts, namespace, neighbor_ctx):
    """
    Apply patch to add cluster information for a given ASIC namespace.

    Changes are perfomed to below tables:

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
    json_namespace = _json_namespace(namespace)
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

    for neigh_ip in neighbor_ctx["neighbor_ips"]:
        if neigh_ip in config_facts.get("BGP_NEIGHBOR", {}):
            patch_rest.append({
                "op": "add",
                "path": f"{json_namespace}/BGP_NEIGHBOR/{neigh_ip}",
                "value": config_facts["BGP_NEIGHBOR"][neigh_ip],
            })
    if emit_localhost:
        for neigh_ip in neighbor_ctx["localhost_neighbor_ips"]:
            patch_rest.append({
                "op": "add",
                "path": f"/localhost/BGP_NEIGHBOR/{neigh_ip}",
                "value": config_facts_localhost["BGP_NEIGHBOR"][neigh_ip],
            })

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
    localhost_interface_dict = _aliasify_interface_dict(
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

    for acl_name, acl_entry in _matching_acl_tables(config_facts, neighbor_ctx).items():
        patch_rest.append({
            "op": "add",
            "path": f"{json_namespace}/ACL_TABLE/{acl_name}",
            "value": acl_entry,
        })

    return patch_pc, patch_rest


def _compute_egress_ptf_ports(dst_mg_facts, neighbor_ctx):
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


def _pick_upstream_src_asic(duthost_up, duthost_dst, dst_asic):
    asic_ids = sorted(duthost_up.get_asic_ids() or [])

    if duthost_up.hostname != duthost_dst.hostname:
        return asic_ids[0] if asic_ids else None

    if not asic_ids:
        return None
    other = [a for a in asic_ids if a != dst_asic]
    return other[0] if other else dst_asic


def _apply_patch_or_assert(duthost, patch):
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.fixture(scope="function")
def initialize_random_variables(
    enum_downstream_dut_hostname,
    enum_upstream_dut_hostname,
    enum_rand_one_frontend_asic_index,
    enum_rand_one_asic_namespace,
    ip_netns_namespace_prefix,
    cli_namespace_prefix,
):
    return (
        enum_downstream_dut_hostname,
        enum_upstream_dut_hostname,
        enum_rand_one_frontend_asic_index,
        enum_rand_one_asic_namespace,
        ip_netns_namespace_prefix,
        cli_namespace_prefix,
    )


@pytest.fixture(scope="function")
def initialize_facts(mg_facts, config_facts, config_facts_localhost):
    return mg_facts, config_facts, config_facts_localhost


@pytest.fixture(scope="function", params=UT2_SCENARIOS, ids=[s["id"] for s in UT2_SCENARIOS])
def ut2_scenario(request):
    return request.param


@pytest.fixture(scope="function")
def selected_ut2_neighbor(initialize_facts, config_facts_localhost, ut2_scenario):
    mg_facts, config_facts, _ = initialize_facts
    return _pick_target_neighbor(config_facts, config_facts_localhost, mg_facts, ut2_scenario)


def test_ut2_remove_and_readd_cluster_peer(
    tbinfo,
    duthosts,
    ptfadapter,
    loganalyzer,
    initialize_random_variables,
    initialize_facts,
    ut2_scenario,
    selected_ut2_neighbor,
):
    """
    Remove-and-readd-existing-cluster-peer test for add-cluster GCU coverage on UT2 / T2.

    Per parametrized scenario:
      1. Select an existing BGP neighbor of the expected type
         (RegionalHub / AZNGHub for RH_AH, LowerSpineRouter for LT2).
      2. Find one IPv4 prefix AND one IPv6 prefix each reachable ONLY through that neighbor.
         If no qualifying IPv6 prefix exists the test is skipped gracefully.
      3. Assert baseline: peer-related add-cluster CONFIG_DB state present, both prefixes
         present, IPv4 and IPv6 dataplane traffic flowing.
      4. Remove the peer via a two-stage GCU JSON patch; assert: cluster-peer config removed
         from all relevant tables, PORT/CABLE_LENGTH reflect the reduced state, both prefixes
         withdrawn, both traffic directions lost.
      5. Re-add the same peer via GCU; assert: cluster-peer config restored across the same
         tables, both prefixes relearned, both traffic directions recovered.
      6. ``config save`` + ``config_reload`` to leave the DUT in a clean state.
    """
    (
        enum_downstream_dut_hostname,
        enum_upstream_dut_hostname,
        enum_rand_one_frontend_asic_index,
        enum_rand_one_asic_namespace,
        _ip_netns_namespace_prefix,
        _cli_namespace_prefix,
    ) = initialize_random_variables
    mg_facts, config_facts, config_facts_localhost = initialize_facts

    duthost = duthosts[enum_downstream_dut_hostname]
    dut_basic_facts = duthost.dut_basic_facts()["ansible_facts"]["dut_basic_facts"]
    if dut_basic_facts.get("is_chassis"):
        pytest.skip("UT2 add-cluster peer workflow is skipped on chassis systems")

    duthost_up = duthosts[enum_upstream_dut_hostname]
    dst_asic = enum_rand_one_frontend_asic_index

    neighbor_ctx = selected_ut2_neighbor

    pytest_assert(
        neighbor_ctx["device_type"] in ut2_scenario["device_types"],
        "Scenario {} expected device_type in {}, got {} for neighbor {}".format(
            ut2_scenario["id"],
            ut2_scenario["device_types"],
            neighbor_ctx["device_type"],
            neighbor_ctx["neighbor_name"],
        ),
    )
    logger.info(
        "[MSFT-49] scenario=%s role=%s: GCU remove-and-readd of cluster peer %s "
        "(device_type=%s, ebgp=%s, ports=%s)",
        ut2_scenario["id"],
        ut2_scenario["neighbor_role"],
        neighbor_ctx["neighbor_name"],
        neighbor_ctx["device_type"],
        neighbor_ctx["ebgp"],
        neighbor_ctx["neighbor_ports"],
    )

    src_asic_on_upstream = _pick_upstream_src_asic(duthost_up, duthost, dst_asic)
    logger.info(
        "Ingress ASIC on upstream DUT %s for peer path to %s: %s "
        "(dst DUT=%s asic=%s)",
        duthost_up.hostname, neighbor_ctx["neighbor_name"],
        src_asic_on_upstream, duthost.hostname, dst_asic,
    )

    prefix, dst_ip = _pick_prefix_for_neighbor(duthost, dst_asic, neighbor_ctx, ip_version=4)
    prefix_v6, dst_ip_v6 = _pick_prefix_for_neighbor(duthost, dst_asic, neighbor_ctx, ip_version=6)
    ptf_dst_ports, ptf_dst_interfaces = _compute_egress_ptf_ports(mg_facts, neighbor_ctx)

    expected_add_state = _build_add_expectations(config_facts, neighbor_ctx)
    expected_remove_present, expected_remove_absent = _build_remove_expectations(config_facts, neighbor_ctx)

    with allure.step(
        f"[{ut2_scenario['id']}] Verify selected {neighbor_ctx['neighbor_role']} "
        f"neighbor and learned prefix before removal"
    ):
        assert_peer_config_state(
            duthost,
            enum_rand_one_asic_namespace,
            neighbor_ctx,
            expected_add_state,
            {},
            "pre-remove baseline",
        )
        pytest_assert(
            _verify_prefix_present(duthost, dst_asic, prefix, neighbor_ctx, should_exist=True),
            f"Expected learned IPv4 prefix {prefix} from neighbor {neighbor_ctx['neighbor_name']} before removal",
        )
        pytest_assert(
            _verify_prefix_present(duthost, dst_asic, prefix_v6, neighbor_ctx, should_exist=True),
            f"Expected learned IPv6 prefix {prefix_v6} from neighbor {neighbor_ctx['neighbor_name']} before removal",
        )
        send_and_verify_traffic(
            tbinfo,
            duthost_up,
            duthost,
            src_asic_on_upstream,
            dst_asic,
            ptfadapter,
            ptf_sport=None,
            ptf_dst_ports=ptf_dst_ports,
            ptf_dst_interfaces=ptf_dst_interfaces,
            dst_ip=dst_ip,
            count=100,
            expect_error=False,
        )
        _send_v6_and_verify(
            tbinfo, duthost_up, src_asic_on_upstream, ptfadapter,
            ptf_dst_ports, dst_ip_v6, count=100, expect_error=False,
        )

    la_entry = loganalyzer[duthost.hostname] if loganalyzer else None
    if la_entry:
        la_entry.ignore_regex.extend([
            r"querySwitchLagHashAttrCapabilities",
            r"SRV6.*unsupported",
        ])
        logger.info("Disabling loganalyzer before starting cluster peer remove/add/reload flow.")
        la_entry.add_start_ignore_mark()
    try:
        with allure.step(
            f"[{ut2_scenario['id']}] Remove selected cluster peer via GCU and validate route withdrawal / traffic loss"
        ):
            remove_patch_main, remove_patch_extra = _build_remove_patch(
                config_facts,
                config_facts_localhost,
                mg_facts,
                enum_rand_one_asic_namespace,
                neighbor_ctx,
            )
            _apply_patch_or_assert(duthost, remove_patch_main)
            if remove_patch_extra:
                _apply_patch_or_assert(duthost, remove_patch_extra)
            assert_peer_config_state(
                duthost,
                enum_rand_one_asic_namespace,
                neighbor_ctx,
                expected_remove_present,
                expected_remove_absent,
                "post-remove",
            )
            pytest_assert(
                wait_until(60, 5, 0, _verify_prefix_present, duthost, dst_asic, prefix, neighbor_ctx, False),
                f"IPv4 prefix {prefix} still present after removing neighbor {neighbor_ctx['neighbor_name']}",
            )
            pytest_assert(
                wait_until(60, 5, 0, _verify_prefix_present, duthost, dst_asic, prefix_v6, neighbor_ctx, False),
                f"IPv6 prefix {prefix_v6} still present after removing neighbor {neighbor_ctx['neighbor_name']}",
            )
            send_and_verify_traffic(
                tbinfo,
                duthost_up,
                duthost,
                src_asic_on_upstream,
                dst_asic,
                ptfadapter,
                ptf_sport=None,
                ptf_dst_ports=ptf_dst_ports,
                ptf_dst_interfaces=ptf_dst_interfaces,
                dst_ip=dst_ip,
                count=100,
                expect_error=True,
            )
            _send_v6_and_verify(
                tbinfo, duthost_up, src_asic_on_upstream, ptfadapter,
                ptf_dst_ports, dst_ip_v6, count=100, expect_error=True,
            )

        with allure.step(
            f"[{ut2_scenario['id']}] Add selected cluster peer back via GCU and validate route / traffic recovery"
        ):
            patch_pc, patch_rest = _build_add_patches(
                config_facts,
                config_facts_localhost,
                mg_facts,
                enum_rand_one_asic_namespace,
                neighbor_ctx,
            )
            if patch_pc:
                _apply_patch_or_assert(duthost, patch_pc)
            _apply_patch_or_assert(duthost, patch_rest)
            assert_peer_config_state(
                duthost,
                enum_rand_one_asic_namespace,
                neighbor_ctx,
                expected_add_state,
                {},
                "post-add",
            )
            pytest_assert(
                wait_until(120, 5, 0, _verify_prefix_present, duthost, dst_asic, prefix, neighbor_ctx, True),
                f"IPv4 prefix {prefix} did not return after re-adding neighbor {neighbor_ctx['neighbor_name']}",
            )
            pytest_assert(
                wait_until(120, 5, 0, _verify_prefix_present, duthost, dst_asic, prefix_v6, neighbor_ctx, True),
                f"IPv6 prefix {prefix_v6} did not return after re-adding neighbor {neighbor_ctx['neighbor_name']}",
            )
            send_and_verify_traffic(
                tbinfo,
                duthost_up,
                duthost,
                src_asic_on_upstream,
                dst_asic,
                ptfadapter,
                ptf_sport=None,
                ptf_dst_ports=ptf_dst_ports,
                ptf_dst_interfaces=ptf_dst_interfaces,
                dst_ip=dst_ip,
                count=100,
                expect_error=False,
            )
            _send_v6_and_verify(
                tbinfo, duthost_up, src_asic_on_upstream, ptfadapter,
                ptf_dst_ports, dst_ip_v6, count=100, expect_error=False,
            )

        with allure.step(f"[{ut2_scenario['id']}] Return DUT to a clean persisted state"):
            duthost.shell("config save -y")
            config_reload(duthost, config_source="config_db", safe_reload=True)
    finally:
        if la_entry:
            logger.info("Re-enabling loganalyzer after cluster peer remove/add/reload flow.")
            la_entry.add_end_ignore_mark()

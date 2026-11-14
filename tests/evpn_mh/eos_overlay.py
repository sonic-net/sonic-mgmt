"""Reversible EOS underlay and remote-EVPN overlay for stock dualtor-aa.

The four stock T1 VMs remain EOS neighbors.  ARISTA01T1--ARISTA03T1 are
fixture-owned transit paths and ARISTA04T1 is the remote EVPN/VXLAN leaf.  No
EOS object is treated as a SONiC ``duthost`` and no SONiC database command is
ever issued through this module.
"""

import ipaddress
import re
import uuid


TRANSIT_VLAN = 4094
TRANSIT_NETWORK = ipaddress.ip_network("198.18.0.0/29")
UNDERLAY_ROLES = ("underlay0", "underlay1", "underlay2")
_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9_.-]+")
_DYNAMIC_CONFIG_HEADERS = (
    "! Command:",
    "! device:",
    "! Last configuration change",
    "! Time:",
)


class EosOverlayError(RuntimeError):
    """EOS capability, configuration, or exact-restore failure."""


def _result_failed(result):
    if not isinstance(result, dict):
        return False
    if result.get("failed") or result.get("unreachable"):
        return True
    text = "\n".join(str(result.get(key, "")) for key in (
        "msg", "stderr", "stdout"
    )).lower()
    return any(marker in text for marker in (
        "invalid input", "unknown command", "unrecognized command",
        "incomplete command", "not supported",
    ))


def _stdout(result):
    if not isinstance(result, dict):
        return result
    value = result.get("stdout", "")
    if isinstance(value, list):
        return value[0] if len(value) == 1 else value
    return value


def eos_text(eos_host, command):
    """Run a read-only EOS CLI command and return its textual output."""
    try:
        result = eos_host.run_command(command)
    except Exception as error:
        raise EosOverlayError(
            "{} failed on {}: {}".format(
                command, getattr(eos_host, "hostname", "EOS"), error
            )
        ) from error
    if _result_failed(result):
        raise EosOverlayError(
            "{} failed on {}: {}".format(
                command, getattr(eos_host, "hostname", "EOS"), result
            )
        )
    value = _stdout(result)
    if isinstance(value, (dict, list)):
        raise EosOverlayError(
            "{} did not return text on {}".format(
                command, getattr(eos_host, "hostname", "EOS")
            )
        )
    return str(value or "")


def eos_json(eos_host, command):
    """Run an EOS JSON command through the public :class:`EosHost` API."""
    try:
        payload = eos_host.run_command_json(command)
    except Exception as error:
        raise EosOverlayError(
            "{} JSON capability failed on {}: {}".format(
                command, getattr(eos_host, "hostname", "EOS"), error
            )
        ) from error
    if not isinstance(payload, (dict, list)):
        raise EosOverlayError(
            "{} returned non-JSON data on {}".format(
                command, getattr(eos_host, "hostname", "EOS")
            )
        )
    return payload


def eos_svi_egress_mac(eos_host, vlan):
    """Read the exact remote SVI source MAC without changing its interface.

    EosHost's general get_mac helper can temporarily change switchport mode;
    use the native read-only JSON surface directly for an already routed SVI.
    """
    name = "Vlan{}".format(int(vlan))
    payload = eos_json(eos_host, "show interfaces {}".format(name))
    row = payload.get("interfaces", {}).get(name) if isinstance(payload, dict) else None
    if not isinstance(row, dict):
        raise EosOverlayError("{} native interface facts are absent".format(name))
    value = row.get("physicalAddress", "")
    flat = re.sub(r"[:.-]", "", value).lower() if isinstance(value, str) else ""
    mac = ":".join(flat[index:index + 2] for index in range(0, 12, 2)) \
        if re.fullmatch(r"[0-9a-f]{12}", flat) else ""
    if (not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
            or int(mac.split(":", 1)[0], 16) & 1
            or mac == "00:00:00:00:00:00"):
        raise EosOverlayError("{} has no valid native SVI egress MAC".format(name))
    return mac


def normalize_eos_config(config):
    """Normalize only volatile ``show running-config`` header lines."""
    lines = []
    for line in str(config).replace("\r\n", "\n").splitlines():
        if line.startswith(_DYNAMIC_CONFIG_HEADERS):
            continue
        lines.append(line.rstrip())
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def _interactive(eos_host, command, prompts, answers):
    try:
        result = eos_host.eos_command(
            commands=[{
                "command": command,
                "prompt": list(prompts),
                "answer": list(answers),
            }],
            module_ignore_errors=True,
        )
    except Exception as error:
        raise EosOverlayError(
            "{} failed on {}: {}".format(
                command, getattr(eos_host, "hostname", "EOS"), error
            )
        ) from error
    if _result_failed(result):
        raise EosOverlayError(
            "{} failed on {}: {}".format(
                command, getattr(eos_host, "hostname", "EOS"), result
            )
        )
    return result


def snapshot_eos_config(eos_host):
    """Copy and verify the complete running configuration before mutation."""
    running = eos_text(eos_host, "show running-config")
    canonical = normalize_eos_config(running)
    if not canonical or "interface" not in canonical:
        raise EosOverlayError(
            "{} returned an incomplete running configuration".format(
                getattr(eos_host, "hostname", "EOS")
            )
        )
    hostname = _SAFE_TOKEN.sub("-", str(eos_host.hostname))
    filename = "flash:evpn-mh-{}-{}.cfg".format(
        hostname, uuid.uuid4().hex[:12]
    )
    try:
        eos_text(eos_host, "copy running-config {}".format(filename))
        stored = eos_text(eos_host, "show file {}".format(filename))
        if normalize_eos_config(stored) != canonical:
            raise EosOverlayError(
                "{} snapshot bytes do not match running configuration".format(
                    eos_host.hostname
                )
            )
    except Exception as error:
        cleanup_error = None
        try:
            _interactive(
                eos_host,
                "delete {}".format(filename),
                (r".*[Cc]onfirm.*", r".*[Dd]elete.*"),
                ("y", "y"),
            )
        except Exception as delete_error:
            cleanup_error = delete_error
        if cleanup_error is not None:
            raise EosOverlayError(
                "{}; failed to remove incomplete snapshot: {}".format(
                    error, cleanup_error
                )
            ) from error
        raise
    return {
        "hostname": eos_host.hostname,
        "filename": filename,
        "running_config": running,
        "canonical_config": canonical,
    }


def restore_eos_config(eos_host, snapshot):
    """Replace from the verified snapshot and prove canonical equality."""
    if snapshot.get("hostname") != eos_host.hostname:
        raise EosOverlayError("EOS snapshot hostname mismatch")
    filename = snapshot.get("filename", "")
    if not re.fullmatch(r"flash:evpn-mh-[A-Za-z0-9_.-]+-[0-9a-f]{12}\.cfg", filename):
        raise EosOverlayError("unsafe EOS snapshot filename {!r}".format(filename))
    failures = []
    restored_exactly = False
    try:
        _interactive(
            eos_host,
            "configure replace {}".format(filename),
            (r".*[Pp]roceed.*", r".*continue.*"),
            ("y", "y"),
        )
        restored = normalize_eos_config(
            eos_text(eos_host, "show running-config")
        )
        if restored != snapshot["canonical_config"]:
            failures.append("running configuration differs from snapshot")
        else:
            restored_exactly = True
    except Exception as error:
        failures.append(str(error))
    # A failed/non-identical replace may leave EOS mutated.  Preserve the
    # verified flash snapshot as a recovery artifact; deleting it would turn
    # a detected rollback failure into unrecoverable state loss.
    if restored_exactly:
        try:
            _interactive(
                eos_host,
                "delete {}".format(filename),
                (r".*[Cc]onfirm.*", r".*[Dd]elete.*"),
                ("y", "y"),
            )
        except Exception as error:
            failures.append("snapshot deletion: {}".format(error))
    if failures:
        raise EosOverlayError(
            "{} exact restore failed: {}".format(
                eos_host.hostname, "; ".join(failures)
            )
        )


def interface_for_address(running_config, prefix):
    """Resolve a physical EOS interface from its stock address, fail closed."""
    expected = ipaddress.ip_interface(str(prefix))
    current = None
    matches = []
    for line in str(running_config).splitlines():
        interface_match = re.match(r"^interface\s+(\S+)\s*$", line)
        if interface_match:
            current = interface_match.group(1)
            continue
        if current is None:
            continue
        address_match = re.match(
            r"^\s+(?:ip|ipv6)\s+address\s+(?:virtual\s+)?(\S+)", line
        )
        if not address_match:
            continue
        try:
            candidate = ipaddress.ip_interface(address_match.group(1))
        except ValueError:
            continue
        if candidate == expected:
            matches.append(current)
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise EosOverlayError(
            "address {} resolves to {} EOS interfaces".format(
                prefix, len(unique)
            )
        )
    if "." in unique[0] or unique[0].lower().startswith("vlan"):
        raise EosOverlayError(
            "stock backplane address {} is not on a physical interface".format(
                prefix
            )
        )
    return unique[0]


def build_eos_overlay_plan(neighbors, tbinfo, topology, snapshots):
    """Build the four-node plan entirely from stock facts and snapshots."""
    expected_roles = ("underlay0", "underlay1", "underlay2", "remote_leaf")
    if tuple(sorted(neighbors)) != tuple(sorted(expected_roles)):
        raise EosOverlayError("EOS role map must contain A01--A04 exactly")
    configuration = tbinfo["topo"]["properties"]["configuration"]
    names = list(topology["underlay_neighbor_names"])
    names.append(topology["remote_neighbor_name"])
    roles = dict(zip(expected_roles, names))
    hosts = list(TRANSIT_NETWORK.hosts())
    plan = {}
    for offset, role in enumerate(expected_roles):
        host = neighbors[role]
        name = roles[role]
        stock = configuration.get(name, {})
        bp_ipv4 = stock.get("bp_interface", {}).get("ipv4")
        bp_ipv6 = stock.get("bp_interface", {}).get("ipv6")
        if not bp_ipv4 or not bp_ipv6:
            raise EosOverlayError("{} lacks stock backplane addresses".format(name))
        snapshot = snapshots.get(role)
        if not snapshot or snapshot.get("hostname") != host.hostname:
            raise EosOverlayError("{} lacks a matching EOS snapshot".format(role))
        plan[role] = {
            "name": name,
            "host": host,
            "backplane_interface": interface_for_address(
                snapshot["running_config"], bp_ipv4
            ),
            "backplane_ipv4": bp_ipv4,
            "backplane_ipv6": bp_ipv6,
            "transit_address": "{}/{}".format(
                hosts[offset], TRANSIT_NETWORK.prefixlen
            ),
            "transit_ip": str(hosts[offset]),
            "bgp_asn": int(stock.get("bgp", {}).get("asn", -1)),
            "direct_dut_peers": tuple(
                str(peer)
                for asn, peers in stock.get("bgp", {}).get("peers", {}).items()
                if int(asn) == int(topology["overlay_asn"])
                for peer in peers
            ),
        }
    asns = {details["bgp_asn"] for details in plan.values()}
    if asns != {int(topology["remote_overlay_asn"])}:
        raise EosOverlayError("stock EOS underlay ASN differs from service intent")
    return plan


def _eos_config(eos_host, lines, parents=None):
    kwargs = {"lines": list(lines), "module_ignore_errors": True}
    if parents:
        kwargs["parents"] = list(parents)
    try:
        result = eos_host.eos_config(**kwargs)
    except Exception as error:
        raise EosOverlayError(
            "EOS configuration failed on {}: {}".format(
                eos_host.hostname, error
            )
        ) from error
    if _result_failed(result):
        raise EosOverlayError(
            "EOS configuration failed on {}: {}".format(
                eos_host.hostname, result
            )
        )
    return result


def _configure_backplane_trunk(details, remote=False):
    host = details["host"]
    interface = details["backplane_interface"]
    allowed = [TRANSIT_VLAN]
    if remote:
        allowed.extend((10, 20))
    _eos_config(host, [
        "no ip address {}".format(details["backplane_ipv4"]),
        "no ipv6 address {}".format(details["backplane_ipv6"]),
        "switchport",
        "switchport mode trunk",
        "switchport trunk allowed vlan {}".format(
            ",".join(str(vlan) for vlan in sorted(allowed))
        ),
        "no shutdown",
    ], parents=["interface {}".format(interface)])
    _eos_config(host, ["name EVPN_MH_TRANSIT"],
                parents=["vlan {}".format(TRANSIT_VLAN)])
    _eos_config(host, [
        "ip address {}".format(details["transit_address"]),
        "no shutdown",
    ], parents=["interface Vlan{}".format(TRANSIT_VLAN)])


def _configure_transit_bgp(plan, topology):
    remote = plan["remote_leaf"]
    asn = int(topology["remote_overlay_asn"])
    for role in UNDERLAY_ROLES:
        details = plan[role]
        lines = [
            "neighbor {} remote-as {}".format(remote["transit_ip"], asn),
            "neighbor {} next-hop-self".format(remote["transit_ip"]),
            "neighbor {} description EVPN-MH-REMOTE-TRANSIT".format(
                remote["transit_ip"]
            ),
        ]
        # Both SONiC leaves intentionally use one overlay ASN.  Replace that
        # remote ASN only on the fixture-owned EOS advertisements back to the
        # DUTs, so each leaf can accept the peer leaf's loopback route without
        # an uncheckpointed FRR neighbor mutation on SONiC.
        lines.extend(
            "neighbor {} as-path remote-as replace-out".format(peer)
            for peer in details["direct_dut_peers"]
        )
        _eos_config(details["host"], lines,
                    parents=["router bgp {}".format(asn)])

    lines = ["maximum-paths ibgp 3"]
    for role in UNDERLAY_ROLES:
        peer = plan[role]["transit_ip"]
        lines.extend((
            "neighbor {} remote-as {}".format(peer, asn),
            "neighbor {} description EVPN-MH-TRANSIT".format(peer),
        ))
    _eos_config(remote["host"], lines,
                parents=["router bgp {}".format(asn)])
    # The loopback is the remote VTEP source.  Advertise it before removing
    # the stock direct sessions so the replacement transit path can be proven.
    _eos_config(remote["host"], [
        "network {}/32".format(topology["vtep_ip"]["remote_leaf"]),
    ], parents=["router bgp {}".format(asn), "address-family ipv4"])


def _configure_remote_evpn(remote, topology):
    host = remote["host"]
    asn = int(topology["remote_overlay_asn"])
    # SONiC's local VNI contracts use the MH pair's overlay ASN for their
    # auto-derived route targets.  A04 is an eBGP EVPN peer, so its process ASN
    # differs, but it must import/export the same RT values as the two DUTs.
    rt_asn = int(topology["overlay_asn"])
    vrf = topology["vrf"]
    for vlan, name in (
            (int(topology["mh_vlan"]), "EVPN_MH_LOCAL"),
            (int(topology["remote_vlan"]), "EVPN_MH_REMOTE"),
            (int(topology["l3vni_vlan"]), "EVPN_MH_L3VNI")):
        _eos_config(host, ["name {}".format(name)],
                    parents=["vlan {}".format(vlan)])
    _eos_config(host, ["ip virtual-router mac-address {}".format(
        topology["anycast_gateway_mac"]
    )])
    _eos_config(host, ["description EVPN-MH tenant VRF"],
                parents=["vrf instance {}".format(vrf)])

    for vlan, endpoint in (
            (int(topology["mh_vlan"]), topology["endpoints"]["h3"]),
            (int(topology["remote_vlan"]), topology["endpoints"]["h4"])):
        _eos_config(host, [
            "vrf {}".format(vrf),
            "ip address virtual {}/{}".format(
                endpoint["gateway_ipv4"], endpoint["ipv4_prefixlen"]
            ),
            "ipv6 address virtual {}/{}".format(
                endpoint["gateway_ipv6"], endpoint["ipv6_prefixlen"]
            ),
            "no shutdown",
        ], parents=["interface Vlan{}".format(vlan)])
    _eos_config(host, ["vrf {}".format(vrf), "no shutdown"],
                parents=["interface Vlan{}".format(topology["l3vni_vlan"])])
    _eos_config(host, [
        "vxlan source-interface Loopback0",
        "vxlan udp-port 4789",
        "vxlan vlan {} vni {}".format(topology["mh_vlan"], topology["l2vni"]),
        "vxlan vlan {} vni {}".format(
            topology["remote_vlan"], topology["remote_l2vni"]
        ),
        "vxlan vrf {} vni {}".format(vrf, topology["l3vni"]),
        "no shutdown",
    ], parents=["interface Vxlan1"])

    local_vteps = (
        topology["vtep_ip"]["mh_leaf0"],
        topology["vtep_ip"]["mh_leaf1"],
    )
    bgp_lines = []
    for peer in local_vteps:
        bgp_lines.extend((
            "neighbor {} remote-as {}".format(peer, topology["overlay_asn"]),
            "neighbor {} update-source Loopback0".format(peer),
            "neighbor {} ebgp-multihop 5".format(peer),
            "neighbor {} send-community extended".format(peer),
        ))
    _eos_config(host, bgp_lines, parents=["router bgp {}".format(asn)])
    _eos_config(host, [
        "neighbor {} activate".format(peer) for peer in local_vteps
    ], parents=["router bgp {}".format(asn), "address-family evpn"])

    for vlan, vni in (
            (topology["mh_vlan"], topology["l2vni"]),
            (topology["remote_vlan"], topology["remote_l2vni"])):
        _eos_config(host, [
            "rd {}:{}".format(topology["vtep_ip"]["remote_leaf"], vni),
            "route-target both {}:{}".format(rt_asn, vni),
            "redistribute learned",
        ], parents=["router bgp {}".format(asn), "vlan {}".format(vlan)])
    _eos_config(host, [
        "rd {}:{}".format(
            topology["vtep_ip"]["remote_leaf"], topology["l3vni"]
        ),
        "route-target import evpn {}:{}".format(rt_asn, topology["l3vni"]),
        "route-target export evpn {}:{}".format(rt_asn, topology["l3vni"]),
        "redistribute connected",
    ], parents=["router bgp {}".format(asn), "vrf {}".format(vrf)])


def configure_eos_transit(plan, topology):
    """Build the A01--A04 transit path without removing direct peers."""
    for role in UNDERLAY_ROLES + ("remote_leaf",):
        _configure_backplane_trunk(
            plan[role], remote=(role == "remote_leaf")
        )
    _configure_transit_bgp(plan, topology)


def shutdown_eos_direct_peers(plan, topology):
    """Remove the A04-DUT shortcut only after transit has converged."""
    remote = plan["remote_leaf"]
    asn = int(topology["remote_overlay_asn"])
    _eos_config(
        remote["host"],
        [
            "neighbor {} shutdown".format(peer)
            for peer in remote["direct_dut_peers"]
        ],
        parents=["router bgp {}".format(asn)],
    )


def configure_eos_remote_overlay(plan, topology):
    """Configure A04 EVPN/VXLAN after the routed cutover is proven."""
    _configure_remote_evpn(plan["remote_leaf"], topology)


def probe_eos_overlay_capabilities(neighbors):
    """Return every missing read-only EOS prerequisite without mutating state."""
    failures = []
    for role, host in sorted(neighbors.items()):
        for command in ("show version", "show running-config"):
            try:
                eos_text(host, command)
            except EosOverlayError as error:
                failures.append("{} {}".format(role, error))
        try:
            eos_json(host, "show ip bgp summary")
        except EosOverlayError as error:
            failures.append("{} {}".format(role, error))
    remote = neighbors.get("remote_leaf")
    if remote is None:
        failures.append("remote_leaf EOS host is unavailable")
        return failures
    for command in (
            "show bgp evpn summary",
            "show bgp evpn",
            "show vxlan vni",
            "show mac address-table"):
        try:
            eos_json(remote, command)
        except EosOverlayError as error:
            failures.append("remote_leaf {}".format(error))
    return failures


def walk_eos_json(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_eos_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_eos_json(child)


def eos_scalar_strings(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from eos_scalar_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from eos_scalar_strings(child)
    elif value is not None:
        yield str(value)


def _eos_normalized_peer_address(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def eos_peer_states(summary):
    """Return unique EOS peer-address state; conflicting records fail closed."""
    observed = {}

    def state_from(details):
        for field in ("peerState", "state", "bgpState"):
            if field in details:
                return details[field]
        if "pfxRcd" in details:
            return "Established"
        return None

    def record(address, state):
        address = _eos_normalized_peer_address(address)
        if address is None or state is None:
            return
        state = str(state).strip().lower()
        previous = observed.get(address)
        observed[address] = (
            state if previous is None or previous == state else "ambiguous"
        )

    for item in walk_eos_json(summary):
        if not isinstance(item, dict):
            continue

        state = state_from(item)
        for field in (
                "peerAddress", "peer", "neighborAddress", "neighbor"):
            if field in item:
                record(item[field], state)
                break

        for address, details in item.items():
            if not isinstance(details, dict):
                continue
            record(
                address,
                state_from(details),
            )

    return observed


def eos_established_peers(summary):
    return {
        address
        for address, state in eos_peer_states(summary).items()
        if state == "established"
    }


def _eos_normalized_value(value):
    text = str(value).lower().replace("-", ":")
    if re.fullmatch(
            r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|"
            r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}", text):
        compact = text.replace(":", "").replace(".", "")
        return ":".join(compact[index:index + 2]
                        for index in range(0, 12, 2))
    return text


def eos_contains_value(payload, expected):
    expected = _eos_normalized_value(expected)
    return any(
        _eos_normalized_value(value) == expected
        for value in eos_scalar_strings(payload)
    )


def eos_evpn_peers_ready(eos_host, expected_peers):
    try:
        summary = eos_json(eos_host, "show bgp evpn summary")
    except EosOverlayError:
        return False
    expected = {
        str(ipaddress.ip_address(str(peer))) for peer in expected_peers
    }
    return expected.issubset(eos_established_peers(summary))


def eos_ipv4_route_present(eos_host, prefix):
    payload = eos_json(eos_host, "show ip route {}".format(prefix))
    return eos_contains_value(payload, prefix)


def eos_ipv4_bgp_paths_present(eos_host, prefix, expected_nexthops):
    """Require one prefix's BGP evidence to contain every transit next hop."""
    payload = eos_json(eos_host, "show ip bgp {}".format(prefix))
    return (eos_contains_value(payload, prefix)
            and all(eos_contains_value(payload, nexthop)
                    for nexthop in expected_nexthops))


def eos_transit_ready(plan, topology, require_direct_down=False):
    """Prove transit peers and bidirectional VTEP reachability."""
    remote = plan["remote_leaf"]
    remote_vtep = "{}/32".format(topology["vtep_ip"]["remote_leaf"])
    local_vteps = (
        "{}/32".format(topology["vtep_ip"]["mh_leaf0"]),
        "{}/32".format(topology["vtep_ip"]["mh_leaf1"]),
    )

    try:
        remote_expected = {
            plan[role]["transit_ip"] for role in UNDERLAY_ROLES
        }
        remote_summary = eos_json(remote["host"], "show ip bgp summary")
        remote_established = eos_established_peers(remote_summary)
        if not remote_expected.issubset(remote_established):
            return False
        if (require_direct_down
                and set(remote["direct_dut_peers"]) & remote_established):
            return False
        for prefix in local_vteps:
            if (not eos_ipv4_route_present(remote["host"], prefix)
                    or not eos_ipv4_bgp_paths_present(
                        remote["host"], prefix, remote_expected)):
                return False

        for role in UNDERLAY_ROLES:
            details = plan[role]
            summary = eos_json(details["host"], "show ip bgp summary")
            if remote["transit_ip"] not in eos_established_peers(summary):
                return False
            if not eos_ipv4_route_present(details["host"], remote_vtep):
                return False
        return True
    except EosOverlayError:
        return False


def eos_aliasing_vteps(routes, mac, candidate_vteps):
    """Return VTEPs proven inside one route object that directly owns *mac*.

    The outer EOS JSON document can contain many sibling routes.  Searching a
    recursively flattened root would allow a MAC in one route to combine with
    next hops from unrelated siblings.  Only a dictionary whose own key or
    scalar field, or routeKeyDetail.mac field, is the target MAC may
    contribute nested next-hop evidence from that same route object.
    """
    normalized_mac = _eos_normalized_value(mac)
    expected = {str(address) for address in candidate_vteps}
    found = set()
    for item in walk_eos_json(routes):
        if not isinstance(item, dict):
            continue
        direct_values = {
            _eos_normalized_value(key) for key in item
        }
        direct_values.update(
            _eos_normalized_value(value) for value in item.values()
            if not isinstance(value, (dict, list))
        )
        route_key = item.get("routeKeyDetail")
        if isinstance(route_key, dict) and "mac" in route_key:
            direct_values.add(_eos_normalized_value(route_key["mac"]))
        if normalized_mac not in direct_values:
            continue
        values = {str(value) for value in eos_scalar_strings(item)}
        found.update(expected.intersection(values))
    return found


def collect_remote_eos_evidence(eos_host):
    """Collect all mandatory remote control/dataplane evidence surfaces."""
    return {
        "summary": eos_json(eos_host, "show bgp evpn summary"),
        "routes": eos_json(eos_host, "show bgp evpn"),
        "vni": eos_json(eos_host, "show vxlan vni"),
        "vxlan": eos_json(eos_host, "show interfaces Vxlan1"),
        "fdb": eos_json(eos_host, "show mac address-table"),
    }

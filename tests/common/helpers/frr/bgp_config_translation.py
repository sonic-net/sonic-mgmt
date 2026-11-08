"""Pure, strict bgpcfgd -> frr_mgmt_framework (frrcfgd) BGP config translation.

Converts a traditional-mode CONFIG_DB (plus FRR ``show running-config`` and
``show bgp peer-group json``) into frrcfgd's VRF-keyed schema, so a DUT can be switched
to frr_mgmt_framework mode without losing its BGP config. No DUT access; raises
:class:`FrrTranslationError` on anything it cannot faithfully translate.
"""
import copy
import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

DEFAULT_VRF = "default"
DEFAULT_IPV4_PEER_GROUP = "PEER_V4"
DEFAULT_IPV6_PEER_GROUP = "PEER_V6"
DEFAULT_UNNUMBERED_PEER_GROUP = "PEER_UNNUMBERED"
# bgpcfgd's interface-neighbor fallback (TemplateFabric.is_interface, sonic-buildimage#27370).
_INTERFACE_RE = re.compile(r"^(Ethernet\d+|PortChannel\d+|Vlan\d+)(\.\d+)?$"
                           r"|^Ethernet-(BP|IB|Rec)\d+$|^(Eth\d+|Po\d+)\.\d+$")
_UNNUMBERED_AFS = {"v4": ["ipv4_unicast"], "v6": ["ipv6_unicast"]}

# Stripped from the BGP_NEIGHBOR row; rrclient/nhopself go on BGP_NEIGHBOR_AF instead.
_NEIGHBOR_EXCLUDED_KEYS = ("nhopself", "rrclient", "admin_status", "address_family")


class FrrTranslationError(Exception):
    """Raised when traditional BGP config cannot be faithfully translated to frrcfgd."""


class FrrTranslationGap(FrrTranslationError):
    """Baseline config frrcfgd cannot express by design: the frr variant is skipped, not failed."""


def _afi_safi(ip):
    """Return the frrcfgd afi_safi token for an address, or raise."""
    try:
        version = ipaddress.ip_address(str(ip)).version
    except ValueError:
        raise FrrTranslationError(
            "BGP neighbor address {!r} is neither a valid IPv4 nor IPv6 address".format(ip))
    return "ipv4_unicast" if version == 4 else "ipv6_unicast"


def _is_ip(name):
    try:
        ipaddress.ip_address(str(name))
        return True
    except ValueError:
        return False


def _loopback0_addrs(config_db):
    """Return Loopback0 IP/prefix strings from nested or flat LOOPBACK_INTERFACE keys."""
    addrs = []
    lo = config_db.get("LOOPBACK_INTERFACE", {})
    for key, val in lo.items():
        if key == "Loopback0" and isinstance(val, dict):
            addrs.extend(k for k in val.keys() if "/" in k)
        elif key.startswith("Loopback0|") and "/" in key:
            addrs.append(key.split("|", 1)[1])
    return addrs


def _router_id(config_db):
    """Return the IPv4 Loopback0 address to use as the BGP router-id, or raise."""
    for addr in _loopback0_addrs(config_db):
        ip = addr.split("/")[0]
        try:
            if ipaddress.ip_address(ip).version == 4:
                return ip
        except ValueError:
            continue
    raise FrrTranslationError(
        "No IPv4 Loopback0 address found in LOOPBACK_INTERFACE; cannot set BGP router-id")


def _bgp_asn(config_db):
    meta = config_db.get("DEVICE_METADATA", {}).get("localhost", {})
    asn = meta.get("bgp_asn")
    if not asn:
        raise FrrTranslationError("DEVICE_METADATA|localhost has no bgp_asn; cannot translate BGP config")
    return str(asn)


def _peer_groups(peer_group_json):
    """From 'show bgp peer-group json', return (ipv4_pg, ipv6_pg, all_pg_names, pg_by_neighbor).

    ``ipv4_pg``/``ipv6_pg`` (PEER_V4/PEER_V6 preferred) are only the fallback for neighbors
    not reported as a member of any group.
    """
    if not peer_group_json:
        # No peer-groups: fall back to PEER_V4/PEER_V6 rather than abort the switch.
        return (DEFAULT_IPV4_PEER_GROUP, DEFAULT_IPV6_PEER_GROUP,
                [DEFAULT_IPV4_PEER_GROUP, DEFAULT_IPV6_PEER_GROUP], {})
    ipv4_pgs, ipv6_pgs, all_names = [], [], []
    pg_by_neighbor = {}
    for name, info in peer_group_json.items():
        all_names.append(name)
        members = info.get("members", {}) if isinstance(info, dict) else {}
        for member in members:
            pg_by_neighbor[member] = name
        ips = [m for m in members if _is_ip(m)]
        has_v4 = any("." in m for m in ips)
        has_v6 = any(":" in m for m in ips)
        if not members:
            af = info.get("addressFamilyInfo", "") if isinstance(info, dict) else ""
            has_v4 = "IPv4" in af
            has_v6 = "IPv6" in af
        if has_v4:
            ipv4_pgs.append(name)
        if has_v6:
            ipv6_pgs.append(name)
    for default, pgs in ((DEFAULT_IPV4_PEER_GROUP, ipv4_pgs), (DEFAULT_IPV6_PEER_GROUP, ipv6_pgs)):
        if default in all_names:
            pgs.insert(0, default)
    ipv4_pg = ipv4_pgs[0] if ipv4_pgs else DEFAULT_IPV4_PEER_GROUP
    ipv6_pg = ipv6_pgs[0] if ipv6_pgs else DEFAULT_IPV6_PEER_GROUP
    return ipv4_pg, ipv6_pg, all_names, pg_by_neighbor


def _route_map_names_for_peer_group(peer_group, route_map_names):
    """Resolve a peer group's in/out route-map lists by the FROM_BGP_<pg>/TO_BGP_<pg> convention."""
    rin = sorted(n for n in route_map_names if n.startswith("FROM_BGP_{}".format(peer_group)))
    rout = sorted(n for n in route_map_names if n.startswith("TO_BGP_{}".format(peer_group)))
    if not rin:
        rin = ["FROM_BGP_{}".format(peer_group)]
    if not rout:
        rout = ["TO_BGP_{}".format(peer_group)]
    return rin, rout


# ---- policy extraction from 'show running-config' ----

def _parse_prefix_list(line, family):
    """Parse 'ip[v6] prefix-list NAME seq N permit|deny PREFIX [ge X] [le Y]'; return (name, entry, mode)."""
    parts = line.split()
    if len(parts) < 7 or parts[3] != "seq":
        raise FrrTranslationError("Cannot parse {} prefix-list line: {!r}".format(family, line))
    name = parts[2]
    seq, action, prefix = parts[4], parts[5], parts[6]
    plen = prefix.split("/")[1] if "/" in prefix else ("32" if family == "ipv4" else "128")
    ge = le = None
    if "ge" in parts:
        ge = parts[parts.index("ge") + 1]
    if "le" in parts:
        le = parts[parts.index("le") + 1]
    if ge and le:
        mask_range = "{}..{}".format(ge, le)
    elif ge:
        mask_range = "{}..{}".format(ge, "32" if family == "ipv4" else "128")
    elif le:
        mask_range = "{}..{}".format(plen, le)
    else:
        mask_range = "exact"
    entry = {
        "name": name,
        "sequence_number": int(seq),
        "ip_prefix": prefix,
        "masklength_range": mask_range,
        "action": action,
    }
    return name, entry, ("IPv4" if family == "ipv4" else "IPv6")


def _parse_community_list(line):
    """Parse a 'bgp community-list' line; return (name, set_type, action, community)."""
    parts = line.split()
    if len(parts) < 5:
        raise FrrTranslationError("Cannot parse community-list line: {!r}".format(line))
    set_type = parts[2]
    name = parts[3]
    if parts[4] == "seq" and len(parts) >= 7:
        action = parts[6]
        community = " ".join(parts[7:])
    else:
        action = parts[4]
        community = " ".join(parts[5:])
    community = community.strip().strip('"')
    return name, set_type.upper(), action.lower(), community


def _extract_policy_tables(running_config):
    """Parse FRR running-config into prefix-set, community-set and route-map tables."""
    tables = {
        "PREFIX_SET": {}, "PREFIX": {},
        "COMMUNITY_SET": {}, "EXTENDED_COMMUNITY_SET": {}, "LARGE_COMMUNITY_SET": {},
        "ROUTE_MAP": {}, "ROUTE_MAP_SET": {}, "PROTOCOL_ROUTE_MAP": {},
    }
    community_targets = {
        "bgp community-list ": "COMMUNITY_SET",
        "ip community-list ": "COMMUNITY_SET",
        "bgp extcommunity-list ": "EXTENDED_COMMUNITY_SET",
        "bgp large-community-list ": "LARGE_COMMUNITY_SET",
    }
    for raw in running_config.splitlines():
        line = raw.strip()
        if line.startswith("ip prefix-list "):
            name, entry, mode = _parse_prefix_list(line, "ipv4")
            tables["PREFIX_SET"][name] = {"name": name, "mode": mode}
            key = "{}|{}|{}|{}".format(name, entry["sequence_number"], entry["ip_prefix"],
                                       entry["masklength_range"])
            tables["PREFIX"][key] = entry
        elif line.startswith("ipv6 prefix-list "):
            name, entry, mode = _parse_prefix_list(line, "ipv6")
            tables["PREFIX_SET"][name] = {"name": name, "mode": mode}
            key = "{}|{}|{}|{}".format(name, entry["sequence_number"], entry["ip_prefix"],
                                       entry["masklength_range"])
            tables["PREFIX"][key] = entry
        elif line.startswith("ip protocol ") and " route-map " in line:
            # YANG addr_family is "IPv4"/"IPv6", not the FRR CLI keyword.
            parts = line.split()
            key = "{}|IPv4|{}".format(DEFAULT_VRF, parts[2])
            tables["PROTOCOL_ROUTE_MAP"][key] = {"route_map": parts[4]}
        elif line.startswith("ipv6 protocol ") and " route-map " in line:
            parts = line.split()
            key = "{}|IPv6|{}".format(DEFAULT_VRF, parts[2])
            tables["PROTOCOL_ROUTE_MAP"][key] = {"route_map": parts[4]}
        else:
            for prefix, table in community_targets.items():
                if line.startswith(prefix):
                    norm = line
                    if prefix == "ip community-list ":
                        norm = line.replace("ip community-list", "bgp community-list standard", 1)
                    name, set_type, action, community = _parse_community_list(norm)
                    if not community:
                        break
                    row = tables[table].setdefault(name, {
                        "set_type": set_type, "match_action": "ANY",
                        "action": action, "community_member": [],
                    })
                    if community not in row["community_member"]:
                        row["community_member"].append(community)
                    row["action"] = action
                    break
    _extract_route_maps(running_config, tables)
    return tables


# Route-map clauses frrcfgd cannot express (sonic-buildimage#28482); warned, not raised.
_ROUTE_MAP_UNSUPPORTED_CLAUSES = (
    ("set comm-list ",
     "frrcfgd models only 'set extended-comm-list <name> delete', not the standard-community "
     "form bgpcfgd renders"),
    ("set tag ",
     "sonic-route-map.yang has a set_tag leaf but frrcfgd's route_map_key_map does not render "
     "it, so the field would be inert"),
    ("set originator-id ",
     "frrcfgd has no set_originator_id field"),
    ("set extcommunity bandwidth ",
     "frrcfgd has no set_extcommunity_bandwidth_type field (W-ECMP); writing it would fail "
     "sonic_yang validation over the whole CONFIG_DB"),
)


def _set_match_prefix_set(entry, pl_name, name, seq):
    """Set the single ``match_prefix_set`` leaf; frrcfgd derives ipv4/ipv6 from the PREFIX_SET mode."""
    existing = entry.get("match_prefix_set")
    if existing is not None and existing != pl_name:
        raise FrrTranslationError(
            "route-map {} seq {} matches two prefix-lists ({!r} and {!r}); a frrcfgd "
            "ROUTE_MAP row has a single match_prefix_set leaf and cannot express both"
            .format(name, seq, existing, pl_name))
    entry["match_prefix_set"] = pl_name


def _translate_route_map_clause(entry, line, name, seq):
    """Translate one route-map clause into frrcfgd ROUTE_MAP fields in place; raise if unknown."""
    parts = line.split()

    if line.startswith("match interface "):
        entry["match_interface"] = parts[2]
    elif line.startswith("match ip address prefix-list "):
        _set_match_prefix_set(entry, parts[-1], name, seq)
    elif line.startswith("match ipv6 address prefix-list "):
        _set_match_prefix_set(entry, parts[-1], name, seq)
    elif line.startswith("match ip next-hop prefix-list "):
        entry["match_next_hop_set"] = parts[-1]
    elif line.startswith("match tag "):
        # leaf-list in sonic-route-map.yang
        entry["match_tag"] = [parts[2]]
    elif line.startswith("match metric "):
        entry["match_med"] = parts[2]
    elif line.startswith("match origin "):
        entry["match_origin"] = parts[2]
    elif line.startswith("match local-preference "):
        entry["match_local_pref"] = parts[2]
    elif line.startswith("match community "):
        entry["match_community"] = parts[2]
    elif line.startswith("match extcommunity "):
        entry["match_ext_community"] = parts[2]
    elif line.startswith("match as-path "):
        entry["match_as_path"] = parts[2]
    elif line.startswith("match source-vrf "):
        entry["match_src_vrf"] = parts[2]
    elif line.startswith("match peer "):
        entry["match_neighbor"] = [parts[2]]        # leaf-list (sonic-route-map.yang)
    elif line.startswith("call "):
        entry["call_route_map"] = line.split(None, 1)[1]
    elif line == "on-match next":
        entry["set_on_match_action"] = "ON_MATCH_NEXT"
    elif line.startswith("on-match goto "):
        entry["set_on_match_action"] = "ON_MATCH_GOTO"
        entry["set_on_match_goto"] = parts[2]
    elif line.startswith("set origin "):
        entry["set_origin"] = parts[2]
    elif line.startswith("set local-preference "):
        entry["set_local_pref"] = parts[2]
    elif line.startswith("set metric "):
        entry["set_med"] = parts[2]
    elif line.startswith("set ip next-hop "):
        entry["set_next_hop"] = parts[3]
    elif line == "set ipv6 next-hop prefer-global":
        entry["set_ipv6_next_hop_prefer_global"] = "true"
    elif line.startswith("set ipv6 next-hop global "):
        entry["set_ipv6_next_hop_global"] = parts[4]
    elif line.startswith("set as-path prepend "):
        entry["set_asn_list"] = ",".join(parts[3:])
    elif line.startswith("set community "):
        # A trailing 'additive' stays in the list; frrcfgd space-joins it back.
        entry["set_community_inline"] = parts[2:]
    elif line.startswith("set extcommunity "):
        entry["set_ext_community_inline"] = [" ".join(parts[2:])]
    elif line.startswith("set src "):
        entry["set_src"] = parts[2]
    else:
        for prefix, reason in _ROUTE_MAP_UNSUPPORTED_CLAUSES:
            if line.startswith(prefix):
                logger.warning(
                    "route-map %s seq %s: %r has no frr_mgmt_framework representation (%s); "
                    "frr mode will run without it -- see sonic-buildimage#28482",
                    name, seq, line, reason)
                return
        raise FrrTranslationError(
            "route-map {} seq {}: {!r} is neither translated to a frrcfgd ROUTE_MAP field nor "
            "listed as a known frrcfgd gap. Refusing to switch modes with a policy this "
            "translator would silently change -- extend _translate_route_map_clause() with "
            "the matching frrcfgd field, or add the clause to "
            "_ROUTE_MAP_UNSUPPORTED_CLAUSES if frrcfgd genuinely cannot express it."
            .format(name, seq, line))


def _extract_route_maps(running_config, tables):
    """Parse 'route-map NAME permit|deny SEQ' blocks into ROUTE_MAP/ROUTE_MAP_SET."""
    header = re.compile(r"^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)\s*$")
    current = None  # (name, seq)
    for raw in running_config.splitlines():
        line = raw.strip()
        m = header.match(line)
        if m:
            name, action, seq = m.group(1), m.group(2), m.group(3)
            current = (name, seq)
            tables["ROUTE_MAP_SET"][name] = {"name": name}
            tables["ROUTE_MAP"]["{}|{}".format(name, seq)] = {
                "name": name, "route_operation": action, "stmt_name": seq,
            }
            continue
        # End the stanza at exit, '!', a blank line, or any non-indented line.
        if not line or line == "exit" or line.startswith("!") or not raw[:1].isspace():
            current = None
            continue
        if current is None:
            continue
        _translate_route_map_clause(
            tables["ROUTE_MAP"]["{}|{}".format(*current)], line, current[0], current[1])


# ---- BGP globals / peer-groups / neighbors ----

def _router_bgp_lines(running_config):
    """Yield ``(address_family, line)`` for each line of the default-VRF ``router bgp`` stanza.

    ``address_family`` is None at router-bgp level, else e.g. ``ipv4_unicast``.
    """
    in_bgp = False
    af = None
    for raw in running_config.splitlines():
        line = raw.strip()
        if not line or line == "!":
            # '!' also appears inside 'router bgp'; it does not end the block.
            continue
        if line.startswith("router bgp "):
            in_bgp = " vrf " not in line
            af = None
            continue
        if in_bgp and not raw[:1].isspace():
            in_bgp, af = False, None
            continue
        if not in_bgp:
            continue
        if line.startswith("address-family "):
            parts = line.split()
            af = "{}_{}".format(parts[1], parts[2]) if len(parts) > 2 else None
            continue
        if line in ("exit-address-family", "exit"):
            af = None
            continue
        yield af, line


def _extract_global_af(running_config):
    """BGP_GLOBALS_AF rows for per-AF ``table-map`` and ``maximum-paths`` (YANG default is 1)."""
    global_af = {}
    for af, line in _router_bgp_lines(running_config):
        if not af:
            continue
        key = "{}|{}".format(DEFAULT_VRF, af)
        if line.startswith("table-map "):
            global_af.setdefault(key, {})["route_download_filter"] = line.split()[1]
        elif line.startswith("maximum-paths ") and not line.startswith("maximum-paths ibgp "):
            global_af.setdefault(key, {})["max_ebgp_paths"] = line.split()[1]
    return global_af


# Router-bgp lines -> BGP_GLOBALS fields. value None: prefix match, take the trailing arg;
# literal value: exact match (so 'bgp graceful-restart-disable' is not read as an enable).
_GLOBAL_FLAG_PREFIXES = (
    ("bgp graceful-restart restart-time ", "gr_restart_time", None),
    ("bgp graceful-restart stalepath-time ", "gr_stale_routes_time", None),
    ("bgp graceful-restart preserve-fw-state", "gr_preserve_fw_state", "true"),
    ("bgp graceful-restart", "graceful_restart_enable", "true"),
    ("no bgp ebgp-requires-policy", "ebgp_requires_policy", "false"),
    ("bgp bestpath as-path multipath-relax", "load_balance_mp_relax", "true"),
    ("bgp log-neighbor-changes", "log_nbr_state_changes", "true"),
    ("no bgp log-neighbor-changes", "log_nbr_state_changes", "false"),
)

# Router-bgp lines frrcfgd cannot express; prefix-matched before _GLOBAL_FLAG_PREFIXES.
_GLOBAL_UNSUPPORTED_PREFIXES = (
    ("bgp graceful-restart select-defer-time ",
     "frrcfgd's global_key_map has no select-defer-time field"),
    ("bgp graceful-restart-disable",
     "frrcfgd can only render 'no bgp graceful-restart' (FRR's default helper state), which "
     "is not the same as an explicit graceful-restart-disable"),
    ("bgp long-lived-graceful-restart ",
     "frrcfgd has no long-lived-graceful-restart field"),
)


def _extract_global_flags(running_config):
    """BGP_GLOBALS fields for router-bgp settings bgpcfgd renders from templates (GR, confed, ...)."""
    fields = {}
    for af, line in _router_bgp_lines(running_config):
        if af:
            continue
        if line.startswith("bgp confederation identifier "):
            fields["confed_id"] = line.split()[3]
            continue
        if line.startswith("bgp confederation peers "):
            fields.setdefault("confed_peers", []).extend(line.split()[3:])
            continue
        for prefix, reason in _GLOBAL_UNSUPPORTED_PREFIXES:
            if line.startswith(prefix):
                logger.warning(
                    "%r has no frr_mgmt_framework representation (%s); frr mode will run "
                    "without it -- see sonic-buildimage#28482", line, reason)
                break
        else:
            for prefix, field, value in _GLOBAL_FLAG_PREFIXES:
                if value is None:
                    if line.startswith(prefix):
                        fields[field] = line.split()[-1]
                        break
                elif line == prefix:
                    fields[field] = value
                    break
    return fields


def _build_globals(config_db, bgp_asn, router_id, running_config):
    globals_tbl = {DEFAULT_VRF: {"local_asn": bgp_asn, "router_id": router_id}}
    globals_tbl[DEFAULT_VRF].update(_extract_global_flags(running_config))
    af_network = {}
    for addr in _loopback0_addrs(config_db):
        af = "ipv4_unicast" if "." in addr.split("/")[0] else "ipv6_unicast"
        af_network["{}|{}|{}".format(DEFAULT_VRF, af, addr)] = {}
    return globals_tbl, af_network


def _build_peer_groups(bgp_asn, all_pg_names):
    peer_group = {}
    for name in all_pg_names:
        peer_group["{}|{}".format(DEFAULT_VRF, name)] = {
            "local_asn": bgp_asn, "name": name,
            "peer_group_name": name, "vrf_name": DEFAULT_VRF,
        }
    return peer_group


def _build_peer_group_af(ipv4_pg, ipv6_pg, route_map_names):
    peer_group_af = {}
    for pg, af in ((ipv4_pg, "ipv4_unicast"), (ipv6_pg, "ipv6_unicast")):
        rin, rout = _route_map_names_for_peer_group(pg, route_map_names)
        peer_group_af["{}|{}|{}".format(DEFAULT_VRF, pg, af)] = {
            "vrf_name": DEFAULT_VRF, "peer_group_name": pg, "afi_safi": af,
            "soft_reconfiguration_in": "true",
            "route_map_in": rin, "route_map_out": rout,
        }
    return peer_group_af


def _pg_route_maps(peer_group_af, pg, af, route_map_names):
    """The peer-group AF's route-maps as read from the running config, else the guess."""
    row = peer_group_af.get("{}|{}|{}".format(DEFAULT_VRF, pg, af), {})
    rin, rout = _route_map_names_for_peer_group(pg, route_map_names)
    return row.get("route_map_in", rin), row.get("route_map_out", rout)


def _build_neighbors(config_db, ipv4_pg, ipv6_pg, route_map_names, pg_by_neighbor=None,
                     peer_group_af=None):
    """Transform traditional BGP_NEIGHBOR into frrcfgd BGP_NEIGHBOR + BGP_NEIGHBOR_AF tables."""
    src = config_db.get("BGP_NEIGHBOR")
    if not src:
        raise FrrTranslationError("config_db has no BGP_NEIGHBOR entries to translate")
    pg_by_neighbor = pg_by_neighbor or {}
    neighbors, neighbor_af = {}, {}
    for key, value in src.items():
        if "|" in key:
            vrf, ip = key.split("|", 1)
        else:
            vrf, ip = DEFAULT_VRF, key
        if vrf.startswith("Vnet"):
            raise FrrTranslationError(
                "BGP_NEIGHBOR key {!r} is scoped to VNET {!r}; frrcfgd ignores it unless "
                "BGP_GLOBALS|{} exists, which is not translated here".format(key, vrf, vrf))
        if _INTERFACE_RE.match(ip):
            # Unnumbered neighbor.
            afs = _UNNUMBERED_AFS.get(value.get("address_family"), ["ipv4_unicast", "ipv6_unicast"])
            pg = pg_by_neighbor.get(ip) or DEFAULT_UNNUMBERED_PEER_GROUP
        else:
            afs = [_afi_safi(ip)]
            pg = pg_by_neighbor.get(ip) or (ipv4_pg if afs[0] == "ipv4_unicast" else ipv6_pg)
        admin_status = value.get("admin_status", "up")
        row = {k: v for k, v in value.items() if k not in _NEIGHBOR_EXCLUDED_KEYS}
        row.update({"vrf_name": vrf, "neighbor": ip, "admin_status": admin_status,
                    "peer_group_name": pg})
        neighbors["{}|{}".format(vrf, ip)] = row
        for af in afs:
            rin, rout = _pg_route_maps(peer_group_af or {}, pg, af, route_map_names)
            af_row = {
                "admin_status": admin_status, "vrf_name": vrf, "neighbor": ip, "afi_safi": af,
                "route_map_in": rin, "route_map_out": rout,
            }
            # rrclient/nhopself are AF-level in frrcfgd.
            if value.get("rrclient") in ("1", "true"):
                af_row["rrclient"] = "true"
            if value.get("nhopself") in ("1", "true"):
                af_row["nhself"] = "true"
            neighbor_af["{}|{}|{}".format(vrf, ip, af)] = af_row
    return neighbors, neighbor_af


def _extract_extra_peer_groups(running_config, bgp_asn):
    """Read peer-group attributes/route-maps from running-config; return (peer_group, peer_group_af).

    bgpcfgd renders these from templates, so they exist only in the running-config.
    """
    peer_group, peer_group_af = {}, {}
    for current_af, line in _router_bgp_lines(running_config):
        if not line.startswith("neighbor "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[1]
        if "." in name or ":" in name or _INTERFACE_RE.match(name):
            continue
        pg_key = "{}|{}".format(DEFAULT_VRF, name)
        row = peer_group.setdefault(pg_key, {
            "local_asn": bgp_asn, "name": name,
            "peer_group_name": name, "vrf_name": DEFAULT_VRF,
        })
        attr = parts[2] if len(parts) > 2 else ""
        if current_af is None:
            if attr == "remote-as" and len(parts) > 3:
                row["asn"] = parts[3]
            elif attr == "update-source" and len(parts) > 3:
                row["local_addr"] = parts[3]
            elif attr == "passive":
                row["passive_mode"] = "true"
            elif attr == "capability" and parts[3:4] == ["extended-nexthop"]:
                row["capability_ext_nexthop"] = "true"
            elif attr == "ebgp-multihop":
                row["ebgp_multihop"] = "true"
                if len(parts) > 3:
                    row["ebgp_multihop_ttl"] = parts[3]
        else:
            af_key = "{}|{}|{}".format(DEFAULT_VRF, name, current_af)
            af_row = peer_group_af.setdefault(af_key, {
                "vrf_name": DEFAULT_VRF, "peer_group_name": name, "afi_safi": current_af,
            })
            if attr == "route-map" and len(parts) >= 5:
                rm_name, direction = parts[3], parts[4]
                if direction == "in":
                    af_row.setdefault("route_map_in", []).append(rm_name)
                elif direction == "out":
                    af_row.setdefault("route_map_out", []).append(rm_name)
            elif attr == "allowas-in":
                af_row["allow_as_in"] = "true"
                if parts[3:4] == ["origin"]:
                    af_row["allow_as_origin"] = "true"
                elif len(parts) > 3:
                    af_row["allow_as_count"] = parts[3]
            elif attr == "soft-reconfiguration" and len(parts) > 3 and parts[3] == "inbound":
                af_row["soft_reconfiguration_in"] = "true"
            elif attr == "activate":
                # frrcfgd renders 'activate' from admin_status; needed for listen-range groups.
                af_row["admin_status"] = "up"
    return peer_group, peer_group_af


def _build_listen_prefixes(config_db):
    """Translate BGP_PEER_RANGE into BGP_GLOBALS_LISTEN_PREFIX; a non-default VRF scope raises."""
    src = config_db.get("BGP_PEER_RANGE")
    if not src:
        return {}
    listen = {}
    for name, value in src.items():
        if "|" in name:
            scope, pg_name = name.split("|", 1)
            if scope != DEFAULT_VRF:
                raise FrrTranslationError(
                    "BGP_PEER_RANGE key {!r} is scoped to VRF/VNET {!r}; VRF-scoped listen "
                    "ranges have no translation here (frrcfgd would need a "
                    "BGP_GLOBALS_LISTEN_PREFIX row plus its own BGP_GLOBALS/BGP_PEER_GROUP "
                    "instance under that VRF)".format(name, scope))
        else:
            pg_name = name
        pg = value.get("name") or pg_name
        for prefix in value.get("ip_range", []):
            listen["{}|{}".format(DEFAULT_VRF, prefix)] = {
                "vrf_name": DEFAULT_VRF, "ip_prefix": prefix, "peer_group": pg,
            }
    return listen


# ---- BBR / W-ECMP / aggregate-address ----

_AGG_VALID_ORIGINS = ("igp", "egp", "incomplete", "unspecified")

# Fields bgpcfgd's AggregateAddressMgr reads; anything else raises.
_AGG_KNOWN_FIELDS = frozenset((
    "as-set", "summary-only", "origin",
    "bbr-required", "aggregate-address-prefix-list", "contributing-address-prefix-list",
))


def _apply_bbr(config_db, peer_group_af):
    """Fold ``BGP_BBR|all`` enabled into ``allowas-in 1`` on the given peer-group AF rows."""
    bbr = config_db.get("BGP_BBR")
    if not bbr:
        return
    entry = bbr.get("all")
    if entry is None:
        raise FrrTranslationError("BGP_BBR present but has no 'all' key; cannot translate BBR state")
    status = entry.get("status")
    if status == "enabled":
        for row in peer_group_af.values():
            row["allow_as_in"] = "true"
            row["allow_as_count"] = "1"
    elif status != "disabled":
        raise FrrTranslationError(
            "BGP_BBR|all has unexpected status {!r} (expected 'enabled' or 'disabled')".format(status))


def _apply_wcmp(config_db):
    """Validate ``BGP_DEVICE_GLOBAL`` W-ECMP; frrcfgd cannot express it, so warn when enabled."""
    dev = config_db.get("BGP_DEVICE_GLOBAL")
    if not dev:
        return
    wcmp = dev.get("STATE", {}).get("wcmp_enabled", "false")
    if wcmp == "false":
        return
    if wcmp != "true":
        raise FrrTranslationError(
            "BGP_DEVICE_GLOBAL|STATE wcmp_enabled has unexpected value {!r} (expected 'true'/'false')".format(wcmp))
    # Writing an unmodeled leaf would fail sonic_yang validation of the whole CONFIG_DB.
    logger.warning(
        "BGP_DEVICE_GLOBAL wcmp_enabled=true, but frrcfgd has no field for 'set extcommunity "
        "bandwidth num-multipaths' (no leaf in sonic-route-map.yang, and not added by "
        "sonic-buildimage#28543); frr mode will run without W-ECMP -- see "
        "sonic-buildimage#28482")


def _build_aggregate_addresses(config_db):
    """Translate BGP_AGGREGATE_ADDRESS into BGP_GLOBALS_AF_AGGREGATE_ADDR.

    Raises if bbr-required or the aggregate/contributing prefix-list fields are set.
    """
    src = config_db.get("BGP_AGGREGATE_ADDRESS")
    if not src:
        return {}
    aggregates = {}
    for key, value in src.items():
        if "|" in key:
            vrf, prefix = key.split("|", 1)
        else:
            vrf, prefix = DEFAULT_VRF, key
        af = _afi_safi(prefix.split("/")[0])
        row = {}
        for field, fval in value.items():
            if field not in _AGG_KNOWN_FIELDS:
                raise FrrTranslationError(
                    "Unrecognized BGP_AGGREGATE_ADDRESS field {!r} on {!r}".format(field, key))
            if field == "as-set":
                row["as_set"] = fval
            elif field == "summary-only":
                row["summary_only"] = fval
            elif field == "origin":
                if fval not in _AGG_VALID_ORIGINS:
                    raise FrrTranslationError(
                        "BGP_AGGREGATE_ADDRESS {!r} has origin {!r}; expected one of {}".format(
                            key, fval, _AGG_VALID_ORIGINS))
                # 'unspecified' means emit nothing.
                if fval != "unspecified":
                    row["origin"] = fval
            elif field == "bbr-required" and str(fval).lower() == "true":
                raise FrrTranslationError(
                    "BGP_AGGREGATE_ADDRESS {!r} sets bbr-required=true; BBR-gating of the "
                    "aggregate has no frr_mgmt_framework equivalent".format(key))
            elif field in ("aggregate-address-prefix-list", "contributing-address-prefix-list") and fval:
                raise FrrTranslationError(
                    "BGP_AGGREGATE_ADDRESS {!r} sets {}={!r}; aggregate/contributing prefix-list "
                    "linkage has no frr_mgmt_framework equivalent".format(key, field, fval))
        aggregates["{}|{}|{}".format(vrf, af, prefix)] = row
    return aggregates


def translate_config_db(config_db, running_config, peer_group_json):
    """Return a deep copy of ``config_db`` with bgpcfgd BGP tables replaced by frrcfgd ones.

    :param config_db: parsed ``/etc/sonic/config_db.json`` (traditional mode).
    :param running_config: text of FRR ``show running-config``.
    :param peer_group_json: parsed ``show bgp peer-group json``.
    :raises FrrTranslationError: on config that cannot be faithfully translated.
    """
    result = copy.deepcopy(config_db)
    if result.get("PREFIX_LIST"):
        raise FrrTranslationGap(
            "PREFIX_LIST rows {} are rendered by bgpcfgd's PrefixListMgr, which frrcfgd has no "
            "equivalent for".format(sorted(result["PREFIX_LIST"])))
    bgp_asn = _bgp_asn(result)
    router_id = _router_id(result)

    ipv4_pg, ipv6_pg, all_pg_names, pg_by_neighbor = _peer_groups(peer_group_json)
    policy = _extract_policy_tables(running_config)
    _apply_wcmp(result)
    route_map_names = set(policy["ROUTE_MAP_SET"].keys())

    globals_tbl, af_network = _build_globals(result, bgp_asn, router_id, running_config)
    # DEVICE_METADATA knobs; zebra_nexthop is explicit since frrcfgd only renders it when set.
    lines = {ln.strip() for ln in running_config.splitlines()}
    meta = result.setdefault("DEVICE_METADATA", {}).setdefault("localhost", {})
    for ln in lines:
        if ln.startswith("zebra nexthop-group keep "):
            meta["nexthop_group_keep_time"] = ln.split()[-1]
    if "zebra nexthop kernel enable" in lines:
        meta["zebra_nexthop"] = "enabled"
    elif "no zebra nexthop kernel enable" in lines:
        meta["zebra_nexthop"] = "disabled"
    meta["suppress-fib-pending"] = "enabled" if "bgp suppress-fib-pending" in lines else "disabled"
    peer_group = _build_peer_groups(bgp_asn, all_pg_names)
    peer_group_af = _build_peer_group_af(ipv4_pg, ipv6_pg, route_map_names)
    primary_af = dict(peer_group_af)
    extra_pg, extra_pg_af = _extract_extra_peer_groups(running_config, bgp_asn)
    for key, value in extra_pg.items():
        peer_group[key] = {**peer_group.get(key, {}), **value}
    for key, value in extra_pg_af.items():
        peer_group_af[key] = {**peer_group_af.get(key, {}), **value}
    # BBR's allowas-in goes on the primary v4/v6 peer-groups only.
    _apply_bbr(result, {key: peer_group_af[key] for key in primary_af})
    listen_prefixes = _build_listen_prefixes(result)
    neighbors, neighbor_af = _build_neighbors(
        result, ipv4_pg, ipv6_pg, route_map_names, pg_by_neighbor, peer_group_af)
    aggregates = _build_aggregate_addresses(result)

    result["BGP_GLOBALS"] = globals_tbl
    global_af = _extract_global_af(running_config)
    if global_af:
        result["BGP_GLOBALS_AF"] = global_af
    if af_network:
        result["BGP_GLOBALS_AF_NETWORK"] = af_network
    result["BGP_PEER_GROUP"] = peer_group
    result["BGP_PEER_GROUP_AF"] = peer_group_af
    result["BGP_NEIGHBOR"] = neighbors
    result["BGP_NEIGHBOR_AF"] = neighbor_af
    if aggregates:
        result["BGP_GLOBALS_AF_AGGREGATE_ADDR"] = aggregates
    if listen_prefixes:
        result["BGP_GLOBALS_LISTEN_PREFIX"] = listen_prefixes
    for table, rows in policy.items():
        if rows:
            result[table] = rows
    # Drop bgpcfgd-only tables now expressed in frrcfgd schema.
    result.pop("BGP_AGGREGATE_ADDRESS", None)
    result.pop("BGP_BBR", None)
    result.pop("BGP_PEER_RANGE", None)
    return result

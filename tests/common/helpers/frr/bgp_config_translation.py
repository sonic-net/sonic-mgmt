"""Pure, strict bgpcfgd -> frr_mgmt_framework (frrcfgd) BGP config translation.

SONiC can program FRR from CONFIG_DB in two ways:

* the traditional per-feature daemons (bgpcfgd for BGP) render FRR config from a
  small, flat set of CONFIG_DB tables (e.g. ``BGP_NEIGHBOR|<ip>``) plus Jinja
  templates -- so much of the policy (route-maps, prefix-lists) lives only in the
  rendered *running* FRR config, not in CONFIG_DB;
* the newer ``frr_mgmt_framework`` daemon (frrcfgd) is driven directly from a
  richer, VRF-keyed CONFIG_DB schema (``BGP_GLOBALS``, ``BGP_PEER_GROUP``,
  ``BGP_NEIGHBOR|default|<ip>`` + ``BGP_NEIGHBOR_AF``, ``ROUTE_MAP``, ...).

This module converts the former into the latter so a DUT running in traditional
mode can be switched to frr_mgmt_framework mode without losing its BGP config.
The frrcfgd field/table names and the "a neighbor needs ``asn`` or
``peer_group_name``" rule are taken directly from
``sonic-frr-mgmt-framework/frrcfgd/frrcfgd.py``.

Design goals (see the ``frr_config_mode`` fixture):

* **Pure** -- the translation is a function of its inputs (the traditional
  ``config_db`` dict, FRR's ``show running-config`` text, and
  ``show bgp peer-group json``). No DUT access, so it is unit-testable offline.
* **Strict / fail-loud** -- it raises :class:`FrrTranslationError` on input it
  cannot faithfully translate (a neighbor with no usable key, an address that is
  neither v4 nor v6, a prefix-list line it recognizes but cannot parse, ...)
  rather than silently dropping it. The reference migrator this replaces was
  silently lossy; the goal here is that extending bgpcfgd test coverage forces a
  matching extension here instead of quietly reducing frr-mode coverage.

Route-map *clause* coverage is deliberately scoped: we translate the clauses the
test topologies use and preserve every route-map/prefix-list/community-list
*name*. The ``frr_config_mode`` fixture independently asserts that FRR's
running-config objects are preserved across the switch, which catches any
name-level drop this module might introduce.
"""
import copy
import ipaddress
import re

DEFAULT_VRF = "default"
DEFAULT_IPV4_PEER_GROUP = "PEER_V4"
DEFAULT_IPV6_PEER_GROUP = "PEER_V6"

# Fields present on a traditional BGP_NEIGHBOR row that do not belong on the frrcfgd
# BGP_NEIGHBOR row: rrclient/nhopself are re-emitted onto the neighbor's BGP_NEIGHBOR_AF
# row (as route-reflector-client / next-hop-self), and admin_status is carried through
# explicitly below -- so they are stripped here only to be placed correctly.
_NEIGHBOR_EXCLUDED_KEYS = ("nhopself", "rrclient", "admin_status")


class FrrTranslationError(Exception):
    """Raised when traditional BGP config cannot be faithfully translated to the
    frr_mgmt_framework schema. Failing loudly here is intentional -- it signals
    that this translator must be extended to cover newly-added config."""


def _afi_safi(ip):
    """Return the frrcfgd afi_safi token for an address, or raise if it is neither
    IPv4 nor IPv6."""
    try:
        version = ipaddress.ip_address(str(ip)).version
    except ValueError:
        raise FrrTranslationError(
            "BGP neighbor address {!r} is neither a valid IPv4 nor IPv6 address".format(ip))
    return "ipv4_unicast" if version == 4 else "ipv6_unicast"


def _loopback0_addrs(config_db):
    """Return the list of Loopback0 IP/prefix strings from either the nested
    ({"Loopback0": {"10.1.0.32/32": {}}}) or flat ("Loopback0|10.1.0.32/32": {})
    LOOPBACK_INTERFACE representation."""
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
    """From 'show bgp peer-group json', return (ipv4_pg, ipv6_pg, all_pg_names).

    A peer group is classed v4 or v6 by the address family of its members. The
    first v4/v6 peer group found is used for neighbors of that family (matching
    the reference migrator); every discovered peer group is created."""
    if not peer_group_json:
        # A test may have deployed a BGP config with no peer-groups, or torn the
        # peer-groups down, before the mode switch. Rather than abort the switch, fall
        # back to the conventional PEER_V4/PEER_V6 groups so neighbors still translate to
        # a valid frrcfgd config; the fixture's fail-loud fingerprint independently
        # catches anything actually dropped.
        return (DEFAULT_IPV4_PEER_GROUP, DEFAULT_IPV6_PEER_GROUP,
                [DEFAULT_IPV4_PEER_GROUP, DEFAULT_IPV6_PEER_GROUP])
    ipv4_pgs, ipv6_pgs, all_names = [], [], []
    for name, info in peer_group_json.items():
        all_names.append(name)
        members = info.get("members", {}) if isinstance(info, dict) else {}
        has_v4 = any("." in m for m in members)
        has_v6 = any(":" in m for m in members)
        # Fall back to the address family declared on the group if it has no members yet.
        if not members:
            af = info.get("addressFamilyInfo", "") if isinstance(info, dict) else ""
            has_v4 = "IPv4" in af
            has_v6 = "IPv6" in af
        if has_v4:
            ipv4_pgs.append(name)
        if has_v6:
            ipv6_pgs.append(name)
    ipv4_pg = ipv4_pgs[0] if ipv4_pgs else DEFAULT_IPV4_PEER_GROUP
    ipv6_pg = ipv6_pgs[0] if ipv6_pgs else DEFAULT_IPV6_PEER_GROUP
    return ipv4_pg, ipv6_pg, all_names


def _route_map_names_for_peer_group(peer_group, route_map_names):
    """Resolve inbound/outbound route-map name lists for a peer group by the
    ``FROM_BGP_<pg>`` / ``TO_BGP_<pg>`` naming convention, falling back to the
    conventional names when none are present (matching the reference migrator)."""
    rin = sorted(n for n in route_map_names if n.startswith("FROM_BGP_{}".format(peer_group)))
    rout = sorted(n for n in route_map_names if n.startswith("TO_BGP_{}".format(peer_group)))
    if not rin:
        rin = ["FROM_BGP_{}".format(peer_group)]
    if not rout:
        rout = ["TO_BGP_{}".format(peer_group)]
    return rin, rout


# --------------------------------------------------------------------------- #
# Prefix-list / community-list extraction from FRR 'show running-config'
# --------------------------------------------------------------------------- #

def _parse_prefix_list(line, family):
    """Parse 'ip[v6] prefix-list NAME seq N permit|deny PREFIX [ge X] [le Y]'.

    Returns (name, entry_dict, family_label) where family_label is "IPv4"/"IPv6".
    Raises on a line we recognize as a prefix-list but cannot parse."""
    parts = line.split()
    # parts: <ip|ipv6> prefix-list NAME seq N action PREFIX ...
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
    """Parse 'bgp community-list standard|expanded NAME [seq N] permit|deny VALUE...'.

    Returns (name, set_type, action, community). Raises on unparseable input."""
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
    """Parse FRR running-config text into PREFIX_SET/PREFIX and
    COMMUNITY_SET/EXTENDED_COMMUNITY_SET/LARGE_COMMUNITY_SET / ROUTE_MAP tables.

    Returns a dict of {table_name: {key: value}}. Recognized-but-malformed lines
    raise; lines belonging to other config sections are left to other methods."""
    tables = {
        "PREFIX_SET": {}, "PREFIX": {},
        "COMMUNITY_SET": {}, "EXTENDED_COMMUNITY_SET": {}, "LARGE_COMMUNITY_SET": {},
        "ROUTE_MAP": {}, "ROUTE_MAP_SET": {},
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


def _extract_route_maps(running_config, tables):
    """Parse 'route-map NAME permit|deny SEQ' blocks into ROUTE_MAP/ROUTE_MAP_SET.

    Preserves every route-map name (the fixture's fail-loud net checks names);
    translates the match/set clauses used by the test topologies."""
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
        if current is None or not line or line.startswith("!"):
            continue
        entry = tables["ROUTE_MAP"]["{}|{}".format(*current)]
        if line.startswith("call "):
            entry["call_route_map"] = line.split(None, 1)[1]
        elif line.startswith("match community "):
            entry["match_community"] = line.split()[2]
        elif line.startswith("set community ") and line.endswith(" additive"):
            # frrcfgd models 'additive' as the companion field set_community_additive,
            # not as a member of the community value list (frrcfgd handler
            # hdl_set_community_additive appends ' additive' only when that field is 'true').
            entry["set_community_inline"] = line.split()[2:-1]
            entry["set_community_additive"] = "true"
        elif line == "set ipv6 next-hop prefer-global":
            entry["set_ipv6_next_hop_prefer_global"] = "true"
        elif line == "on-match next":
            # frrcfgd's route-map model has no representation for continue-flow
            # ('on-match next'/'goto'). It appears throughout the bgpcfgd-generated
            # FROM_BGP_* inbound maps (the allow-list framework's 'call ...; on-match
            # next', and the 'set ipv6 next-hop prefer-global; on-match next' entry),
            # where dropping it is benign for the baseline permit path (the allow-list
            # test itself is skipped in frr mode). Tolerate it in those framework maps;
            # fail loud anywhere else so a policy that genuinely depends on continue-flow
            # is never silently mistranslated.
            if not current[0].startswith("FROM_BGP"):
                raise FrrTranslationError(
                    "route-map {} seq {}: 'on-match next' has no frr_mgmt_framework "
                    "representation (only tolerated in the bgpcfgd FROM_BGP_* framework "
                    "maps)".format(*current))
        elif line.startswith("on-match "):
            raise FrrTranslationError(
                "route-map {} seq {}: {!r} (route-map continue-flow) has no "
                "frr_mgmt_framework representation".format(current[0], current[1], line))
        # Other match/set clauses are not modeled here; the route-map name is still
        # preserved above, and the fixture asserts name-level preservation.


# --------------------------------------------------------------------------- #
# BGP globals / peer-groups / neighbors
# --------------------------------------------------------------------------- #

def _build_globals(config_db, bgp_asn, router_id):
    globals_tbl = {DEFAULT_VRF: {"local_asn": bgp_asn, "router_id": router_id}}
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


def _build_neighbors(config_db, ipv4_pg, ipv6_pg, route_map_names):
    """Transform the traditional BGP_NEIGHBOR table into the frrcfgd VRF-keyed
    BGP_NEIGHBOR + BGP_NEIGHBOR_AF tables."""
    src = config_db.get("BGP_NEIGHBOR")
    if not src:
        raise FrrTranslationError("config_db has no BGP_NEIGHBOR entries to translate")
    neighbors, neighbor_af = {}, {}
    for key, value in src.items():
        if "|" in key:
            vrf, ip = key.split("|", 1)
        else:
            vrf, ip = DEFAULT_VRF, key
        af = _afi_safi(ip)
        pg = ipv4_pg if af == "ipv4_unicast" else ipv6_pg
        # Carry the source admin_status through (default up when absent) rather than
        # forcing up -- an admin_status="down" neighbor must not silently come up.
        admin_status = value.get("admin_status", "up")
        row = {k: v for k, v in value.items() if k not in _NEIGHBOR_EXCLUDED_KEYS}
        row.update({"vrf_name": vrf, "neighbor": ip, "admin_status": admin_status,
                    "peer_group_name": pg})
        neighbors["{}|{}".format(vrf, ip)] = row
        rin, rout = _route_map_names_for_peer_group(pg, route_map_names)
        af_row = {
            "admin_status": admin_status, "vrf_name": vrf, "neighbor": ip, "afi_safi": af,
            "route_map_in": rin, "route_map_out": rout,
        }
        # rrclient/nhopself are AF-level in frrcfgd (route-reflector-client / next-hop-self).
        # Re-emit them onto the neighbor's AF row when enabled so a route-reflector client
        # or next-hop-self neighbor is not silently dropped on the switch; the no-op
        # ("0"/"false"/absent) case needs no line.
        if value.get("rrclient") in ("1", "true"):
            af_row["rrclient"] = "true"
        if value.get("nhopself") in ("1", "true"):
            af_row["nhself"] = "true"
        neighbor_af["{}|{}|{}".format(vrf, ip, af)] = af_row
    return neighbors, neighbor_af


def _extract_extra_peer_groups(running_config, primary_names, bgp_asn):
    """Translate non-standard peer-groups (the listen-range peer-groups a t0 baseline
    ships, e.g. ``BGPSLBPassive`` / ``BGPVac``) from FRR ``show running-config`` into
    frrcfgd ``BGP_PEER_GROUP`` + ``BGP_PEER_GROUP_AF`` rows.

    ``_build_peer_group_af`` / ``_build_neighbors`` only handle the primary v4/v6
    peer-groups. A peer-group bound to a ``bgp listen range`` (no explicit BGP_NEIGHBOR
    rows) would otherwise be dropped, and its ``neighbor <pg> remote-as`` line would
    vanish after the switch -- which the fixture's fail-loud fingerprint catches.
    bgpcfgd renders these peer-groups' attributes from templates, so they live only in
    the running-config, not CONFIG_DB; we read them back from there.

    frrcfgd BGP_PEER_GROUP uses cmn_key_map (frrcfgd.py:2154-2165, 2420):
    ``asn``->remote-as, ``local_addr``->update-source, ``passive_mode``->passive,
    ``ebgp_multihop``(+``ebgp_multihop_ttl``)->ebgp-multihop. BGP_PEER_GROUP_AF carries
    ``route_map_in`` / ``route_map_out`` / ``soft_reconfiguration_in`` (frrcfgd.py:2422)
    for each address-family the peer-group is activated in.

    Returns ``(peer_group, peer_group_af)`` dicts keyed like the other builders.
    """
    peer_group, peer_group_af = {}, {}
    current_af = None
    for raw in running_config.splitlines():
        line = raw.strip()
        if line.startswith("address-family "):
            parts = line.split()
            # 'address-family ipv4 unicast' -> 'ipv4_unicast'
            if len(parts) >= 3:
                current_af = "{}_{}".format(parts[1], parts[2])
            continue
        if line == "exit-address-family" or line == "exit":
            current_af = None
            continue
        if not line.startswith("neighbor "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[1]
        # Skip IP neighbors (handled by _build_neighbors) and the primary v4/v6
        # peer-groups (handled by _build_peer_group_af).
        if "." in name or ":" in name or name in primary_names:
            continue
        pg_key = "{}|{}".format(DEFAULT_VRF, name)
        row = peer_group.setdefault(pg_key, {
            "local_asn": bgp_asn, "name": name,
            "peer_group_name": name, "vrf_name": DEFAULT_VRF,
        })
        attr = parts[2] if len(parts) > 2 else ""
        if current_af is None:
            # router-bgp context: peer-group-level attributes
            if attr == "remote-as" and len(parts) > 3:
                row["asn"] = parts[3]
            elif attr == "update-source" and len(parts) > 3:
                row["local_addr"] = parts[3]
            elif attr == "passive":
                row["passive_mode"] = "true"
            elif attr == "ebgp-multihop":
                row["ebgp_multihop"] = "true"
                if len(parts) > 3:
                    row["ebgp_multihop_ttl"] = parts[3]
            # 'peer-group' (identity) / 'description' / unmapped attrs: ignore
        else:
            # address-family context: AF-level attributes
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
            elif attr == "soft-reconfiguration" and len(parts) > 3 and parts[3] == "inbound":
                af_row["soft_reconfiguration_in"] = "true"
            elif attr == "activate":
                # frrcfgd renders 'neighbor <pg> activate' from admin_status (nbr_af_key_map,
                # frrcfgd.py:2184). A listen-range peer-group has no explicit BGP_NEIGHBOR_AF
                # rows to carry the activation, so without this the peer-group is not
                # activated in the AF and dynamic (listen-range) peers never establish.
                af_row["admin_status"] = "up"
    return peer_group, peer_group_af


def _build_listen_prefixes(config_db):
    """Translate the traditional ``BGP_PEER_RANGE`` table (dynamic-neighbor listen
    ranges, e.g. for BGPSLBPassive / BGPVac) into frrcfgd's ``BGP_GLOBALS_LISTEN_PREFIX``
    (frrcfgd.py:2271, 2418; yang key ``vrf_name|ip_prefix``, leaf ``peer_group`` ->
    ``bgp listen range <prefix> peer-group <pg>``). bgpcfgd consumes BGP_PEER_RANGE
    directly; frrcfgd expresses the same range through this table."""
    src = config_db.get("BGP_PEER_RANGE")
    if not src:
        return {}
    listen = {}
    for name, value in src.items():
        pg = value.get("name") or name.split("|")[-1]
        for prefix in value.get("ip_range", []):
            listen["{}|{}".format(DEFAULT_VRF, prefix)] = {
                "vrf_name": DEFAULT_VRF, "ip_prefix": prefix, "peer_group": pg,
            }
    return listen


# --------------------------------------------------------------------------- #
# Baseline BGP feature tables (BBR / W-ECMP / aggregate-address)
#
# These traditional (bgpcfgd) tables have no frr_mgmt_framework table of the same
# name. bgpcfgd renders them into FRR config imperatively (BBR toggles peer-group
# allowas-in; W-ECMP edits the outbound route-map; aggregate-address emits
# aggregate-address lines). frrcfgd expresses the same FRR state through its own
# CONFIG_DB schema, so we fold each into the frr tables the translator already
# builds rather than leaving a table frrcfgd would ignore.
# --------------------------------------------------------------------------- #

# frrcfgd origin tokens accepted by the aggregate-address 'aggr-origin' format
# (frrcfgd.py:1061-1063 -- 'unspecified' is treated as "emit nothing").
_AGG_VALID_ORIGINS = ("igp", "egp", "incomplete", "unspecified")

# Every field bgpcfgd's AggregateAddressMgr reads off a BGP_AGGREGATE_ADDRESS row
# (sonic-bgpcfgd/bgpcfgd/managers_aggregate_address.py:12-16). Anything outside
# this set is unrecognized input and must fail loudly.
_AGG_KNOWN_FIELDS = frozenset((
    "as-set", "summary-only", "origin",
    "bbr-required", "aggregate-address-prefix-list", "contributing-address-prefix-list",
))


def _apply_bbr(config_db, peer_group_af):
    """Fold a traditional ``BGP_BBR|all`` status into the frr peer-group AF rows.

    frrcfgd has no BGP_BBR table handler, so BBR cannot be carried as a table.
    bgpcfgd's BBRMgr, when status==enabled, pushes ``neighbor <pg> allowas-in 1``
    on the ipv4/ipv6 address-families of its BBR peer-groups
    (sonic-bgpcfgd/bgpcfgd/managers_bbr.py:161-167). The frrcfgd equivalent of
    ``allowas-in 1`` is ``allow_as_in='true'`` + ``allow_as_count='1'`` on the
    BGP_PEER_GROUP_AF row (nbr_af_key_map, frrcfgd.py:2183 -- the map is shared by
    BGP_PEER_GROUP_AF, frrcfgd.py:2422). When disabled we leave the rows unset."""
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


def _apply_wcmp(config_db, policy, ipv4_pg, ipv6_pg):
    """Fold ``BGP_DEVICE_GLOBAL`` W-ECMP into the outbound peer-group route-maps.

    When ``wcmp_enabled == 'true'`` bgpcfgd renders, on the outbound route-maps of
    the v4/v6 peer-groups (``TO_BGP_PEER_V4``/``TO_BGP_PEER_V6`` at seq 100),
    ``set extcommunity bandwidth num-multipaths``
    (docker-fpm-frr/frr/bgpd/wcmp/bgpd.wcmp.conf.j2). frrcfgd emits that same line
    from ``set_extcommunity_bandwidth_type == 'NUM_MULTIPATHS'`` on a ROUTE_MAP row
    (route_map_key_map, frrcfgd.py:2252-2254; handler frrcfgd.py:577). We model it
    as a ROUTE_MAP entry keyed like every other ROUTE_MAP row this module emits."""
    dev = config_db.get("BGP_DEVICE_GLOBAL")
    if not dev:
        return
    wcmp = dev.get("STATE", {}).get("wcmp_enabled", "false")
    if wcmp == "false":
        return
    if wcmp != "true":
        raise FrrTranslationError(
            "BGP_DEVICE_GLOBAL|STATE wcmp_enabled has unexpected value {!r} (expected 'true'/'false')".format(wcmp))
    for pg in (ipv4_pg, ipv6_pg):
        name = "TO_BGP_{}".format(pg)
        policy["ROUTE_MAP_SET"].setdefault(name, {"name": name})
        entry = policy["ROUTE_MAP"].setdefault("{}|100".format(name), {
            "name": name, "route_operation": "permit", "stmt_name": "100",
        })
        # set_extcommunity_bandwidth_type NUM_MULTIPATHS -> 'set extcommunity
        # bandwidth num-multipaths' (frrcfgd.py:2252-2254).
        entry["set_extcommunity_bandwidth_type"] = "NUM_MULTIPATHS"


def _build_aggregate_addresses(config_db):
    """Translate the traditional ``BGP_AGGREGATE_ADDRESS`` table into frrcfgd's
    ``BGP_GLOBALS_AF_AGGREGATE_ADDR`` (registered frrcfgd.py:2725; af_aggregate_key_map
    frrcfgd.py:2290). The frr key is ``<vrf>|<afi_safi>|<ip_prefix>`` and the row
    carries ``as_set`` / ``summary_only`` / ``origin`` (frrcfgd.py:2290, formats at
    frrcfgd.py:950-951, 1061-1063).

    bgpcfgd's ``as-set`` / ``summary-only`` / ``origin``
    (managers_aggregate_address.py:12-16) map straight across. Three bgpcfgd fields
    have NO frr_mgmt_framework equivalent, so rather than silently drop them we fail
    loudly when they carry meaning:

    * ``bbr-required`` gates whether the aggregate is installed on BBR state
      (managers_aggregate_address.py:74-84) -- frrcfgd installs unconditionally;
    * ``aggregate-address-prefix-list`` / ``contributing-address-prefix-list`` add
      side prefix-lists (managers_aggregate_address.py:116-134) that frrcfgd's
      aggregate schema cannot express."""
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
                # 'unspecified' is frrcfgd's "emit nothing" sentinel (frrcfgd.py:1062);
                # only carry a concrete origin.
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
    """Return a deep-copied ``config_db`` with its traditional (bgpcfgd) BGP tables
    replaced by the equivalent frr_mgmt_framework (frrcfgd) tables.

    :param config_db: parsed ``/etc/sonic/config_db.json`` (traditional mode).
    :param running_config: text of FRR ``show running-config``.
    :param peer_group_json: parsed ``show bgp peer-group json``.
    :raises FrrTranslationError: on config that cannot be faithfully translated.
    """
    result = copy.deepcopy(config_db)
    bgp_asn = _bgp_asn(result)
    router_id = _router_id(result)

    ipv4_pg, ipv6_pg, all_pg_names = _peer_groups(peer_group_json)
    policy = _extract_policy_tables(running_config)
    # W-ECMP adds an outbound-route-map clause; fold it in before route_map_names
    # is snapshotted so peer-groups still resolve their route_map_out list.
    _apply_wcmp(result, policy, ipv4_pg, ipv6_pg)
    route_map_names = set(policy["ROUTE_MAP_SET"].keys())

    globals_tbl, af_network = _build_globals(result, bgp_asn, router_id)
    peer_group = _build_peer_groups(bgp_asn, all_pg_names)
    peer_group_af = _build_peer_group_af(ipv4_pg, ipv6_pg, route_map_names)
    _apply_bbr(result, peer_group_af)
    # Non-standard / listen-range peer-groups (e.g. BGPSLBPassive, BGPVac). Merge AFTER
    # _apply_bbr so BBR's allowas-in stays on the primary v4/v6 peer-groups only.
    extra_pg, extra_pg_af = _extract_extra_peer_groups(
        running_config, {ipv4_pg, ipv6_pg}, bgp_asn)
    for key, value in extra_pg.items():
        peer_group[key] = {**peer_group.get(key, {}), **value}
    peer_group_af.update(extra_pg_af)
    listen_prefixes = _build_listen_prefixes(result)
    neighbors, neighbor_af = _build_neighbors(result, ipv4_pg, ipv6_pg, route_map_names)
    aggregates = _build_aggregate_addresses(result)

    result["BGP_GLOBALS"] = globals_tbl
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
    # Drop the traditional bgpcfgd tables now fully expressed in frr schema;
    # frrcfgd has no handler for them (table_handler_list, frrcfgd.py:2694-2751).
    result.pop("BGP_AGGREGATE_ADDRESS", None)
    result.pop("BGP_BBR", None)
    result.pop("BGP_PEER_RANGE", None)
    return result

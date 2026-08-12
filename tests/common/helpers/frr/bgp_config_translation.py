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
import logging
import re

logger = logging.getLogger(__name__)

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
    """From 'show bgp peer-group json', return (ipv4_pg, ipv6_pg, all_pg_names, pg_by_neighbor).

    A peer group is classed v4 or v6 by the address family of its members. ``ipv4_pg`` /
    ``ipv6_pg`` are the first v4/v6 group found, used only as the *fallback* for a neighbor
    FRR does not report as an explicit member; every discovered peer group is created.

    ``pg_by_neighbor`` maps each explicitly-configured neighbor IP to the group it actually
    belongs to. Discarding that mapping and assigning every neighbor of an address family to
    the first group of that family loses the association whenever a topology has more than
    one same-family peer group (e.g. PEER_V4 with 10.0.0.1 and ANOTHER_V4 with 10.0.0.2 both
    ended up in PEER_V4).
    """
    if not peer_group_json:
        # A test may have deployed a BGP config with no peer-groups, or torn the
        # peer-groups down, before the mode switch. Rather than abort the switch, fall
        # back to the conventional PEER_V4/PEER_V6 groups so neighbors still translate to
        # a valid frrcfgd config; the fixture's fail-loud fingerprint independently
        # catches anything actually dropped.
        return (DEFAULT_IPV4_PEER_GROUP, DEFAULT_IPV6_PEER_GROUP,
                [DEFAULT_IPV4_PEER_GROUP, DEFAULT_IPV6_PEER_GROUP], {})
    ipv4_pgs, ipv6_pgs, all_names = [], [], []
    pg_by_neighbor = {}
    for name, info in peer_group_json.items():
        all_names.append(name)
        members = info.get("members", {}) if isinstance(info, dict) else {}
        for member in members:
            pg_by_neighbor[member] = name
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
    return ipv4_pg, ipv6_pg, all_names, pg_by_neighbor


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
            # zebra 'ip protocol <proto> route-map <name>' -> PROTOCOL_ROUTE_MAP.
            # The key is "<vrf_name>|<addr_family>|<protocol>" (sonic-protocol-route-map.yang:
            # key "vrf_name addr_family protocol"), and addr_family is sonic-types:ip-family,
            # whose values are "IPv4"/"IPv6" -- not the lowercase FRR CLI keywords. Getting
            # either wrong makes sonic_yang reject the row, and because GCU validates the
            # WHOLE CONFIG_DB, that breaks every apply-patch on the DUT, not just BGP ones.
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


# Route-map clauses frrcfgd cannot express. Each is a genuine frrcfgd gap, not a translation
# miss: the route-map NAME is still preserved (so the fixture's fingerprint stays green), but
# the clause is not rendered in frr mode. These are logged loudly rather than raised, because
# bgpcfgd emits them from its own base templates on stock DUTs -- raising would make the mode
# switch fail outright on, e.g., every UpperSpineRouter. Tracked in sonic-buildimage#28482.
_ROUTE_MAP_UNSUPPORTED_CLAUSES = (
    ("set comm-list ",
     "frrcfgd models only 'set extended-comm-list <name> delete', not the standard-community "
     "form bgpcfgd renders"),
    ("set tag ",
     "sonic-route-map.yang has a set_tag leaf but frrcfgd's route_map_key_map does not render "
     "it, so the field would be inert"),
    ("set originator-id ",
     "frrcfgd has no set_originator_id field"),
    # W-ECMP. set_extcommunity_bandwidth_type is in NEITHER sonic-route-map.yang NOR
    # frrcfgd's route_map_key_map, and sonic-buildimage#28543 does not add it. This parser
    # used to emit it when it saw the clause in the running config -- which is the same
    # unmodeled-leaf GCU breakage _apply_wcmp() was fixed for, just reached by a different
    # route (a DUT that already has the clause rendered, rather than BGP_DEVICE_GLOBAL).
    ("set extcommunity bandwidth ",
     "frrcfgd has no set_extcommunity_bandwidth_type field (W-ECMP); writing it would fail "
     "sonic_yang validation over the whole CONFIG_DB"),
)


def _set_match_prefix_set(entry, pl_name, name, seq):
    """Record a ``match ip[v6] address prefix-list`` clause on a ROUTE_MAP row.

    The CONFIG_DB field is the single ``match_prefix_set`` leaf: frrcfgd derives the
    ipv4/ipv6 qualifier itself by looking up the referenced PREFIX_SET's mode (frrcfgd.py
    ``__update_bgp_table``), and ``match_prefix_set|ipv4`` is only an internal key_map name.
    Writing that internal name as a CONFIG_DB field is worse than dropping the clause:
    frrcfgd ignores it AND sonic_yang rejects the row, which -- because GCU validates the
    WHOLE CONFIG_DB -- breaks every later apply-patch on the DUT, not just BGP ones.
    """
    existing = entry.get("match_prefix_set")
    if existing is not None and existing != pl_name:
        raise FrrTranslationError(
            "route-map {} seq {} matches two prefix-lists ({!r} and {!r}); a frrcfgd "
            "ROUTE_MAP row has a single match_prefix_set leaf and cannot express both"
            .format(name, seq, existing, pl_name))
    entry["match_prefix_set"] = pl_name


def _translate_route_map_clause(entry, line, name, seq):
    """Translate one route-map clause into frrcfgd ROUTE_MAP fields, in place.

    Every field below is grounded in frrcfgd's ``route_map_key_map``
    (sonic-frr-mgmt-framework/frrcfgd/frrcfgd.py) and the ROUTE_MAP leaves of
    ``sonic-yang-models/yang-models/sonic-route-map.yang``.

    Clauses in neither that map nor :data:`_ROUTE_MAP_UNSUPPORTED_CLAUSES` raise. Silently
    ignoring them -- as this did before -- conflicts with the module's fail-loud contract in
    the way that matters most: the route-map *name* survives, so the fixture's fingerprint
    reports success while the policy the test then exercises has quietly changed.
    """
    parts = line.split()

    # -- match ---------------------------------------------------------------
    if line.startswith("match interface "):
        entry["match_interface"] = parts[2]
    elif line.startswith("match ip address prefix-list "):
        _set_match_prefix_set(entry, parts[-1], name, seq)
    elif line.startswith("match ipv6 address prefix-list "):
        _set_match_prefix_set(entry, parts[-1], name, seq)
    elif line.startswith("match ip next-hop prefix-list "):
        entry["match_next_hop_set"] = parts[-1]
    elif line.startswith("match tag "):
        # sonic-route-map.yang models match_tag as a leaf-list, so it must be a list --
        # a bare string is rejected by sonic_yang.
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
    # -- call / continue-flow ------------------------------------------------
    elif line.startswith("call "):
        entry["call_route_map"] = line.split(None, 1)[1]
    elif line == "on-match next":
        # frrcfgd models route-map continue-flow via the set_on_match_action enum
        # (rendered as 'on-match next' / 'on-match goto <seq>'). See sonic-buildimage#28482.
        entry["set_on_match_action"] = "ON_MATCH_NEXT"
    elif line.startswith("on-match goto "):
        entry["set_on_match_action"] = "ON_MATCH_GOTO"
        entry["set_on_match_goto"] = parts[2]
    # -- set -----------------------------------------------------------------
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
        # frrcfgd's set_asn_list is a comma-separated ASN list
        # ('set as-path prepend {:asn_list}', hdl_set_asn_list).
        entry["set_asn_list"] = ",".join(parts[3:])
    elif line.startswith("set community "):
        # frrcfgd space-joins the set_community_inline leaf-list and has no separate
        # 'additive' companion field, so every community plus any trailing 'additive'
        # token stays in the list (-> 'set community <c1> <c2> additive').
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
    """Parse 'route-map NAME permit|deny SEQ' blocks into ROUTE_MAP/ROUTE_MAP_SET.

    Preserves every route-map name (the fixture's fail-loud net checks names) and translates
    each clause via :func:`_translate_route_map_clause`."""
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
        # Close the stanza explicitly: at 'exit', at a '!' separator, at a blank line, or at
        # the next non-indented line. Previously '!' only skipped the line and `current`
        # stayed set past the end of the block, so -- because this parser strips indentation
        # before matching -- a match/set line in a later stanza was attributed to the
        # preceding route-map.
        if not line or line == "exit" or line.startswith("!") or not raw[:1].isspace():
            current = None
            continue
        if current is None:
            continue
        _translate_route_map_clause(
            tables["ROUTE_MAP"]["{}|{}".format(*current)], line, current[0], current[1])


# --------------------------------------------------------------------------- #
# BGP globals / peer-groups / neighbors
# --------------------------------------------------------------------------- #

def _router_bgp_lines(running_config):
    """Yield ``(address_family, line)`` for each line inside the default-VRF ``router bgp``
    stanza of FRR's ``show running-config``.

    Centralises the stanza / address-family context tracking every router-bgp extractor
    below needs. ``address_family`` is None in router-bgp context and e.g. ``ipv4_unicast``
    inside an ``address-family`` block.

    Only the default-VRF instance is yielded. ``router bgp <asn> vrf <name>`` configures a
    different VRF, and everything the callers emit is keyed to :data:`DEFAULT_VRF`, so
    folding a VRF instance's lines in would silently move that config into the default VRF.
    """
    in_bgp = False
    af = None
    for raw in running_config.splitlines():
        line = raw.strip()
        if not line or line == "!":
            # '!' separates stanzas *inside* 'router bgp' too, so it must not end the block.
            continue
        if line.startswith("router bgp "):
            in_bgp = " vrf " not in line
            af = None
            continue
        if in_bgp and not raw[:1].isspace():
            # Any non-indented line (including a bare 'exit') closes the router bgp block.
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
    """BGP_GLOBALS_AF rows for per-address-family globals bgpcfgd renders.

    * ``table-map`` (frrcfgd ``route_download_filter``), which bgpcfgd applies on an
      UpperSpineRouter/UpstreamLC to keep locally-anchored routes out of the FIB
      (SELECTIVE_ROUTE_DOWNLOAD_V4/V6);
    * ``maximum-paths`` (frrcfgd ``max_ebgp_paths``), which bgpcfgd renders per address
      family from ``constants.yml``. frrcfgd drives it from BGP_GLOBALS_AF instead, and the
      YANG default is 1 -- so without this the switch silently collapses BGP multipath to a
      single path, which the fixture's name-only fingerprint cannot see (it broke ECMP
      expectations in frr mode while every object name was still present).
    """
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


# 'bgp graceful-restart ...' forms bgpcfgd renders from constants.yml, mapped to the
# BGP_GLOBALS fields frrcfgd drives them from (frrcfgd.py global_key_map; leaves confirmed in
# sonic-bgp-global.yang). Longest CLI form first -- 'bgp graceful-restart restart-time N'
# also starts with the bare 'bgp graceful-restart'.
#
# An entry whose ``value`` is None takes a trailing argument, so its CLI form is matched as a
# PREFIX; one with a literal value is a valueless line and is matched EXACTLY. The distinction
# is load-bearing: 'bgp graceful-restart-disable' (rendered on an UpperRegionalHub) starts with
# 'bgp graceful-restart', so a prefix match there would read an explicit disable as an enable
# and turn graceful restart ON in frr mode -- the exact inverse of the DUT's config.
_GLOBAL_FLAG_PREFIXES = (
    ("bgp graceful-restart restart-time ", "gr_restart_time", None),
    ("bgp graceful-restart stalepath-time ", "gr_stale_routes_time", None),
    ("bgp graceful-restart preserve-fw-state", "gr_preserve_fw_state", "true"),
    ("bgp graceful-restart", "graceful_restart_enable", "true"),
    ("no bgp ebgp-requires-policy", "ebgp_requires_policy", "false"),
    ("bgp bestpath as-path multipath-relax", "load_balance_mp_relax", "true"),
    # bgpcfgd renders this unconditionally (bgpd.main.conf.j2). frrcfgd DOES model it --
    # log_nbr_state_changes in global_key_map, leaf in sonic-bgp-global.yang -- so this was a
    # translation gap, not a frrcfgd one. Caught by the globals fingerprint on KVM t0.
    ("bgp log-neighbor-changes", "log_nbr_state_changes", "true"),
    ("no bgp log-neighbor-changes", "log_nbr_state_changes", "false"),
)

# Router-bgp-global lines bgpcfgd renders that frrcfgd cannot express. Matched as prefixes,
# and checked BEFORE _GLOBAL_FLAG_PREFIXES.
_GLOBAL_UNSUPPORTED_PREFIXES = (
    # global_key_map models restart-time / stalepath-time / preserve-fw-state only.
    ("bgp graceful-restart select-defer-time ",
     "frrcfgd's global_key_map has no select-defer-time field"),
    # frrcfgd's only lever is graceful_restart_enable, which renders 'no bgp graceful-restart'
    # -- FRR's *default* (still a GR helper for its peers), not the explicit
    # 'graceful-restart-disable' that also drops the helper role. Translating it would be a
    # behaviour change, so record it as a gap instead. Rendered on an UpperRegionalHub.
    ("bgp graceful-restart-disable",
     "frrcfgd can only render 'no bgp graceful-restart' (FRR's default helper state), which "
     "is not the same as an explicit graceful-restart-disable"),
    ("bgp long-lived-graceful-restart ",
     "frrcfgd has no long-lived-graceful-restart field"),
)


def _extract_global_flags(running_config):
    """BGP_GLOBALS fields for the router-bgp-level settings bgpcfgd renders from its
    templates/constants but frrcfgd drives from CONFIG_DB fields.

    Graceful restart is the load-bearing one: bgpcfgd renders ``bgp graceful-restart``,
    ``restart-time``, and ``preserve-fw-state`` on a ToR from constants.yml, while frrcfgd
    consumes none of those constants and renders GR only from explicit BGP_GLOBALS fields.
    Without this the DUT silently loses graceful restart the first time the bgp container
    restarts in frr mode.
    """
    fields = {}
    for af, line in _router_bgp_lines(running_config):
        if af:
            continue
        # Confederation membership. frrcfgd models the identifier as the confed_id leaf and
        # the peer ASNs as the confed_peers leaf-list (global_key_map / sonic-bgp-global.yang).
        # Dropping these silently un-confederates the DUT, which the fixture's name-only
        # fingerprint cannot see -- and test_bgp_confed_route_propagation reads both straight
        # out of the running config.
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
                    # Takes a trailing argument: prefix-match and read the argument.
                    if line.startswith(prefix):
                        fields[field] = line.split()[-1]
                        break
                # Valueless line: must match EXACTLY. See _GLOBAL_FLAG_PREFIXES.
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


def _build_neighbors(config_db, ipv4_pg, ipv6_pg, route_map_names, pg_by_neighbor=None):
    """Transform the traditional BGP_NEIGHBOR table into the frrcfgd VRF-keyed
    BGP_NEIGHBOR + BGP_NEIGHBOR_AF tables.

    ``pg_by_neighbor`` (from ``show bgp peer-group json``) gives each neighbor's real peer
    group; the per-family ``ipv4_pg``/``ipv6_pg`` are only the fallback for a neighbor FRR
    does not report as a member of any group."""
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
        af = _afi_safi(ip)
        pg = pg_by_neighbor.get(ip) or (ipv4_pg if af == "ipv4_unicast" else ipv6_pg)
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

    frrcfgd BGP_PEER_GROUP uses cmn_key_map (frrcfgd.py):
    ``asn``->remote-as, ``local_addr``->update-source, ``passive_mode``->passive,
    ``ebgp_multihop``(+``ebgp_multihop_ttl``)->ebgp-multihop. BGP_PEER_GROUP_AF carries
    ``route_map_in`` / ``route_map_out`` / ``soft_reconfiguration_in`` (frrcfgd.py)
    for each address-family the peer-group is activated in.

    Returns ``(peer_group, peer_group_af)`` dicts keyed like the other builders.
    """
    peer_group, peer_group_af = {}, {}
    for current_af, line in _router_bgp_lines(running_config):
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
                # frrcfgd.py). A listen-range peer-group has no explicit BGP_NEIGHBOR_AF
                # rows to carry the activation, so without this the peer-group is not
                # activated in the AF and dynamic (listen-range) peers never establish.
                af_row["admin_status"] = "up"
    return peer_group, peer_group_af


def _build_listen_prefixes(config_db):
    """Translate the traditional ``BGP_PEER_RANGE`` table (dynamic-neighbor listen
    ranges, e.g. for BGPSLBPassive / BGPVac) into frrcfgd's ``BGP_GLOBALS_LISTEN_PREFIX``
    (frrcfgd.py; yang key ``vrf_name|ip_prefix``, leaf ``peer_group`` ->
    ``bgp listen range <prefix> peer-group <pg>``). bgpcfgd consumes BGP_PEER_RANGE
    directly; frrcfgd expresses the same range through this table.

    A ``BGP_PEER_RANGE`` key may be qualified as ``<vrf-or-vnet>|<peer-group>``. Everything
    emitted here is keyed to :data:`DEFAULT_VRF`, so a non-default scope raises rather than
    being silently relocated into the default VRF -- which would produce a config with
    different semantics from the one being translated."""
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
# (frrcfgd.py -- 'unspecified' is treated as "emit nothing").
_AGG_VALID_ORIGINS = ("igp", "egp", "incomplete", "unspecified")

# Every field bgpcfgd's AggregateAddressMgr reads off a BGP_AGGREGATE_ADDRESS row
# (sonic-bgpcfgd/bgpcfgd/managers_aggregate_address.py). Anything outside
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
    (sonic-bgpcfgd/bgpcfgd/managers_bbr.py). The frrcfgd equivalent of
    ``allowas-in 1`` is ``allow_as_in='true'`` + ``allow_as_count='1'`` on the
    BGP_PEER_GROUP_AF row (nbr_af_key_map, frrcfgd.py -- the map is shared by
    BGP_PEER_GROUP_AF, frrcfgd.py). When disabled we leave the rows unset."""
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
    (route_map_key_map, frrcfgd.py; handler frrcfgd.py). We model it
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
    # No frrcfgd representation. This used to emit
    # ROUTE_MAP.set_extcommunity_bandwidth_type, but that leaf exists in NEITHER
    # sonic-route-map.yang NOR frrcfgd's route_map_key_map -- and it is not added by
    # sonic-buildimage#28543 either (verified against the PR's YANG diff). Writing an
    # unmodeled leaf is actively harmful: sonic_yang validates the WHOLE CONFIG_DB, so it
    # breaks every GCU apply-patch on the DUT, not just BGP ones.
    #
    # The frr_28543_compat shim happens to strip it today, but that file is documented for
    # deletion once #28543 lands -- at which point the bug would come back. So treat W-ECMP
    # as what it is: a genuine frrcfgd gap, consistent with BGP_DEVICE_GLOBAL being
    # unsupported (the TSA/IDF/W-ECMP modules are already frr_bgpcfgd_only).
    #
    # Closing it needs a new frrcfgd field, proposed on sonic-buildimage#28482. It must be an
    # opt-in knob the migrator sets, NOT a changed frrcfgd default -- same treatment as
    # ebgp_requires_policy in #28543 -- so existing installations keep their behaviour.
    logger.warning(
        "BGP_DEVICE_GLOBAL wcmp_enabled=true, but frrcfgd has no field for 'set extcommunity "
        "bandwidth num-multipaths' (no leaf in sonic-route-map.yang, and not added by "
        "sonic-buildimage#28543); frr mode will run without W-ECMP -- see "
        "sonic-buildimage#28482")


def _build_aggregate_addresses(config_db):
    """Translate the traditional ``BGP_AGGREGATE_ADDRESS`` table into frrcfgd's
    ``BGP_GLOBALS_AF_AGGREGATE_ADDR`` (registered frrcfgd.py; af_aggregate_key_map
    frrcfgd.py). The frr key is ``<vrf>|<afi_safi>|<ip_prefix>`` and the row
    carries ``as_set`` / ``summary_only`` / ``origin`` (frrcfgd.py).

    bgpcfgd's ``as-set`` / ``summary-only`` / ``origin``
    (managers_aggregate_address.py) map straight across. Three bgpcfgd fields
    have NO frr_mgmt_framework equivalent, so rather than silently drop them we fail
    loudly when they carry meaning:

    * ``bbr-required`` gates whether the aggregate is installed on BBR state
      (managers_aggregate_address.py) -- frrcfgd installs unconditionally;
    * ``aggregate-address-prefix-list`` / ``contributing-address-prefix-list`` add
      side prefix-lists (managers_aggregate_address.py) that frrcfgd's
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
                # 'unspecified' is frrcfgd's "emit nothing" sentinel (frrcfgd.py);
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

    ipv4_pg, ipv6_pg, all_pg_names, pg_by_neighbor = _peer_groups(peer_group_json)
    policy = _extract_policy_tables(running_config)
    # W-ECMP adds an outbound-route-map clause; fold it in before route_map_names
    # is snapshotted so peer-groups still resolve their route_map_out list.
    _apply_wcmp(result, policy, ipv4_pg, ipv6_pg)
    route_map_names = set(policy["ROUTE_MAP_SET"].keys())

    # _build_globals folds in the router-bgp-level settings bgpcfgd renders from its templates
    # and constants.yml but frrcfgd drives from BGP_GLOBALS fields -- graceful restart,
    # ebgp-requires-policy, multipath-relax. See _extract_global_flags.
    globals_tbl, af_network = _build_globals(result, bgp_asn, router_id, running_config)
    # suppress-fib-pending lives in DEVICE_METADATA rather than BGP_GLOBALS. bgpcfgd's template
    # renders 'bgp suppress-fib-pending' from it (bgpd.main.conf.j2).
    #
    # Correcting an earlier claim here: frrcfgd does NOT consume this field. Grepping the whole
    # sonic-frr-mgmt-framework tree for suppress-fib finds nothing -- no global_key_map entry
    # and no template line -- so the FRR line is genuinely lost in frr mode. It is recorded as
    # a gap in the fixture's FRRCFGD_UNSUPPORTED_GLOBAL_PREFIXES and reported on
    # sonic-buildimage#28482.
    #
    # The field is still carried across, because it is the CONFIG_DB source of truth
    # independent of which daemon renders FRR: it is YANG-modeled (sonic-device_metadata.yang),
    # it is what `config suppress-fib-pending` writes, and route_check.py reads it. Dropping it
    # would leave CONFIG_DB inconsistent on top of the missing FRR line.
    suppress_fib = "enabled" if any(
        ln.strip() == "bgp suppress-fib-pending" for ln in running_config.splitlines()) else "disabled"
    result.setdefault("DEVICE_METADATA", {}).setdefault("localhost", {})[
        "suppress-fib-pending"] = suppress_fib
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
    neighbors, neighbor_af = _build_neighbors(
        result, ipv4_pg, ipv6_pg, route_map_names, pg_by_neighbor)
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
    # Drop the traditional bgpcfgd tables now fully expressed in frr schema;
    # frrcfgd has no handler for them (table_handler_list, frrcfgd.py).
    result.pop("BGP_AGGREGATE_ADDRESS", None)
    result.pop("BGP_BBR", None)
    result.pop("BGP_PEER_RANGE", None)
    return result

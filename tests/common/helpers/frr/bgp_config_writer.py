"""Mode-aware writer for bgpcfgd-format CONFIG_DB rows.

``write_bgp_config`` writes the rows as-is in traditional (bgpcfgd) mode. In
frr_mgmt_framework mode it converts them with ``to_frr_rows`` -- reusing the
bgp_config_translation builders where one exists -- and writes the frrcfgd rows instead.
Only the tables below are converted; any other table raises FrrTranslationError.
"""
import json
import time

import yaml

from tests.common.helpers.frr.bgp_config_translation import (
    DEFAULT_VRF, FrrTranslationError, _afi_safi, _apply_bbr, _bgp_asn, _build_listen_prefixes)

CONSTANTS_FILE = "/etc/sonic/constants.yml"
STAGING_FILE = "/tmp/bgp_config_writer.json"


def namespace_cli_arg(namespace):
    # Same as tests.common.helpers.bgp, which cannot be imported by the unit tests.
    return "-n {}".format(namespace) if namespace else ""


# --------------------------------------------------------------------------- #
# BGP allow-list -- traditional (bgpcfgd) vs frr_mgmt_framework (frrcfgd)
#
# In traditional mode bgpcfgd owns the BGP_ALLOWED_PREFIXES convenience table and
# decomposes it into FRR prefix-lists, community-lists and a per-deployment
# route-map (see sonic-bgpcfgd/bgpcfgd/managers_allow_list.py). frrcfgd does NOT
# consume BGP_ALLOWED_PREFIXES, so in frr mode we reproduce exactly the FRR state
# bgpcfgd would render, but through frrcfgd's own CONFIG_DB schema.
#
# For one BGP_ALLOWED_PREFIXES entry, e.g.::
#
#   "DEPLOYMENT_ID|0|1010:1010": {prefixes_v4: ["172.16.30.0/24"],
#                                 prefixes_v6: ["2000:172:16:30::/64"],
#                                 default_action: "permit"}
#
# we write (mirroring bgpcfgd's names/seqs):
#
#   PREFIX_SET|PL_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_1010:1010_V4  {mode: IPv4}
#   PREFIX|PL_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_1010:1010_V4|10|172.16.30.0/24|exact
#                                                                   {action: permit}
#   COMMUNITY_SET|COMMUNITY_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_1010:1010
#           {set_type: standard, match_action: all, community_member: [1010:1010],
#            action: permit}   -> "bgp community-list standard <name> permit 1010:1010"
#   ROUTE_MAP|ALLOW_LIST_DEPLOYMENT_ID_0_V4|10
#           {route_operation: permit, match_prefix_set: <PL>, match_community: <CL>}
#   ROUTE_MAP|ALLOW_LIST_DEPLOYMENT_ID_0_V4|30000   (no-community deployment entry)
#           {route_operation: permit, match_prefix_set: PL_..._empty_V4}
#   ROUTE_MAP|ALLOW_LIST_DEPLOYMENT_ID_0_V4|65535   (default rule)
#           {route_operation: permit,
#            set_community_inline: [<drop_community|no-export>, additive]}
#              -> "set community <c> additive"
#
# route_operation/seq -> "route-map <NAME> permit <seq>" (frrcfgd.py);
# match_prefix_set -> "match ip[v6] address prefix-list" with the af resolved from
# the referenced PREFIX_SET (frrcfgd.py); match_community -> "match community"; and
# set_community_inline (a space-joined list, so a trailing 'additive' element renders
# as "set community <c> additive") (frrcfgd.py).
#
# The route-map is attached inbound by overwriting route_map_in on every
# BGP_PEER_GROUP_AF that already has an inbound route-map (nbr_af_key_map
# route_map_in, frrcfgd.py) -- this replaces the peer-group's stock inbound
# map with our allow-list map for the duration of the test; the originals are
# stashed and restored by remove_allow_list. bgpcfgd instead wires the map in via
# a `call` from the stock inbound map; overwriting route_map_in is the frr-schema
# way to reach the same inbound filtering without editing the stock map's clauses.
# Default seq 65535 tags every not-explicitly-allowed prefix: with
# default_action=permit that is the drop_community (routes still forwarded but
# marked); with default_action=deny it is no-export (routes not re-advertised to
# eBGP neighbors) -- matching bgpcfgd's __get_default_action_community.
# --------------------------------------------------------------------------- #
def _allow_list_as_prefix_list(value):
    """Return the prefixes as a list, accepting either a python list or a
    comma-separated string (both shapes appear in BGP_ALLOWED_PREFIXES data).
    Entries are whitespace-stripped, so a value written as "a, b" does not produce a
    prefix with a leading space that no prefix-list would ever match."""
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = str(value).split(',')
    return [str(p).strip() for p in items if str(p).strip()]


def _allow_list_default_pl_rules(al_constants, ver):
    """The ``default_pl_rules`` bgpcfgd prepends to EVERY generated allow-list
    prefix-list (BGPAllowListMgr.__load_constant_lists / __update_prefix_list).

    These are the guards, not decoration: the v4 set is
    ``deny 0.0.0.0/0 le 17`` + ``permit 127.0.0.1/32``, and the v6 set denies
    ``0::/0 le 59`` and ``0::/0 ge 65``. Omitting them made a configured /17-or-shorter
    prefix reachable and lost the loopback exception, so the frr-mode policy was strictly
    more permissive than the bgpcfgd one it is supposed to reproduce.
    """
    rules = al_constants.get('default_pl_rules') or {}
    return list(rules.get('v{}'.format(ver)) or [])


def _allow_list_prefix_rules(prefixes, ver):
    """Convert allow-list prefixes into bgpcfgd's prefix-list rule strings
    (BGPAllowListMgr.__to_prefix_list): a prefix that already carries ge/le is passed
    through, a host prefix is an exact permit, and anything shorter permits more-specifics
    up to the family's host length."""
    host_len = 32 if ver == '4' else 128
    rules = []
    for prefix in prefixes:
        if 'le' in prefix or 'ge' in prefix:
            rules.append('permit {}'.format(prefix))
            continue
        try:
            masklen = int(prefix.split('/')[1])
        except (IndexError, ValueError):
            rules.append('permit {}'.format(prefix))
            continue
        if masklen == host_len:
            rules.append('permit {}'.format(prefix))
        else:
            rules.append('permit {} le {}'.format(prefix, host_len))
    return rules


def _frr_prefix_key_parts(rule, ver):
    """Parse a bgpcfgd prefix-list rule ('deny 0.0.0.0/0 le 17') into the frrcfgd PREFIX
    row's (action, ip_prefix, masklength_range).

    masklength_range follows frrcfgd's own encoding: 'ge..le', 'ge..<host-len>',
    '<prefix-len>..le', or 'exact' when neither bound is present."""
    parts = rule.split()
    action, prefix = parts[0], parts[1]
    host_len = '32' if ver == '4' else '128'
    ge = parts[parts.index('ge') + 1] if 'ge' in parts else None
    le = parts[parts.index('le') + 1] if 'le' in parts else None
    plen = prefix.split('/')[1] if '/' in prefix else host_len
    if ge and le:
        mask_range = '{}..{}'.format(ge, le)
    elif ge:
        mask_range = '{}..{}'.format(ge, host_len)
    elif le:
        mask_range = '{}..{}'.format(plen, le)
    else:
        mask_range = 'exact'
    return action, prefix, mask_range


def _parse_allow_list_key(raw_key):
    """Split a BGP_ALLOWED_PREFIXES key into (deployment_id, community, neighbor_type).

    BGPAllowListMgr.set_handler accepts four forms, and the naming templates differ by
    whether a neighbor type is present::

        DEPLOYMENT_ID|<id>                                    -> community 'empty', no neighbor
        DEPLOYMENT_ID|<id>|<community>                        -> community only
        DEPLOYMENT_ID|<id>|NEIGHBOR_TYPE|<type>               -> neighbor only, community 'empty'
        DEPLOYMENT_ID|<id>|NEIGHBOR_TYPE|<type>|<community>   -> both

    Taking ``key.split('|')[2]`` as the community handled only the first two, and read the
    literal token 'NEIGHBOR_TYPE' as the community for the other two.
    """
    if not raw_key.startswith('DEPLOYMENT_ID|'):
        raise ValueError("Unsupported BGP_ALLOWED_PREFIXES key {!r}: expected it to start "
                         "with 'DEPLOYMENT_ID|'".format(raw_key))
    if '|NEIGHBOR_TYPE|' in raw_key:
        head, tail = raw_key.split('|NEIGHBOR_TYPE|', 1)
        deployment_id = head[len('DEPLOYMENT_ID|'):]
        neighbor_type, community = tail.split('|', 1) if '|' in tail else (tail, None)
    else:
        rest = raw_key[len('DEPLOYMENT_ID|'):]
        deployment_id, community = rest.split('|', 1) if '|' in rest else (rest, None)
        neighbor_type = None
    if not deployment_id.isdigit():
        raise ValueError("Unsupported BGP_ALLOWED_PREFIXES key {!r}: {!r} is not a numeric "
                         "deployment id".format(raw_key, deployment_id))
    return deployment_id, community, neighbor_type


def _allow_list_names(deployment_id, community, neighbor_type, ver):
    """The prefix-list / community-list / route-map names bgpcfgd would generate for this
    entry (BGPAllowListMgr's *_TMPL constants). The _WITH_NEIGH templates insert
    ``NEIGHBOR_<type>`` and are what makes a neighbor-type entry a distinct policy rather
    than a collision with the plain one."""
    comm_token = community if community else 'empty'
    if neighbor_type:
        return (
            'PL_ALLOW_LIST_DEPLOYMENT_ID_{}_NEIGHBOR_{}_COMMUNITY_{}_V{}'.format(
                deployment_id, neighbor_type, comm_token, ver),
            'COMMUNITY_ALLOW_LIST_DEPLOYMENT_ID_{}_NEIGHBOR_{}_COMMUNITY_{}'.format(
                deployment_id, neighbor_type, comm_token),
            'ALLOW_LIST_DEPLOYMENT_ID_{}_NEIGHBOR_{}_V{}'.format(
                deployment_id, neighbor_type, ver),
        )
    return (
        'PL_ALLOW_LIST_DEPLOYMENT_ID_{}_COMMUNITY_{}_V{}'.format(
            deployment_id, comm_token, ver),
        'COMMUNITY_ALLOW_LIST_DEPLOYMENT_ID_{}_COMMUNITY_{}'.format(
            deployment_id, comm_token),
        'ALLOW_LIST_DEPLOYMENT_ID_{}_V{}'.format(deployment_id, ver),
    )


def _build_allow_list_frr_config(allow_list, drop_community, al_constants):
    """Translate the test's BGP_ALLOWED_PREFIXES dict into the frrcfgd-native
    CONFIG_DB tables. Returns (tables, rms_by_af, created_keys).

    * tables       -- {table: {key: value}} to feed to sonic-cfggen -w
    * rms_by_af    -- {'ipv4_unicast': {<rm name>, ...}, 'ipv6_unicast': {...}} -- every
                      generated route-map for that address family. A set, not one name:
                      the input may carry several deployment ids / neighbor types, and
                      keeping a single slot per AF silently dropped all but the last.
    * created_keys -- [(table, key), ...] written by this helper
    """
    tables = {'PREFIX_SET': {}, 'PREFIX': {}, 'COMMUNITY_SET': {}, 'ROUTE_MAP': {}}
    created_keys = []
    rms_by_af = {'ipv4_unicast': set(), 'ipv6_unicast': set()}

    def add(table, key, value):
        tables[table][key] = value
        created_keys.append((table, key))

    # Group entries by the (deployment_id, neighbor_type) policy they belong to; each
    # policy gets one V4 + one V6 route-map, exactly as bgpcfgd names them.
    policies = {}
    for raw_key, data in list(allow_list.get('BGP_ALLOWED_PREFIXES', {}).items()):
        deployment_id, community, neighbor_type = _parse_allow_list_key(raw_key)
        policies.setdefault((deployment_id, neighbor_type), []).append((community, data))

    for (deployment_id, neighbor_type), entries in list(policies.items()):
        default_action = ''
        for af, ver, plist_key in (('ipv4', '4', 'prefixes_v4'), ('ipv6', '6', 'prefixes_v6')):
            _, _, rm_name = _allow_list_names(deployment_id, None, neighbor_type, ver)
            rms_by_af['{}_unicast'.format(af)].add(rm_name)
            # Community entries get seq 10.. (bgpcfgd 10..29990); no-community
            # deployment entries get seq 30000.. (bgpcfgd 30000..65530).
            cur_with = 10
            cur_without = 30000
            for community, data in entries:
                default_action = data.get('default_action', '') or default_action
                prefixes = _allow_list_as_prefix_list(data.get(plist_key))
                if not prefixes:
                    continue
                pl_name, cl_name, _ = _allow_list_names(
                    deployment_id, community, neighbor_type, ver)
                add('PREFIX_SET', pl_name, {'mode': 'IPv4' if af == 'ipv4' else 'IPv6'})
                # bgpcfgd renders constants' default_pl_rules FIRST, then the allow-list
                # prefixes, numbering the combined list from seq 10 in steps of 10.
                pl_seq = 10
                rules = (_allow_list_default_pl_rules(al_constants, ver)
                         + _allow_list_prefix_rules(prefixes, ver))
                for rule in rules:
                    action, prefix, mask_range = _frr_prefix_key_parts(rule, ver)
                    add('PREFIX', '{}|{}|{}|{}'.format(pl_name, pl_seq, prefix, mask_range),
                        {'action': action})
                    pl_seq += 10
                rm_entry = {'route_operation': 'permit', 'match_prefix_set': pl_name}
                if community:
                    add('COMMUNITY_SET', cl_name,
                        {'set_type': 'standard', 'match_action': 'all',
                         'community_member': [community], 'action': 'permit'})
                    rm_entry['match_community'] = cl_name
                    rm_seq = cur_with
                    cur_with += 10
                else:
                    rm_seq = cur_without
                    cur_without += 10
                add('ROUTE_MAP', '{}|{}'.format(rm_name, rm_seq), rm_entry)
            # Default rule (seq 65535): tag everything not explicitly allowed.
            drop = 'no-export' if default_action == 'deny' else drop_community
            add('ROUTE_MAP', '{}|65535'.format(rm_name),
                {'route_operation': 'permit', 'set_community_inline': [drop, 'additive']})

    return tables, rms_by_af, created_keys


def _allow_list_rows(rows, config_db, constants):
    al = constants.get("constants", {}).get("bgp", {}).get("allow_list", {}) or {}
    tables, _, _ = _build_allow_list_frr_config(
        {"BGP_ALLOWED_PREFIXES": rows}, al["drop_community"], al)
    return tables, {}, set()


def get_bbr_peer_group_afs(constants):
    """Return the BBR-eligible ``{peer-group: [afi_safi, ...]}`` from constants.yml.

    Computed the way ``BBRMgr.__read_pgs`` does: the union of
    ``constants.bgp.peers.<peer_type>.bbr``, e.g. ``{'PEER_V4': ['ipv4_unicast'],
    'PEER_V6': ['ipv6_unicast']}``. bgpcfgd applies ``allowas-in 1`` to exactly these
    peer-group/address-family pairs and no others.
    """
    peers = (constants.get("constants", {}).get("bgp", {}).get("peers") or {})
    result = {}
    for value in peers.values():
        for pg_name, pg_afs in ((value or {}).get("bbr") or {}).items():
            result[pg_name] = ["{}_unicast".format(af) for af in (pg_afs or [])]
    return result


def _bbr_rows(rows, config_db, constants):
    """BGP_BBR|all -> allowas-in on the BBR-eligible BGP_PEER_GROUP_AF rows. Enabling
    reuses _apply_bbr; disabling has to remove fields, which a cfggen write cannot."""
    eligible = get_bbr_peer_group_afs(constants)
    af_rows = {}
    for key in config_db.get("BGP_PEER_GROUP_AF", {}):
        fields = key.split("|")            # <vrf>|<pg>|<afi_safi>
        if len(fields) == 3 and fields[2] in eligible.get(fields[1], []):
            af_rows[key] = {}
    _apply_bbr({"BGP_BBR": rows}, af_rows)
    peer_groups = {key.split("|")[1] for key in af_rows}
    if rows["all"].get("status") == "enabled":
        return {"BGP_PEER_GROUP_AF": af_rows}, {}, peer_groups
    return {}, {"BGP_PEER_GROUP_AF|" + k: ["allow_as_in", "allow_as_count"] for k in af_rows}, peer_groups


def _peer_range_rows(rows, config_db, constants):
    """BGP_PEER_RANGE -> listen prefix (_build_listen_prefixes) plus the peer-group and
    AF rows bgpcfgd renders from its BGPSLBPassive template, which the translator only
    reads back from running-config."""
    local_asn = _bgp_asn(config_db)
    tables = {"BGP_GLOBALS_LISTEN_PREFIX": _build_listen_prefixes({"BGP_PEER_RANGE": rows}),
              "BGP_PEER_GROUP": {}, "BGP_PEER_GROUP_AF": {}}
    for key, row in rows.items():
        pg = row.get("name") or key.split("|")[-1]
        tables["BGP_PEER_GROUP"]["{}|{}".format(DEFAULT_VRF, pg)] = {
            "asn": row["peer_asn"], "local_addr": row["src_address"], "local_asn": local_asn,
            "name": pg, "passive_mode": "true", "ebgp_multihop": "true",
            "peer_group_name": pg, "vrf_name": DEFAULT_VRF}
        for af in sorted({_afi_safi(p.split("/")[0]) for p in row.get("ip_range", [])}):
            tables["BGP_PEER_GROUP_AF"]["{}|{}|{}".format(DEFAULT_VRF, pg, af)] = {
                "admin_status": "up", "afi_safi": af, "peer_group_name": pg,
                "route_map_in": ["FROM_BGP_SPEAKER"], "route_map_out": ["TO_BGP_SPEAKER"],
                "soft_reconfiguration_in": "true", "vrf_name": DEFAULT_VRF}
    return tables, {}, set()


_CONVERTERS = {
    "BGP_ALLOWED_PREFIXES": _allow_list_rows,
    "BGP_BBR": _bbr_rows,
    "BGP_PEER_RANGE": _peer_range_rows,
}


def to_frr_rows(rows, config_db, constants):
    """Convert bgpcfgd-format ``{table: {key: row}}`` into frrcfgd rows.

    Returns ``(tables, del_fields, peer_groups)``: the rows to write, the
    ``{'TABLE|key': [field, ...]}`` to remove, and the peer-groups to soft-clear.
    """
    tables, del_fields, peer_groups = {}, {}, set()
    for table, table_rows in rows.items():
        if table not in _CONVERTERS:
            raise FrrTranslationError("No frrcfgd conversion for {}".format(table))
        t, d, p = _CONVERTERS[table](table_rows, config_db, constants)
        for name, out in t.items():
            tables.setdefault(name, {}).update(out)
        del_fields.update(d)
        peer_groups |= p
    return {t: r for t, r in tables.items() if r}, del_fields, peer_groups


def cfggen_write(duthost, tables, namespace=None):
    duthost.copy(content=json.dumps(tables, indent=3), dest=STAGING_FILE)
    duthost.shell("sonic-cfggen {} -j {} -w".format(namespace_cli_arg(namespace), STAGING_FILE))
    duthost.shell("rm -f {}".format(STAGING_FILE), module_ignore_errors=True)


def read_frr_inputs(duthost, namespace=None):
    """The running CONFIG_DB and constants.yml that to_frr_rows converts against."""
    config_db = json.loads(duthost.shell(
        "sonic-cfggen {} -d --print-data".format(namespace_cli_arg(namespace)))["stdout"])
    constants = yaml.safe_load(duthost.shell("cat {}".format(CONSTANTS_FILE))["stdout"])
    return config_db, constants


def write_bgp_config(duthost, rows, namespace=None, delete=False):
    """Write (or with ``delete``, remove) bgpcfgd-format rows in the DUT's FRR config mode."""
    db_cli = "sonic-db-cli {}".format(namespace_cli_arg(namespace)).rstrip()
    del_fields, peer_groups = {}, set()
    if duthost.get_frr_mgmt_framework_config():
        rows, del_fields, peer_groups = to_frr_rows(rows, *read_frr_inputs(duthost, namespace))
    if delete:
        for table, table_rows in rows.items():
            for key in table_rows:
                duthost.shell("{} CONFIG_DB del '{}|{}'".format(db_cli, table, key),
                              module_ignore_errors=True)
    elif rows:
        cfggen_write(duthost, rows, namespace)
    for key, fields in del_fields.items():
        duthost.shell("{} CONFIG_DB hdel '{}' {}".format(db_cli, key, " ".join(fields)))
    time.sleep(3)
    if peer_groups:
        # Re-evaluate already-received routes, as bgpcfgd's restart_peer_groups does.
        asichost = duthost.asic_instance_from_namespace(namespace)
        for pg in sorted(peer_groups):
            asichost.run_vtysh('-c "clear bgp peer-group {} soft in"'.format(pg))
        time.sleep(3)

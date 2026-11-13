"""Write bgpcfgd-format CONFIG_DB rows as-is, or converted to frrcfgd rows in frr_mgmt_framework mode."""
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


# BGP allow-list: frrcfgd ignores BGP_ALLOWED_PREFIXES, so render the PREFIX_SET/PREFIX/COMMUNITY_SET/ROUTE_MAP
# rows bgpcfgd's managers_allow_list.py would (same names and seqs; seq 65535 tags everything else).
def _allow_list_as_prefix_list(value):
    """Return the prefixes (list or comma-separated string) as a whitespace-stripped list."""
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = str(value).split(',')
    return [str(p).strip() for p in items if str(p).strip()]


def _allow_list_default_pl_rules(al_constants, ver):
    """The ``default_pl_rules`` guards bgpcfgd prepends to every allow-list prefix-list."""
    rules = al_constants.get('default_pl_rules') or {}
    return list(rules.get('v{}'.format(ver)) or [])


def _allow_list_prefix_rules(prefixes, ver):
    """Convert allow-list prefixes into bgpcfgd's prefix-list rule strings (BGPAllowListMgr.__to_prefix_list)."""
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
    """Parse a bgpcfgd prefix-list rule into the frrcfgd PREFIX row's (action, ip_prefix, masklength_range)."""
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
    """Split ``DEPLOYMENT_ID|<id>[|NEIGHBOR_TYPE|<type>][|<community>]`` into (id, community, neighbor_type)."""
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
    """The prefix-list / community-list / route-map names bgpcfgd generates (BGPAllowListMgr's *_TMPL)."""
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
    """Translate BGP_ALLOWED_PREFIXES into frrcfgd tables; returns (tables, rms_by_af, created_keys)."""
    tables = {'PREFIX_SET': {}, 'PREFIX': {}, 'COMMUNITY_SET': {}, 'ROUTE_MAP': {}}
    created_keys = []
    rms_by_af = {'ipv4_unicast': set(), 'ipv6_unicast': set()}

    def add(table, key, value):
        tables[table][key] = value
        created_keys.append((table, key))

    # One V4 + one V6 route-map per (deployment_id, neighbor_type) policy.
    policies = {}
    for raw_key, data in list(allow_list.get('BGP_ALLOWED_PREFIXES', {}).items()):
        deployment_id, community, neighbor_type = _parse_allow_list_key(raw_key)
        policies.setdefault((deployment_id, neighbor_type), []).append((community, data))

    for (deployment_id, neighbor_type), entries in list(policies.items()):
        default_action = ''
        for af, ver, plist_key in (('ipv4', '4', 'prefixes_v4'), ('ipv6', '6', 'prefixes_v6')):
            _, _, rm_name = _allow_list_names(deployment_id, None, neighbor_type, ver)
            rms_by_af['{}_unicast'.format(af)].add(rm_name)
            # Community entries from seq 10, no-community entries from 30000 (as bgpcfgd).
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
                # default_pl_rules first, then the prefixes, seq 10 in steps of 10 (as bgpcfgd).
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
    """Return the BBR-eligible ``{peer-group: [afi_safi, ...]}`` from constants.yml, as BBRMgr.__read_pgs does."""
    peers = (constants.get("constants", {}).get("bgp", {}).get("peers") or {})
    result = {}
    for value in peers.values():
        for pg_name, pg_afs in ((value or {}).get("bbr") or {}).items():
            result[pg_name] = ["{}_unicast".format(af) for af in (pg_afs or [])]
    return result


def _bbr_rows(rows, config_db, constants):
    """BGP_BBR|all -> allowas-in on BBR-eligible BGP_PEER_GROUP_AF rows (disable removes the fields)."""
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
    """BGP_PEER_RANGE -> listen prefix plus the peer-group/AF rows of bgpcfgd's BGPSLBPassive template."""
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
    """Convert bgpcfgd-format rows; returns (tables to write, {'TABLE|key': fields} to remove, peer-groups)."""
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

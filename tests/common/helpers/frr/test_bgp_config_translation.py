"""Offline unit tests for the bgpcfgd -> frr_mgmt_framework BGP config translation."""
import json

import pytest

from tests.common.helpers.frr.bgp_config_translation import (
    translate_config_db,
    FrrTranslationError,
    FrrTranslationGap,
)

pytestmark = [
    pytest.mark.topology('any')
]


def _base_config_db():
    return {
        "DEVICE_METADATA": {"localhost": {"bgp_asn": "65100"}},
        "LOOPBACK_INTERFACE": {
            "Loopback0": {"10.1.0.32/32": {}, "fc00:1::32/128": {}},
        },
        "BGP_NEIGHBOR": {
            "10.0.0.1": {
                "admin_status": "up", "asn": "65200", "holdtime": "10",
                "keepalive": "3", "local_addr": "10.0.0.0", "name": "ARISTA01T2",
                "nhopself": "0", "rrclient": "0",
            },
            "fc00::6": {
                "admin_status": "up", "asn": "65200", "holdtime": "10",
                "keepalive": "3", "local_addr": "fc00::5", "name": "ARISTA02T2",
                "nhopself": "0", "rrclient": "0",
            },
        },
    }


def _peer_group_json():
    return {
        "PEER_V4": {"members": {"10.0.0.1": {}}, "addressFamilyInfo": "IPv4 Unicast"},
        "PEER_V6": {"members": {"fc00::6": {}}, "addressFamilyInfo": "IPv6 Unicast"},
    }


def _tr(running=(), cfg=None, pg_json=None):
    """Translate; ``running`` is a list of running-config lines."""
    return translate_config_db(_base_config_db() if cfg is None else cfg, "\n".join(running),
                               _peer_group_json() if pg_json is None else pg_json)


def _cfg(**tables):
    cfg = _base_config_db()
    cfg.update(tables)
    return cfg


def test_neighbor_v6_matches_captured_ground_truth():
    out = _tr()
    assert out["BGP_NEIGHBOR"]["default|fc00::6"] == {
        "asn": "65200", "holdtime": "10", "keepalive": "3", "local_addr": "fc00::5",
        "name": "ARISTA02T2", "admin_status": "up", "neighbor": "fc00::6",
        "peer_group_name": "PEER_V6", "vrf_name": "default",
    }
    assert out["BGP_NEIGHBOR_AF"]["default|fc00::6|ipv6_unicast"]["afi_safi"] == "ipv6_unicast"
    assert out["BGP_NEIGHBOR_AF"]["default|fc00::6|ipv6_unicast"]["admin_status"] == "up"


def test_neighbor_v4_gets_v4_peer_group_and_af():
    out = _tr()
    nbr = out["BGP_NEIGHBOR"]["default|10.0.0.1"]
    assert nbr["peer_group_name"] == "PEER_V4"
    assert nbr["asn"] == "65200" and nbr["local_addr"] == "10.0.0.0"
    assert "nhopself" not in nbr and "rrclient" not in nbr
    assert "default|10.0.0.1|ipv4_unicast" in out["BGP_NEIGHBOR_AF"]
    assert "10.0.0.1" not in out["BGP_NEIGHBOR"]


def test_globals_and_router_id():
    out = _tr()
    assert out["BGP_GLOBALS"]["default"]["local_asn"] == "65100"
    assert out["BGP_GLOBALS"]["default"]["router_id"] == "10.1.0.32"
    assert "default|ipv4_unicast|10.1.0.32/32" in out["BGP_GLOBALS_AF_NETWORK"]
    assert "default|ipv6_unicast|fc00:1::32/128" in out["BGP_GLOBALS_AF_NETWORK"]


def test_peer_groups_built():
    out = _tr()
    assert out["BGP_PEER_GROUP"]["default|PEER_V4"]["local_asn"] == "65100"
    assert out["BGP_PEER_GROUP"]["default|PEER_V6"]["peer_group_name"] == "PEER_V6"
    assert out["BGP_PEER_GROUP_AF"]["default|PEER_V4|ipv4_unicast"]["soft_reconfiguration_in"] == "true"


def test_prefix_list_parsing():
    out = _tr(["ip prefix-list PL_V4 seq 10 permit 10.0.0.0/8 le 32",
               "ipv6 prefix-list PL_V6 seq 5 permit 2001:db8::/32"])
    assert out["PREFIX_SET"]["PL_V4"] == {"name": "PL_V4", "mode": "IPv4"}
    assert out["PREFIX_SET"]["PL_V6"] == {"name": "PL_V6", "mode": "IPv6"}
    assert out["PREFIX"]["PL_V4|10|10.0.0.0/8|8..32"]["action"] == "permit"
    assert out["PREFIX"]["PL_V6|5|2001:db8::/32|exact"]["sequence_number"] == 5


def test_community_list_parsing():
    out = _tr(["bgp community-list standard CL1 permit 65100:100"])
    assert out["COMMUNITY_SET"]["CL1"]["community_member"] == ["65100:100"]
    assert out["COMMUNITY_SET"]["CL1"]["action"] == "permit"
    assert out["COMMUNITY_SET"]["CL1"]["set_type"] == "STANDARD"


def test_route_map_name_preserved():
    out = _tr(["route-map FROM_BGP_PEER_V4 permit 10", " match community CL1",
               "route-map TO_BGP_PEER_V4 permit 10"])
    assert out["ROUTE_MAP_SET"]["FROM_BGP_PEER_V4"] == {"name": "FROM_BGP_PEER_V4"}
    assert out["ROUTE_MAP"]["FROM_BGP_PEER_V4|10"]["match_community"] == "CL1"
    assert out["ROUTE_MAP"]["FROM_BGP_PEER_V4|10"]["route_operation"] == "permit"
    assert out["BGP_NEIGHBOR_AF"]["default|10.0.0.1|ipv4_unicast"]["route_map_in"] == ["FROM_BGP_PEER_V4"]


def test_set_community_additive_kept_in_inline_list():
    # frrcfgd has no set_community_additive field; it space-joins the inline list.
    rm = _tr(["route-map SET_COMM permit 10",
              " set community 65100:100 65100:200 additive"])["ROUTE_MAP"]["SET_COMM|10"]
    assert rm["set_community_inline"] == ["65100:100", "65100:200", "additive"]
    assert "set_community_additive" not in rm


def test_neighbor_admin_status_down_is_preserved():
    cfg = _base_config_db()
    cfg["BGP_NEIGHBOR"]["10.0.0.1"]["admin_status"] = "down"
    out = _tr(cfg=cfg)
    assert out["BGP_NEIGHBOR"]["default|10.0.0.1"]["admin_status"] == "down"
    assert out["BGP_NEIGHBOR_AF"]["default|10.0.0.1|ipv4_unicast"]["admin_status"] == "down"


@pytest.mark.parametrize("value,expected", [("1", "true"), ("0", None)])
def test_neighbor_rrclient_nhself_on_af(value, expected):
    cfg = _base_config_db()
    cfg["BGP_NEIGHBOR"]["10.0.0.1"].update({"rrclient": value, "nhopself": value})
    af = _tr(cfg=cfg)["BGP_NEIGHBOR_AF"]["default|10.0.0.1|ipv4_unicast"]
    assert (af.get("rrclient"), af.get("nhself")) == (expected, expected)


@pytest.mark.parametrize("status,expected", [
    ("enabled", {"allow_as_in": "true", "allow_as_count": "1"}),
    ("disabled", {"allow_as_in": None, "allow_as_count": None}),
])
def test_bbr_sets_allow_as_in_on_peer_group_afs(status, expected):
    out = _tr(cfg=_cfg(BGP_BBR={"all": {"status": status}}))
    for af_key in ("default|PEER_V4|ipv4_unicast", "default|PEER_V6|ipv6_unicast"):
        row = out["BGP_PEER_GROUP_AF"][af_key]
        assert {k: row.get(k) for k in expected} == expected
    assert "BGP_BBR" not in out


@pytest.mark.parametrize("state", [{"wcmp_enabled": "true", "tsa_enabled": "false"},
                                   {"wcmp_enabled": "false"}])
def test_wcmp_emits_no_unmodeled_field(state):
    # set_extcommunity_bandwidth_type is not in sonic-route-map.yang; emitting it breaks GCU.
    out = _tr(cfg=_cfg(BGP_DEVICE_GLOBAL={"STATE": state}))
    for name in ("TO_BGP_PEER_V4", "TO_BGP_PEER_V6"):
        assert "{}|100".format(name) not in out.get("ROUTE_MAP", {})
    assert "set_extcommunity_bandwidth_type" not in json.dumps(out)


def test_aggregate_address_maps_to_globals_af_aggregate_addr():
    out = _tr(cfg=_cfg(BGP_AGGREGATE_ADDRESS={
        "192.168.0.0/16": {"as-set": "true", "summary-only": "true", "origin": "igp"},
        "fc00:100::/48": {"as-set": "false", "summary-only": "false"},
        "10.9.0.0/16": {"origin": "unspecified"},
    }))
    agg = out["BGP_GLOBALS_AF_AGGREGATE_ADDR"]
    assert agg["default|ipv4_unicast|192.168.0.0/16"] == {"as_set": "true", "summary_only": "true", "origin": "igp"}
    assert agg["default|ipv6_unicast|fc00:100::/48"] == {"as_set": "false", "summary_only": "false"}
    assert agg["default|ipv4_unicast|10.9.0.0/16"] == {}
    assert "BGP_AGGREGATE_ADDRESS" not in out


def _set_in(table, key, value):
    def mutate(cfg):
        cfg.setdefault(table, {})[key] = value
    return mutate


@pytest.mark.parametrize("mutate,match", [
    (lambda cfg: cfg.pop("BGP_NEIGHBOR"), None),
    (_set_in("DEVICE_METADATA", "localhost", {}), None),
    (lambda cfg: cfg.pop("LOOPBACK_INTERFACE"), None),
    (_set_in("BGP_NEIGHBOR", "not-an-ip", {"asn": "65200"}), None),
    (_set_in("BGP_NEIGHBOR", "Vnet1|10.0.0.9", {"admin_status": "up", "asn": "65300"}), "VNET"),
    (_set_in("BGP_AGGREGATE_ADDRESS", "10.0.0.0/16", {"bbr-required": "true"}), None),
    (_set_in("BGP_AGGREGATE_ADDRESS", "10.0.0.0/16", {"aggregate-address-prefix-list": "PL_AGG"}), None),
    (_set_in("BGP_AGGREGATE_ADDRESS", "10.0.0.0/16", {"bogus-field": "x"}), None),
    (_set_in("BGP_BBR", "all", {"status": "maybe"}), None),
    (_set_in("BGP_DEVICE_GLOBAL", "STATE", {"wcmp_enabled": "yes"}), None),
    (_set_in("BGP_PEER_RANGE", "Vnet1|BGPVac", {"ip_range": ["10.255.0.0/25"], "name": "BGPVac"}), None),
], ids=["no-neighbor", "no-asn", "no-loopback", "bad-neighbor-addr", "vnet-neighbor", "agg-bbr-required",
        "agg-prefix-list", "agg-unknown-field", "bad-bbr-status", "bad-wcmp", "vrf-peer-range"])
def test_config_db_raises(mutate, match):
    cfg = _base_config_db()
    mutate(cfg)
    with pytest.raises(FrrTranslationError, match=match):
        _tr(cfg=cfg)


@pytest.mark.parametrize("running", [
    ["ip prefix-list BROKEN permit 10.0.0.0/8"],
    ["route-map RM_X permit 10", " on-match bogus"],
    ["route-map RM_X permit 10", " match ip address prefix-list PL_A", " match ipv6 address prefix-list PL_B"],
    ["route-map RM_X permit 10", " set some-brand-new-clause 5"],
], ids=["malformed-prefix-list", "bad-on-match", "two-prefix-list-matches", "unknown-clause"])
def test_running_config_raises(running):
    with pytest.raises(FrrTranslationError):
        _tr(running)


def test_empty_peer_groups_falls_back_to_defaults():
    out = _tr(pg_json={})
    assert "default|PEER_V4" in out["BGP_PEER_GROUP"]
    assert "default|PEER_V6" in out["BGP_PEER_GROUP"]
    assert out["BGP_NEIGHBOR"]["default|10.0.0.1"]["peer_group_name"] == "PEER_V4"


def test_on_match_next_translated():
    out = _tr(["route-map FROM_BGP_PEER_V6 permit 1", " on-match next", " set ipv6 next-hop prefer-global",
               "route-map FROM_BGP_PEER_V6 permit 10", " call ALLOW_LIST_DEPLOYMENT_ID_0_V6", " on-match next",
               "route-map FROM_BGP_PEER_V6 permit 100",
               "route-map RM_X permit 10", " match community CL1", " on-match next"])
    rm1 = out["ROUTE_MAP"]["FROM_BGP_PEER_V6|1"]
    assert rm1["set_ipv6_next_hop_prefer_global"] == "true"
    assert rm1["set_on_match_action"] == "ON_MATCH_NEXT"
    rm10 = out["ROUTE_MAP"]["FROM_BGP_PEER_V6|10"]
    assert rm10["call_route_map"] == "ALLOW_LIST_DEPLOYMENT_ID_0_V6"
    assert rm10["set_on_match_action"] == "ON_MATCH_NEXT"
    assert out["ROUTE_MAP"]["RM_X|10"]["set_on_match_action"] == "ON_MATCH_NEXT"


def test_on_match_goto_translated():
    rm = _tr(["route-map RM_X permit 10", " call SOMETHING", " on-match goto 30"])["ROUTE_MAP"]["RM_X|10"]
    assert rm["set_on_match_action"] == "ON_MATCH_GOTO"
    assert rm["set_on_match_goto"] == "30"


def test_set_src_and_protocol_route_map_translated():
    out = _tr(["route-map RM_SET_SRC permit 10", " set src 10.1.0.32",
               "route-map RM_SET_SRC6 permit 10", " set src fc00:1::32",
               "ip protocol bgp route-map RM_SET_SRC", "ipv6 protocol bgp route-map RM_SET_SRC6"])
    assert out["ROUTE_MAP"]["RM_SET_SRC|10"]["set_src"] == "10.1.0.32"
    assert out["ROUTE_MAP"]["RM_SET_SRC6|10"]["set_src"] == "fc00:1::32"
    assert out["PROTOCOL_ROUTE_MAP"]["default|IPv4|bgp"]["route_map"] == "RM_SET_SRC"
    assert out["PROTOCOL_ROUTE_MAP"]["default|IPv6|bgp"]["route_map"] == "RM_SET_SRC6"


# Listen-range peer-groups: attributes come only from the running config, ranges from BGP_PEER_RANGE.
_T0_LISTEN_RANGE_RUNNING = [
    "router bgp 65100",
    " neighbor BGPSLBPassive peer-group",
    " neighbor BGPSLBPassive remote-as 65432",
    " neighbor BGPSLBPassive passive",
    " neighbor BGPSLBPassive ebgp-multihop",
    " neighbor BGPSLBPassive update-source 10.1.0.32",
    " neighbor BGPSLBPassive description BGPSLBPassive",
    " bgp listen range 10.255.0.0/25 peer-group BGPSLBPassive",
    " address-family ipv4 unicast",
    "  neighbor BGPSLBPassive activate",
    "  neighbor BGPSLBPassive route-map FROM_BGP_SPEAKER in",
    "  neighbor BGPSLBPassive route-map TO_BGP_SPEAKER out",
    "  neighbor BGPSLBPassive soft-reconfiguration inbound",
    " exit-address-family",
]


def _config_db_with_peer_range(**tables):
    return _cfg(BGP_PEER_RANGE={"BGPSLBPassive": {
        "ip_range": ["10.255.0.0/25"], "name": "BGPSLBPassive", "src_address": "10.1.0.32"}}, **tables)


def test_listen_range_peer_group_translated():
    out = _tr(_T0_LISTEN_RANGE_RUNNING, _config_db_with_peer_range())
    pg = out["BGP_PEER_GROUP"]["default|BGPSLBPassive"]
    assert pg["asn"] == "65432"
    assert pg["local_addr"] == "10.1.0.32"
    assert pg["passive_mode"] == "true"
    assert pg["ebgp_multihop"] == "true"
    assert "ebgp_multihop_ttl" not in pg
    assert pg["peer_group_name"] == "BGPSLBPassive" and pg["vrf_name"] == "default"
    af = out["BGP_PEER_GROUP_AF"]["default|BGPSLBPassive|ipv4_unicast"]
    assert af["route_map_in"] == ["FROM_BGP_SPEAKER"]
    assert af["route_map_out"] == ["TO_BGP_SPEAKER"]
    assert af["soft_reconfiguration_in"] == "true"
    assert af["admin_status"] == "up"   # 'activate' must activate the pg; it has no neighbor rows
    assert "default|BGPSLBPassive|ipv6_unicast" not in out["BGP_PEER_GROUP_AF"]
    assert out["BGP_GLOBALS_LISTEN_PREFIX"]["default|10.255.0.0/25"] == {
        "vrf_name": "default", "ip_prefix": "10.255.0.0/25", "peer_group": "BGPSLBPassive"}
    assert "BGP_PEER_RANGE" not in out


def test_bbr_does_not_leak_onto_listen_range_peer_group():
    out = _tr(_T0_LISTEN_RANGE_RUNNING, _config_db_with_peer_range(BGP_BBR={"all": {"status": "enabled"}}))
    assert out["BGP_PEER_GROUP_AF"]["default|PEER_V4|ipv4_unicast"]["allow_as_in"] == "true"
    slb_af = out["BGP_PEER_GROUP_AF"]["default|BGPSLBPassive|ipv4_unicast"]
    assert "allow_as_in" not in slb_af and "allow_as_count" not in slb_af


def test_no_peer_range_leaves_no_listen_prefix_table():
    assert "BGP_GLOBALS_LISTEN_PREFIX" not in _tr()


def test_default_scoped_peer_range_key_is_accepted():
    out = _tr(cfg=_cfg(BGP_PEER_RANGE={"default|BGPVac": {"ip_range": ["10.255.0.0/25"], "name": "BGPVac"}}))
    assert out["BGP_GLOBALS_LISTEN_PREFIX"]["default|10.255.0.0/25"]["peer_group"] == "BGPVac"


def test_route_map_stanza_does_not_leak_into_the_next_block():
    out = _tr(["route-map RM_A permit 10", " match community CL1", "!",
               "route-map RM_B permit 20", " match community CL2"])
    assert out["ROUTE_MAP"]["RM_A|10"]["match_community"] == "CL1"
    assert out["ROUTE_MAP"]["RM_B|20"]["match_community"] == "CL2"


def test_clause_after_route_map_exit_is_not_attributed_to_it():
    out = _tr(["route-map RM_A permit 10", " match community CL1", "exit",
               "router bgp 65100", " bgp router-id 10.1.0.32"])
    assert out["ROUTE_MAP"]["RM_A|10"] == {
        "name": "RM_A", "route_operation": "permit", "stmt_name": "10", "match_community": "CL1"}


def test_extra_peer_groups_ignore_a_non_default_vrf_bgp_instance():
    out = _tr(["router bgp 65100", " neighbor BGPSLBPassive peer-group",
               " neighbor BGPSLBPassive remote-as 65432", "exit",
               "router bgp 65100 vrf Vrf1", " neighbor VRF_ONLY_PG peer-group",
               " neighbor VRF_ONLY_PG remote-as 65999", "exit"])
    assert out["BGP_PEER_GROUP"]["default|BGPSLBPassive"]["asn"] == "65432"
    assert "default|VRF_ONLY_PG" not in out["BGP_PEER_GROUP"]


def test_match_prefix_list_uses_the_single_match_prefix_set_leaf():
    out = _tr(["route-map RM_V4 permit 10", " match ip address prefix-list PL_V4",
               "route-map RM_V6 permit 10", " match ipv6 address prefix-list PL_V6"])
    assert out["ROUTE_MAP"]["RM_V4|10"]["match_prefix_set"] == "PL_V4"
    assert out["ROUTE_MAP"]["RM_V6|10"]["match_prefix_set"] == "PL_V6"
    assert not any(k.startswith("match_prefix_set|") for k in out["ROUTE_MAP"]["RM_V4|10"])


def test_match_tag_is_a_leaf_list():
    assert _tr(["route-map RM_X permit 10", " match tag 1001"])["ROUTE_MAP"]["RM_X|10"]["match_tag"] == ["1001"]


def test_azng_style_clauses_translated():
    rm = _tr(["route-map V4_SPINE_AH permit 10", " match as-path AS_PATH_SET_1", " set local-preference 80",
              " set as-path prepend 65100 65100", " set metric 42", " set origin igp"])["ROUTE_MAP"]["V4_SPINE_AH|10"]
    assert rm["match_as_path"] == "AS_PATH_SET_1"
    assert rm["set_local_pref"] == "80"
    assert rm["set_asn_list"] == "65100,65100"
    assert rm["set_med"] == "42"
    assert rm["set_origin"] == "igp"


def test_known_frrcfgd_gap_clause_is_kept_non_fatal():
    rm = _tr(["route-map RM_X permit 10", " set comm-list DEVICE_INTERNAL_COMMUNITY delete",
              " set tag 101", " set originator-id 10.10.10.10"])["ROUTE_MAP"]["RM_X|10"]
    assert rm == {"name": "RM_X", "route_operation": "permit", "stmt_name": "10"}


def test_wcmp_clause_in_running_config_is_not_emitted_either():
    out = _tr(["route-map TO_BGP_PEER_V4 permit 100", " set extcommunity bandwidth num-multipaths"])
    assert "set_extcommunity_bandwidth_type" not in json.dumps(out)
    assert out["ROUTE_MAP_SET"]["TO_BGP_PEER_V4"] == {"name": "TO_BGP_PEER_V4"}


# expected: BGP_GLOBALS|default field -> value, None meaning the field must be absent.
@pytest.mark.parametrize("running,expected", [
    ([], {"ebgp_requires_policy": None, "graceful_restart_enable": None}),
    (["router bgp 65100", " no bgp ebgp-requires-policy"], {"ebgp_requires_policy": "false"}),
    (["router bgp 65100", " bgp log-neighbor-changes"], {"log_nbr_state_changes": "true"}),
    (["router bgp 65100", " no bgp log-neighbor-changes"], {"log_nbr_state_changes": "false"}),
    (["router bgp 65100", " bgp graceful-restart", " bgp graceful-restart restart-time 240",
      " bgp graceful-restart preserve-fw-state", " bgp graceful-restart stalepath-time 300"],
     {"graceful_restart_enable": "true", "gr_restart_time": "240", "gr_preserve_fw_state": "true",
      "gr_stale_routes_time": "300"}),
    # 'graceful-restart-disable' must not prefix-match as an enable.
    (["router bgp 65100", " bgp graceful-restart-disable", " bgp long-lived-graceful-restart stale-time 864000"],
     {"graceful_restart_enable": None}),
    (["router bgp 65100", " bgp graceful-restart", " bgp graceful-restart select-defer-time 45"],
     {"graceful_restart_enable": "true"}),
    (["router bgp 64589", " bgp confederation identifier 64582", " bgp confederation peers 64588"],
     {"confed_id": "64582", "confed_peers": ["64588"]}),
    (["router bgp 64589", " bgp confederation peers 64588 64590", " bgp confederation peers 64591"],
     {"confed_peers": ["64588", "64590", "64591"]}),
], ids=["absent", "ebgp-requires-policy", "log-nbr", "no-log-nbr", "graceful-restart", "gr-disable",
        "select-defer-time-gap", "confed", "confed-peers-accumulate"])
def test_bgp_globals_from_running_config(running, expected):
    g = _tr(running)["BGP_GLOBALS"]["default"]
    assert {k: g.get(k) for k in expected} == expected


def test_maximum_paths_carried_into_global_af():
    out = _tr(["router bgp 65100", " address-family ipv4 unicast", "  maximum-paths 64", " exit-address-family",
               " address-family ipv6 unicast", "  maximum-paths 64", "  maximum-paths ibgp 8",
               " exit-address-family"])
    assert out["BGP_GLOBALS_AF"]["default|ipv4_unicast"]["max_ebgp_paths"] == "64"
    assert out["BGP_GLOBALS_AF"]["default|ipv6_unicast"]["max_ebgp_paths"] == "64"


def test_neighbor_keeps_its_own_peer_group():
    cfg = _base_config_db()
    cfg["BGP_NEIGHBOR"]["10.0.0.2"] = {
        "admin_status": "up", "asn": "65201", "local_addr": "10.0.0.3", "name": "ARISTA03T2"}
    cfg["BGP_NEIGHBOR"]["10.0.0.9"] = {"admin_status": "up", "asn": "65299"}
    pg_json = dict(_peer_group_json(),
                   ANOTHER_V4={"members": {"10.0.0.2": {}}, "addressFamilyInfo": "IPv4 Unicast"})
    out = _tr(cfg=cfg, pg_json=pg_json)
    assert out["BGP_NEIGHBOR"]["default|10.0.0.1"]["peer_group_name"] == "PEER_V4"
    assert out["BGP_NEIGHBOR"]["default|10.0.0.2"]["peer_group_name"] == "ANOTHER_V4"
    assert out["BGP_NEIGHBOR"]["default|10.0.0.9"]["peer_group_name"] == "PEER_V4"   # unreported -> family default


_CONFED_EXTERNAL_RUNNING = [
    "router bgp 65100",
    " neighbor PEER_EXTERNAL_V4 peer-group",
    " neighbor PEER_V4 peer-group",
    " address-family ipv4 unicast",
    "  neighbor PEER_EXTERNAL_V4 route-map FROM_BGP_PEER_V4 in",
    "  neighbor PEER_EXTERNAL_V4 route-map TO_BGP_PEER_V4 out",
    "  neighbor PEER_V4 route-map FROM_BGP_PEER_V4 in",
    "  neighbor PEER_V4 route-map TO_BGP_PEER_V4 out",
    " exit-address-family",
]


def test_confed_external_group_is_not_primary_and_uses_its_real_route_maps():
    cfg = _cfg(BGP_BBR={"all": {"status": "enabled"}})
    cfg["BGP_NEIGHBOR"]["10.0.0.9"] = {"admin_status": "up", "asn": "65300"}
    pg_json = {"PEER_EXTERNAL_V4": {"members": {"10.0.0.9": {}}, "addressFamilyInfo": "IPv4 Unicast"},
               **_peer_group_json()}
    out = _tr(_CONFED_EXTERNAL_RUNNING, cfg, pg_json)
    ext = out["BGP_PEER_GROUP_AF"]["default|PEER_EXTERNAL_V4|ipv4_unicast"]
    assert ext["route_map_in"] == ["FROM_BGP_PEER_V4"]
    assert "allow_as_in" not in ext
    assert out["BGP_PEER_GROUP_AF"]["default|PEER_V4|ipv4_unicast"]["allow_as_in"] == "true"
    assert out["BGP_NEIGHBOR_AF"]["default|10.0.0.9|ipv4_unicast"]["route_map_in"] == ["FROM_BGP_PEER_V4"]
    assert out["BGP_NEIGHBOR"]["default|10.0.0.9"]["peer_group_name"] == "PEER_EXTERNAL_V4"


_UNNUMBERED_RUNNING = [
    "router bgp 65100",
    " neighbor PEER_UNNUMBERED peer-group",
    " neighbor PEER_UNNUMBERED capability extended-nexthop",
    " neighbor Ethernet0 interface peer-group PEER_UNNUMBERED",
    " address-family ipv4 unicast",
    "  neighbor PEER_UNNUMBERED allowas-in 1",
    "  neighbor PEER_UNNUMBERED route-map FROM_BGP_PEER_UNNUMBERED_V4 in",
    "  neighbor PEER_UNNUMBERED route-map TO_BGP_PEER_UNNUMBERED_V4 out",
    "  neighbor Ethernet0 activate",
    " exit-address-family",
    " address-family ipv6 unicast",
    "  neighbor PEER_UNNUMBERED route-map FROM_BGP_PEER_UNNUMBERED_V6 in",
    "  neighbor PEER_UNNUMBERED route-map TO_BGP_PEER_UNNUMBERED_V6 out",
    "  neighbor Ethernet0 activate",
    " exit-address-family",
]


def test_unnumbered_neighbor_translated_to_interface_neighbor():
    cfg = _base_config_db()
    cfg["BGP_NEIGHBOR"]["Ethernet0"] = {"admin_status": "up", "asn": "65300", "name": "T0-1"}
    pg_json = {"PEER_UNNUMBERED": {"members": {"Ethernet0": {}},
                                   "addressFamilyInfo": "IPv4 Unicast, IPv6 Unicast"},
               **_peer_group_json()}
    out = _tr(_UNNUMBERED_RUNNING, cfg, pg_json)
    assert out["BGP_NEIGHBOR"]["default|Ethernet0"]["peer_group_name"] == "PEER_UNNUMBERED"
    assert out["BGP_NEIGHBOR_AF"]["default|Ethernet0|ipv4_unicast"]["route_map_in"] == [
        "FROM_BGP_PEER_UNNUMBERED_V4"]
    assert out["BGP_NEIGHBOR_AF"]["default|Ethernet0|ipv6_unicast"]["route_map_out"] == [
        "TO_BGP_PEER_UNNUMBERED_V6"]
    assert out["BGP_PEER_GROUP"]["default|PEER_UNNUMBERED"]["capability_ext_nexthop"] == "true"
    v4 = out["BGP_PEER_GROUP_AF"]["default|PEER_UNNUMBERED|ipv4_unicast"]
    assert (v4["allow_as_in"], v4["allow_as_count"]) == ("true", "1")
    assert "default|Ethernet0" not in out["BGP_PEER_GROUP"]
    assert out["BGP_NEIGHBOR"]["default|10.0.0.1"]["peer_group_name"] == "PEER_V4"


def test_unnumbered_neighbor_address_family_limits_its_afs():
    cfg = _base_config_db()
    cfg["BGP_NEIGHBOR"]["Ethernet4"] = {"admin_status": "up", "asn": "65300", "address_family": "v6"}
    out = _tr(cfg=cfg)
    assert "default|Ethernet4|ipv4_unicast" not in out["BGP_NEIGHBOR_AF"]
    assert "default|Ethernet4|ipv6_unicast" in out["BGP_NEIGHBOR_AF"]
    assert "address_family" not in out["BGP_NEIGHBOR"]["default|Ethernet4"]


# expected: DEVICE_METADATA|localhost field -> value, None meaning the field must be absent.
@pytest.mark.parametrize("running,expected", [
    ([], {"nexthop_group_keep_time": None, "zebra_nexthop": None, "suppress-fib-pending": "disabled"}),
    (["router bgp 65100", " bgp suppress-fib-pending"], {"suppress-fib-pending": "enabled"}),
    (["zebra nexthop-group keep 1", "zebra nexthop kernel enable", "router bgp 65100", " bgp suppress-fib-pending"],
     {"nexthop_group_keep_time": "1", "zebra_nexthop": "enabled", "suppress-fib-pending": "enabled"}),
], ids=["absent", "suppress-fib-pending", "zebra-knobs"])
def test_device_knobs_carried_into_device_metadata(running, expected):
    meta = _tr(running)["DEVICE_METADATA"]["localhost"]
    assert {k: meta.get(k) for k in expected} == expected


def test_prefix_list_rows_are_a_gap():
    cfg = _base_config_db()
    cfg["PREFIX_LIST"] = {"ANCHOR_PREFIX|fc00:1::/48": {}}
    with pytest.raises(FrrTranslationGap, match="PrefixListMgr"):
        translate_config_db(cfg, "", _peer_group_json())


def test_tor_unconditional_allowas_in_carried_without_bbr():
    out = _tr(["router bgp 65100", " address-family ipv4 unicast", "  neighbor PEER_V4 allowas-in 1",
               " exit-address-family", " address-family ipv6 unicast", "  neighbor PEER_V6 allowas-in 1",
               " exit-address-family"])
    for key in ("default|PEER_V4|ipv4_unicast", "default|PEER_V6|ipv6_unicast"):
        row = out["BGP_PEER_GROUP_AF"][key]
        assert (row["allow_as_in"], row["allow_as_count"]) == ("true", "1")
        assert row["route_map_in"]

"""Offline unit tests for the bgpcfgd -> frr_mgmt_framework BGP config translation.

These run without a DUT. The expected frrcfgd output is anchored to real output
captured from a t1 DUT (e.g. the ARISTA02T2 fc00::6 neighbor and the PEER_V4 /
PEER_V6 peer groups the topology ships with).
"""
import pytest

from tests.common.helpers.frr.bgp_config_translation import (
    translate_config_db,
    FrrTranslationError,
)

# Pure offline unit tests (no DUT). The topology marker is required by the CI
# markers check; 'any' lets them run in any collection without a testbed.
pytestmark = [
    pytest.mark.topology('any')
]


def _base_config_db():
    """A minimal traditional-mode config_db with one v4 and one v6 eBGP neighbor,
    modeled on a t1 testbed."""
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


def test_neighbor_v6_matches_captured_ground_truth():
    out = translate_config_db(_base_config_db(), "", _peer_group_json())
    # Anchored to real frrcfgd output captured from the DUT for ARISTA02T2.
    assert out["BGP_NEIGHBOR"]["default|fc00::6"] == {
        "asn": "65200", "holdtime": "10", "keepalive": "3", "local_addr": "fc00::5",
        "name": "ARISTA02T2", "admin_status": "up", "neighbor": "fc00::6",
        "peer_group_name": "PEER_V6", "vrf_name": "default",
    }
    assert out["BGP_NEIGHBOR_AF"]["default|fc00::6|ipv6_unicast"]["afi_safi"] == "ipv6_unicast"
    assert out["BGP_NEIGHBOR_AF"]["default|fc00::6|ipv6_unicast"]["admin_status"] == "up"


def test_neighbor_v4_gets_v4_peer_group_and_af():
    out = translate_config_db(_base_config_db(), "", _peer_group_json())
    nbr = out["BGP_NEIGHBOR"]["default|10.0.0.1"]
    assert nbr["peer_group_name"] == "PEER_V4"
    assert nbr["asn"] == "65200" and nbr["local_addr"] == "10.0.0.0"
    # Excluded traditional-only keys must be dropped.
    assert "nhopself" not in nbr and "rrclient" not in nbr
    assert "default|10.0.0.1|ipv4_unicast" in out["BGP_NEIGHBOR_AF"]


def test_flat_neighbor_key_is_vrf_prefixed():
    out = translate_config_db(_base_config_db(), "", _peer_group_json())
    assert "10.0.0.1" not in out["BGP_NEIGHBOR"]        # old flat key gone
    assert "default|10.0.0.1" in out["BGP_NEIGHBOR"]     # new vrf-keyed


def test_globals_and_router_id():
    out = translate_config_db(_base_config_db(), "", _peer_group_json())
    assert out["BGP_GLOBALS"]["default"]["local_asn"] == "65100"
    assert out["BGP_GLOBALS"]["default"]["router_id"] == "10.1.0.32"   # IPv4 Loopback0
    # Loopback0 addresses are advertised.
    assert "default|ipv4_unicast|10.1.0.32/32" in out["BGP_GLOBALS_AF_NETWORK"]
    assert "default|ipv6_unicast|fc00:1::32/128" in out["BGP_GLOBALS_AF_NETWORK"]


def test_ebgp_requires_policy_translated_from_running_config():
    # 'no bgp ebgp-requires-policy' in the running config -> BGP_GLOBALS ebgp_requires_policy=false
    running = "\n".join([
        "router bgp 65100",
        " no bgp ebgp-requires-policy",
    ])
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    assert out["BGP_GLOBALS"]["default"]["ebgp_requires_policy"] == "false"


def test_ebgp_requires_policy_absent_when_not_in_running_config():
    # Not present in running config -> field is not set (frrcfgd leaves FRR's default).
    out = translate_config_db(_base_config_db(), "", _peer_group_json())
    assert "ebgp_requires_policy" not in out["BGP_GLOBALS"]["default"]


def test_peer_groups_built():
    out = translate_config_db(_base_config_db(), "", _peer_group_json())
    assert out["BGP_PEER_GROUP"]["default|PEER_V4"]["local_asn"] == "65100"
    assert out["BGP_PEER_GROUP"]["default|PEER_V6"]["peer_group_name"] == "PEER_V6"
    assert out["BGP_PEER_GROUP_AF"]["default|PEER_V4|ipv4_unicast"]["soft_reconfiguration_in"] == "true"


def test_prefix_list_parsing():
    running = "\n".join([
        "ip prefix-list PL_V4 seq 10 permit 10.0.0.0/8 le 32",
        "ipv6 prefix-list PL_V6 seq 5 permit 2001:db8::/32",
    ])
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    assert out["PREFIX_SET"]["PL_V4"] == {"name": "PL_V4", "mode": "IPv4"}
    assert out["PREFIX_SET"]["PL_V6"] == {"name": "PL_V6", "mode": "IPv6"}
    v4_key = "PL_V4|10|10.0.0.0/8|8..32"
    assert out["PREFIX"][v4_key]["action"] == "permit"
    v6_key = "PL_V6|5|2001:db8::/32|exact"
    assert out["PREFIX"][v6_key]["sequence_number"] == 5


def test_community_list_parsing():
    running = 'bgp community-list standard CL1 permit 65100:100'
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    assert out["COMMUNITY_SET"]["CL1"]["community_member"] == ["65100:100"]
    assert out["COMMUNITY_SET"]["CL1"]["action"] == "permit"
    assert out["COMMUNITY_SET"]["CL1"]["set_type"] == "STANDARD"


def test_route_map_name_preserved():
    running = "\n".join([
        "route-map FROM_BGP_PEER_V4 permit 10",
        " match community CL1",
        "route-map TO_BGP_PEER_V4 permit 10",
    ])
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    assert out["ROUTE_MAP_SET"]["FROM_BGP_PEER_V4"] == {"name": "FROM_BGP_PEER_V4"}
    assert out["ROUTE_MAP"]["FROM_BGP_PEER_V4|10"]["match_community"] == "CL1"
    assert out["ROUTE_MAP"]["FROM_BGP_PEER_V4|10"]["route_operation"] == "permit"
    # Named route-maps feed the neighbor/peer-group route_map_in/out lists.
    assert out["BGP_NEIGHBOR_AF"]["default|10.0.0.1|ipv4_unicast"]["route_map_in"] == ["FROM_BGP_PEER_V4"]


def test_set_community_additive_kept_in_inline_list():
    running = "\n".join([
        "route-map SET_COMM permit 10",
        " set community 65100:100 65100:200 additive",
    ])
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    rm = out["ROUTE_MAP"]["SET_COMM|10"]
    # Community frrcfgd has no set_community_additive companion field; it space-joins the
    # inline list, so every community plus the trailing 'additive' token must stay in the
    # list (and all communities are kept, not just the first).
    assert rm["set_community_inline"] == ["65100:100", "65100:200", "additive"]
    assert "set_community_additive" not in rm


def test_neighbor_admin_status_down_is_preserved():
    cfg = _base_config_db()
    cfg["BGP_NEIGHBOR"]["10.0.0.1"]["admin_status"] = "down"
    out = translate_config_db(cfg, "", _peer_group_json())
    # admin_status must be carried through, not forced up -- else a shut neighbor comes up.
    assert out["BGP_NEIGHBOR"]["default|10.0.0.1"]["admin_status"] == "down"
    assert out["BGP_NEIGHBOR_AF"]["default|10.0.0.1|ipv4_unicast"]["admin_status"] == "down"


def test_neighbor_rrclient_nhself_emitted_on_af_when_enabled():
    cfg = _base_config_db()
    cfg["BGP_NEIGHBOR"]["10.0.0.1"].update({"rrclient": "1", "nhopself": "1"})
    out = translate_config_db(cfg, "", _peer_group_json())
    af = out["BGP_NEIGHBOR_AF"]["default|10.0.0.1|ipv4_unicast"]
    # route-reflector-client / next-hop-self are AF-level in frrcfgd; re-emit, don't drop.
    assert af["rrclient"] == "true"
    assert af["nhself"] == "true"


def test_neighbor_rrclient_nhself_noop_not_emitted():
    # Base config has rrclient="0"/nhopself="0" -> no line needed on the AF row.
    out = translate_config_db(_base_config_db(), "", _peer_group_json())
    af = out["BGP_NEIGHBOR_AF"]["default|10.0.0.1|ipv4_unicast"]
    assert "rrclient" not in af and "nhself" not in af


# --------------------------------------------------------------------------- #
# Baseline feature tables: BBR / W-ECMP / aggregate-address
# --------------------------------------------------------------------------- #

def test_bbr_enabled_sets_allow_as_in_on_peer_group_afs():
    cfg = _base_config_db()
    cfg["BGP_BBR"] = {"all": {"status": "enabled"}}
    out = translate_config_db(cfg, "", _peer_group_json())
    for af_key in ("default|PEER_V4|ipv4_unicast", "default|PEER_V6|ipv6_unicast"):
        assert out["BGP_PEER_GROUP_AF"][af_key]["allow_as_in"] == "true"
        assert out["BGP_PEER_GROUP_AF"][af_key]["allow_as_count"] == "1"
    # The traditional BGP_BBR table is consumed, not carried into frr config.
    assert "BGP_BBR" not in out


def test_bbr_disabled_leaves_allow_as_in_unset():
    cfg = _base_config_db()
    cfg["BGP_BBR"] = {"all": {"status": "disabled"}}
    out = translate_config_db(cfg, "", _peer_group_json())
    pg_af = out["BGP_PEER_GROUP_AF"]["default|PEER_V4|ipv4_unicast"]
    assert "allow_as_in" not in pg_af and "allow_as_count" not in pg_af


def test_wcmp_enabled_sets_extcommunity_bandwidth_route_map():
    cfg = _base_config_db()
    cfg["BGP_DEVICE_GLOBAL"] = {"STATE": {"wcmp_enabled": "true", "tsa_enabled": "false"}}
    out = translate_config_db(cfg, "", _peer_group_json())
    for name in ("TO_BGP_PEER_V4", "TO_BGP_PEER_V6"):
        assert out["ROUTE_MAP_SET"][name] == {"name": name}
        rm = out["ROUTE_MAP"]["{}|100".format(name)]
        assert rm["set_extcommunity_bandwidth_type"] == "NUM_MULTIPATHS"
        assert rm["route_operation"] == "permit" and rm["stmt_name"] == "100"


def test_wcmp_disabled_adds_no_route_map():
    cfg = _base_config_db()
    cfg["BGP_DEVICE_GLOBAL"] = {"STATE": {"wcmp_enabled": "false"}}
    out = translate_config_db(cfg, "", _peer_group_json())
    assert "TO_BGP_PEER_V4|100" not in out.get("ROUTE_MAP", {})


def test_aggregate_address_maps_to_globals_af_aggregate_addr():
    cfg = _base_config_db()
    cfg["BGP_AGGREGATE_ADDRESS"] = {
        "192.168.0.0/16": {"as-set": "true", "summary-only": "true", "origin": "igp"},
        "fc00:100::/48": {"as-set": "false", "summary-only": "false"},
    }
    out = translate_config_db(cfg, "", _peer_group_json())
    v4 = out["BGP_GLOBALS_AF_AGGREGATE_ADDR"]["default|ipv4_unicast|192.168.0.0/16"]
    assert v4 == {"as_set": "true", "summary_only": "true", "origin": "igp"}
    v6 = out["BGP_GLOBALS_AF_AGGREGATE_ADDR"]["default|ipv6_unicast|fc00:100::/48"]
    assert v6 == {"as_set": "false", "summary_only": "false"}
    # Traditional table consumed; unspecified/absent origin is not emitted.
    assert "BGP_AGGREGATE_ADDRESS" not in out
    assert "origin" not in v6


def test_aggregate_address_unspecified_origin_dropped():
    cfg = _base_config_db()
    cfg["BGP_AGGREGATE_ADDRESS"] = {"10.9.0.0/16": {"origin": "unspecified"}}
    out = translate_config_db(cfg, "", _peer_group_json())
    assert out["BGP_GLOBALS_AF_AGGREGATE_ADDR"]["default|ipv4_unicast|10.9.0.0/16"] == {}


# --------------------------------------------------------------------------- #
# Strictness / fail-loud
# --------------------------------------------------------------------------- #

def test_raises_on_missing_bgp_neighbor():
    cfg = _base_config_db()
    del cfg["BGP_NEIGHBOR"]
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


def test_raises_on_missing_bgp_asn():
    cfg = _base_config_db()
    cfg["DEVICE_METADATA"]["localhost"] = {}
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


def test_raises_on_missing_loopback():
    cfg = _base_config_db()
    del cfg["LOOPBACK_INTERFACE"]
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


def test_empty_peer_groups_falls_back_to_defaults():
    # A config with no peer-groups (a test may have torn them down before the switch)
    # must not abort the translation; fall back to the conventional PEER_V4/PEER_V6.
    out = translate_config_db(_base_config_db(), "", {})
    assert "default|PEER_V4" in out["BGP_PEER_GROUP"]
    assert "default|PEER_V6" in out["BGP_PEER_GROUP"]
    # Neighbors still translate and join those peer-groups.
    assert out["BGP_NEIGHBOR"]["default|10.0.0.1"]["peer_group_name"] == "PEER_V4"


def test_raises_on_invalid_neighbor_address():
    cfg = _base_config_db()
    cfg["BGP_NEIGHBOR"]["not-an-ip"] = {"asn": "65200"}
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


def test_raises_on_malformed_prefix_list():
    # Recognized as a prefix-list line but missing the 'seq N action prefix' tail.
    running = "ip prefix-list BROKEN permit 10.0.0.0/8"
    with pytest.raises(FrrTranslationError):
        translate_config_db(_base_config_db(), running, _peer_group_json())


def test_raises_on_aggregate_bbr_required():
    cfg = _base_config_db()
    cfg["BGP_AGGREGATE_ADDRESS"] = {"10.0.0.0/16": {"bbr-required": "true"}}
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


def test_raises_on_aggregate_prefix_list_linkage():
    cfg = _base_config_db()
    cfg["BGP_AGGREGATE_ADDRESS"] = {
        "10.0.0.0/16": {"aggregate-address-prefix-list": "PL_AGG"},
    }
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


def test_raises_on_unknown_aggregate_field():
    cfg = _base_config_db()
    cfg["BGP_AGGREGATE_ADDRESS"] = {"10.0.0.0/16": {"bogus-field": "x"}}
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


def test_raises_on_unexpected_bbr_status():
    cfg = _base_config_db()
    cfg["BGP_BBR"] = {"all": {"status": "maybe"}}
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


def test_raises_on_unexpected_wcmp_value():
    cfg = _base_config_db()
    cfg["BGP_DEVICE_GLOBAL"] = {"STATE": {"wcmp_enabled": "yes"}}
    with pytest.raises(FrrTranslationError):
        translate_config_db(cfg, "", _peer_group_json())


# --------------------------------------------------------------------------- #
# route-map 'on-match next' / 'on-match goto <seq>' (continue-flow) — translated to
# frrcfgd's set_on_match_action enum (+ set_on_match_goto). See sonic-buildimage#28482.
# --------------------------------------------------------------------------- #

def test_on_match_next_translated():
    # bgpcfgd FROM_BGP_* inbound maps use 'on-match next' both with a 'call' (allow-list
    # framework) and standalone (set ipv6 next-hop prefer-global). Both translate to
    # set_on_match_action ON_MATCH_NEXT.
    running = "\n".join([
        "route-map FROM_BGP_PEER_V6 permit 1",
        " on-match next",
        " set ipv6 next-hop prefer-global",
        "route-map FROM_BGP_PEER_V6 permit 10",
        " call ALLOW_LIST_DEPLOYMENT_ID_0_V6",
        " on-match next",
        "route-map FROM_BGP_PEER_V6 permit 100",
    ])
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    rm1 = out["ROUTE_MAP"]["FROM_BGP_PEER_V6|1"]
    assert rm1["set_ipv6_next_hop_prefer_global"] == "true"
    assert rm1["set_on_match_action"] == "ON_MATCH_NEXT"
    rm10 = out["ROUTE_MAP"]["FROM_BGP_PEER_V6|10"]
    assert rm10["call_route_map"] == "ALLOW_LIST_DEPLOYMENT_ID_0_V6"
    assert rm10["set_on_match_action"] == "ON_MATCH_NEXT"


def test_on_match_next_translated_outside_framework():
    # 'on-match next' anywhere (not just FROM_BGP_* maps) is now faithfully translated.
    running = "\n".join([
        "route-map RM_X permit 10",
        " match community CL1",
        " on-match next",
    ])
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    assert out["ROUTE_MAP"]["RM_X|10"]["set_on_match_action"] == "ON_MATCH_NEXT"


def test_on_match_goto_translated():
    running = "\n".join([
        "route-map RM_X permit 10",
        " call SOMETHING",
        " on-match goto 30",
    ])
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    rm = out["ROUTE_MAP"]["RM_X|10"]
    assert rm["set_on_match_action"] == "ON_MATCH_GOTO"
    assert rm["set_on_match_goto"] == "30"


def test_on_match_unrecognized_raises():
    running = "\n".join([
        "route-map RM_X permit 10",
        " on-match bogus",
    ])
    with pytest.raises(FrrTranslationError):
        translate_config_db(_base_config_db(), running, _peer_group_json())


def test_set_src_and_protocol_route_map_translated():
    # The RM_SET_SRC loopback-source setup: route-maps with 'set src' + zebra
    # 'ip[v6] protocol bgp route-map' binds -> ROUTE_MAP set_src + PROTOCOL_ROUTE_MAP.
    running = "\n".join([
        "route-map RM_SET_SRC permit 10",
        " set src 10.1.0.32",
        "route-map RM_SET_SRC6 permit 10",
        " set src fc00:1::32",
        "ip protocol bgp route-map RM_SET_SRC",
        "ipv6 protocol bgp route-map RM_SET_SRC6",
    ])
    out = translate_config_db(_base_config_db(), running, _peer_group_json())
    assert out["ROUTE_MAP"]["RM_SET_SRC|10"]["set_src"] == "10.1.0.32"
    assert out["ROUTE_MAP"]["RM_SET_SRC6|10"]["set_src"] == "fc00:1::32"
    assert out["PROTOCOL_ROUTE_MAP"]["ipv4|bgp"]["route_map"] == "RM_SET_SRC"
    assert out["PROTOCOL_ROUTE_MAP"]["ipv6|bgp"]["route_map"] == "RM_SET_SRC6"


# --------------------------------------------------------------------------- #
# Listen-range / non-standard peer-groups (BGPSLBPassive / BGPVac). These ship in
# the t0 baseline: bgpcfgd renders them from templates so their attributes live only
# in the running-config, and their ranges come from the BGP_PEER_RANGE CONFIG_DB table.
# Anchored to config captured from a t0 DUT (vlab-01).
# --------------------------------------------------------------------------- #

_T0_LISTEN_RANGE_RUNNING = "\n".join([
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
])


def _config_db_with_peer_range():
    cfg = _base_config_db()
    cfg["BGP_PEER_RANGE"] = {
        "BGPSLBPassive": {
            "ip_range": ["10.255.0.0/25"], "name": "BGPSLBPassive",
            "src_address": "10.1.0.32",
        },
    }
    return cfg


def test_listen_range_peer_group_attributes_translated():
    out = translate_config_db(
        _config_db_with_peer_range(), _T0_LISTEN_RANGE_RUNNING, _peer_group_json())
    pg = out["BGP_PEER_GROUP"]["default|BGPSLBPassive"]
    assert pg["asn"] == "65432"                 # remote-as -> asn
    assert pg["local_addr"] == "10.1.0.32"      # update-source -> local_addr
    assert pg["passive_mode"] == "true"         # passive
    assert pg["ebgp_multihop"] == "true"        # ebgp-multihop (bare, no ttl)
    assert "ebgp_multihop_ttl" not in pg
    assert pg["peer_group_name"] == "BGPSLBPassive" and pg["vrf_name"] == "default"


def test_listen_range_peer_group_af_translated():
    out = translate_config_db(
        _config_db_with_peer_range(), _T0_LISTEN_RANGE_RUNNING, _peer_group_json())
    af = out["BGP_PEER_GROUP_AF"]["default|BGPSLBPassive|ipv4_unicast"]
    assert af["route_map_in"] == ["FROM_BGP_SPEAKER"]
    assert af["route_map_out"] == ["TO_BGP_SPEAKER"]
    assert af["soft_reconfiguration_in"] == "true"
    # 'neighbor <pg> activate' -> admin_status:up so frrcfgd activates the peer-group in
    # the AF (a listen-range pg has no neighbor rows to carry the activation).
    assert af["admin_status"] == "up"
    # It is ipv4-only: no ipv6 AF row should be invented.
    assert "default|BGPSLBPassive|ipv6_unicast" not in out["BGP_PEER_GROUP_AF"]


def test_listen_prefix_emitted_from_peer_range():
    out = translate_config_db(
        _config_db_with_peer_range(), _T0_LISTEN_RANGE_RUNNING, _peer_group_json())
    lp = out["BGP_GLOBALS_LISTEN_PREFIX"]["default|10.255.0.0/25"]
    assert lp == {"vrf_name": "default", "ip_prefix": "10.255.0.0/25",
                  "peer_group": "BGPSLBPassive"}
    # The traditional BGP_PEER_RANGE table must be dropped (frrcfgd does not consume it).
    assert "BGP_PEER_RANGE" not in out


def test_bbr_does_not_leak_onto_listen_range_peer_group():
    cfg = _config_db_with_peer_range()
    cfg["BGP_BBR"] = {"all": {"status": "enabled"}}
    out = translate_config_db(cfg, _T0_LISTEN_RANGE_RUNNING, _peer_group_json())
    # BBR allowas-in belongs on the primary v4/v6 peer-groups only ...
    assert out["BGP_PEER_GROUP_AF"]["default|PEER_V4|ipv4_unicast"]["allow_as_in"] == "true"
    # ... never on the listen-range peer-group.
    slb_af = out["BGP_PEER_GROUP_AF"]["default|BGPSLBPassive|ipv4_unicast"]
    assert "allow_as_in" not in slb_af and "allow_as_count" not in slb_af


def test_no_peer_range_leaves_no_listen_prefix_table():
    # Baseline (no BGP_PEER_RANGE) must not synthesize a listen-prefix table.
    out = translate_config_db(_base_config_db(), "", _peer_group_json())
    assert "BGP_GLOBALS_LISTEN_PREFIX" not in out

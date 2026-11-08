import pytest

from tests.common.helpers.frr.bgp_config_translation import FrrTranslationError
from tests.common.helpers.frr.bgp_config_writer import to_frr_rows

CONFIG_DB = {
    "DEVICE_METADATA": {"localhost": {"bgp_asn": "65100"}},
    "BGP_PEER_GROUP_AF": {"default|PEER_V4|ipv4_unicast": {}, "default|PEER_V6|ipv6_unicast": {},
                          "default|PEER_V4|ipv6_unicast": {}, "default|OTHER|ipv4_unicast": {}},
}
CONSTANTS = {"constants": {"bgp": {
    "peers": {"general": {"bbr": {"PEER_V4": ["ipv4"], "PEER_V6": ["ipv6"]}}},
    "allow_list": {"drop_community": "5060:12345",
                   "default_pl_rules": {"v4": ["deny 0.0.0.0/0 le 17"], "v6": []}},
}}}


def test_peer_range_converts_to_listen_prefix_peer_group_and_af():
    rows = {"BGP_PEER_RANGE": {"BGPSLB": {"name": "BGPSLB", "ip_range": ["10.1.0.0/24"],
                                          "src_address": "10.0.0.1", "peer_asn": "65432"}}}
    tables, del_fields, pgs = to_frr_rows(rows, CONFIG_DB, CONSTANTS)
    assert tables == {
        "BGP_GLOBALS_LISTEN_PREFIX": {"default|10.1.0.0/24": {
            "vrf_name": "default", "ip_prefix": "10.1.0.0/24", "peer_group": "BGPSLB"}},
        "BGP_PEER_GROUP": {"default|BGPSLB": {
            "asn": "65432", "local_addr": "10.0.0.1", "local_asn": "65100", "name": "BGPSLB",
            "passive_mode": "true", "ebgp_multihop": "true", "peer_group_name": "BGPSLB",
            "vrf_name": "default"}},
        "BGP_PEER_GROUP_AF": {"default|BGPSLB|ipv4_unicast": {
            "admin_status": "up", "afi_safi": "ipv4_unicast", "peer_group_name": "BGPSLB",
            "route_map_in": ["FROM_BGP_SPEAKER"], "route_map_out": ["TO_BGP_SPEAKER"],
            "soft_reconfiguration_in": "true", "vrf_name": "default"}},
    }
    assert (del_fields, pgs) == ({}, set())


_BBR_ON = {"allow_as_in": "true", "allow_as_count": "1"}
_BBR_FIELDS = ["allow_as_in", "allow_as_count"]


# Only the AFs eligible per constants.yml (PEER_V4/ipv4, PEER_V6/ipv6) are touched.
@pytest.mark.parametrize("status,tables,del_fields", [
    ("enabled", {"BGP_PEER_GROUP_AF": {"default|PEER_V4|ipv4_unicast": _BBR_ON,
                                       "default|PEER_V6|ipv6_unicast": _BBR_ON}}, {}),
    ("disabled", {}, {"BGP_PEER_GROUP_AF|default|PEER_V4|ipv4_unicast": _BBR_FIELDS,
                      "BGP_PEER_GROUP_AF|default|PEER_V6|ipv6_unicast": _BBR_FIELDS}),
])
def test_bbr_status_on_eligible_afs_only(status, tables, del_fields):
    result = to_frr_rows({"BGP_BBR": {"all": {"status": status}}}, CONFIG_DB, CONSTANTS)
    assert result == (tables, del_fields, {"PEER_V4", "PEER_V6"})


def test_allow_list_converts_to_policy_tables():
    rows = {"BGP_ALLOWED_PREFIXES": {"DEPLOYMENT_ID|0|1010:1010": {
        "prefixes_v4": ["172.16.30.0/24"], "default_action": "permit"}}}
    tables, _, _ = to_frr_rows(rows, CONFIG_DB, CONSTANTS)
    pl = "PL_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_1010:1010_V4"
    assert sorted(tables["PREFIX"]) == ["{}|10|0.0.0.0/0|0..17".format(pl),
                                        "{}|20|172.16.30.0/24|24..32".format(pl)]
    assert tables["ROUTE_MAP"]["ALLOW_LIST_DEPLOYMENT_ID_0_V4|65535"] == {
        "route_operation": "permit", "set_community_inline": ["5060:12345", "additive"]}


def test_unconverted_table_raises():
    with pytest.raises(FrrTranslationError):
        to_frr_rows({"BGP_NEIGHBOR": {"10.0.0.1": {}}}, CONFIG_DB, CONSTANTS)

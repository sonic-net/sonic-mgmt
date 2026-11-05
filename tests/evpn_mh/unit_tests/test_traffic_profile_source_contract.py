"""Source and runtime traffic-profile contracts for the exact-16 port."""

from pathlib import Path
import unittest

import yaml
from yaml.constructor import ConstructorError

from tests.evpn_mh.traffic_profile import _compile_expected


REPO_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_PATH = REPO_ROOT / "tests/evpn_mh/files/traffic_profiles.yml"


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class _UniqueLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark,
                "found duplicate key {!r}".format(key), key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


class TrafficProfileSourceContractTests(unittest.TestCase):
    def test_runtime_profile_is_accepted_by_duplicate_rejecting_loader(self):
        with RUNTIME_PATH.open(encoding="utf-8") as stream:
            document = yaml.load(stream, Loader=_UniqueLoader)
        self.assertEqual(len(document["profiles"]), 13)

    def test_runtime_profiles_preserve_exact_paired_500_tuple_contracts(self):
        document = _load(RUNTIME_PATH)
        profiles = document["profiles"]
        self.assertIn("remote_routed_bum", profiles)
        retired_name = "_".join(("mh", "leaf2", "routed", "bum"))
        self.assertNotIn(retired_name, profiles)
        flows = {
            flow["name"]: flow
            for profile in profiles.values()
            for flow in profile["flows"]
        }
        for name in ("h3_to_mh_ecmp", "h3_to_h2_v6"):
            flow = flows[name]
            self.assertEqual(flow["packet_count"], 500)
            self.assertEqual(flow["udp_src_count"], 500)
            self.assertEqual(flow["udp_dst_count"], 500)
            self.assertEqual(flow["udp_port_step"], 1)

    def test_ipv6_bum_is_a_real_ipv6_udp_payload(self):
        document = _load(RUNTIME_PATH)
        flows = document["profiles"]["ipv6_baseline"]["flows"]
        bum = next(flow for flow in flows
                   if flow["name"] == "h3_ipv6_broadcast")
        self.assertEqual(bum["packet"]["kind"], "ipv6_udp")
        self.assertEqual(bum["packet"]["dst_mac"], "ff:ff:ff:ff:ff:ff")

    def test_public_candidate_contains_no_third_sonic_leaf_profile_name(self):
        text = RUNTIME_PATH.read_text(encoding="utf-8")
        retired_role = "mh_" + "leaf" + str(1 + 1)
        self.assertNotIn(retired_role, text)

    def test_remote_bum_declares_two_es_and_one_sh_endpoint(self):
        profiles = _load(RUNTIME_PATH)["profiles"]
        for name in (
                "remote_broadcast", "remote_multicast",
                "remote_unknown_unicast"):
            flow = profiles[name]["flows"][0]
            self.assertEqual(
                flow["receive_groups"], [["sh1"], ["h1"], ["h2"]])
        self.assertNotIn("h5", RUNTIME_PATH.read_text(encoding="utf-8"))

    def test_orphan_profiles_use_the_declared_single_homed_endpoint(self):
        profiles = _load(RUNTIME_PATH)["profiles"]
        self.assertEqual(
            profiles["vlan_detached_drop"]["flows"][0]["tx_endpoint"],
            "sh1")
        self.assertEqual(
            profiles["local_bias"]["flows"][0]["tx_endpoint"], "sh1")
        self.assertEqual(
            profiles["l3_orphan_to_mh"]["flows"][0]["tx_endpoint"],
            "sh1")

    def test_local_bias_covers_both_ethernet_segments(self):
        flow = _load(RUNTIME_PATH)["profiles"]["local_bias"]["flows"][0]
        self.assertEqual(
            flow["receive_groups"],
            [["h3"], ["h1_leg0"], ["h2_leg0"]],
        )
        self.assertEqual(
            flow["forbidden_endpoints"], ["h1_leg1", "h2_leg1"])

    def test_intra_subnet_proves_both_es_and_sh1_recovery(self):
        flows = {
            flow["name"]: flow
            for flow in _load(RUNTIME_PATH)["profiles"]["intra_subnet"]["flows"]
        }
        expected_pairs = {
            "h1_to_h2": ("h1", [["h2"]]),
            "h2_to_h1": ("h2", [["h1"]]),
            "sh1_to_h2": ("sh1", [["h2"]]),
            "h2_to_sh1": ("h2", [["sh1"]]),
        }
        for name, (source, receive_groups) in expected_pairs.items():
            self.assertEqual(flows[name]["tx_endpoint"], source)
            self.assertEqual(flows[name]["receive_groups"], receive_groups)

    def test_symmetric_irb_decrements_both_directions_twice(self):
        topology = {
            "anycast_gateway_mac": "00:11:22:33:44:11",
            "mh_vlan": 10,
            "remote_vlan": 20,
            "routed_egress_macs": {
                "remote_leaf": {"20": "02:aa:bb:cc:dd:20"},
            },
            "endpoints": {
                "h1": {
                    "attachment_role": "mh_leaf0",
                    "vlan": 10,
                    "mac": "02:00:00:00:00:01",
                },
                "h4": {
                    "attachment_role": "remote_leaf",
                    "vlan": 20,
                    "mac": "02:00:00:00:00:04",
                },
            },
        }
        forward_v4 = _compile_expected(
            {"src": "h1", "dst": "h4", "kind": "ipv4_udp", "routed": True},
            {}, topology)
        reverse_v4 = _compile_expected(
            {"src": "h4", "dst": "h1", "kind": "ipv4_udp", "routed": True},
            {}, topology)
        forward_v6 = _compile_expected(
            {"src": "h1", "dst": "h4", "kind": "ipv6_udp", "routed": True},
            {}, topology)
        reverse_v6 = _compile_expected(
            {"src": "h4", "dst": "h1", "kind": "ipv6_udp", "routed": True},
            {}, topology)

        self.assertEqual(forward_v4["ttl"], 62)
        self.assertEqual(reverse_v4["ttl"], 62)
        self.assertEqual(forward_v6["hlim"], 62)
        self.assertEqual(reverse_v6["hlim"], 62)
        self.assertEqual(forward_v4["src_mac"], "02:aa:bb:cc:dd:20")
        self.assertEqual(
            reverse_v4["src_mac"], topology["anycast_gateway_mac"])


if __name__ == "__main__":
    unittest.main()

"""Unit contracts for reversible stock-T1 EOS overlay ownership."""

import importlib.util
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tests" / "evpn_mh" / "eos_overlay.py"


def _load_module():
    name = "evpn_mh_eos_overlay_runtime"
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return name, module


class FakeEosHost:
    def __init__(self, hostname, running_config):
        self.hostname = hostname
        self.running_config = running_config
        self.files = {}
        self.config_calls = []
        self.interactive_calls = []
        self.json_responses = {}
        self.fail_delete = False
        self.replace_noop = False

    def run_command(self, command):
        if command == "show running-config":
            return {"stdout": self.running_config}
        if command.startswith("copy running-config "):
            filename = command.split()[-1]
            self.files[filename] = self.running_config
            return {"stdout": ""}
        if command.startswith("show file "):
            return {"stdout": self.files[command.split()[-1]]}
        if command == "show version":
            return {"stdout": "EOS test image"}
        raise AssertionError("unexpected command {}".format(command))

    def run_command_json(self, command):
        return self.json_responses.get(
            command, {"command": command, "supported": True}
        )

    def eos_config(self, **kwargs):
        self.config_calls.append(kwargs)
        return {"changed": True}

    def eos_command(self, commands, **_kwargs):
        command = commands[0]["command"]
        self.interactive_calls.append(command)
        if command.startswith("configure replace "):
            if not self.replace_noop:
                self.running_config = self.files[command.split()[-1]]
            return {"changed": True}
        if command.startswith("delete "):
            if self.fail_delete:
                return {"failed": True, "msg": "injected delete failure"}
            self.files.pop(command.split()[-1], None)
            return {"changed": True}
        raise AssertionError("unexpected interactive command {}".format(command))


class EosOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module_name, cls.overlay = _load_module()

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop(cls.module_name, None)

    @staticmethod
    def _running(interface, address):
        return "\n".join((
            "! Command: show running-config",
            "hostname test",
            "interface {}".format(interface),
            "   ip address {}".format(address),
            "   ipv6 address 20c0:a800::1/64",
            "!",
        ))

    @staticmethod
    def _topology():
        return {
            "overlay_asn": 65100,
            "remote_overlay_asn": 64600,
            "mh_vlan": 10,
            "remote_vlan": 20,
            "l3vni_vlan": 30,
            "l2vni": 5010,
            "remote_l2vni": 5020,
            "l3vni": 5030,
            "vrf": "Vrf01",
            "anycast_gateway_mac": "00:00:5e:00:01:01",
            "underlay_neighbor_names": ["A01", "A02", "A03"],
            "remote_neighbor_name": "A04",
            "vtep_ip": {
                "mh_leaf0": "10.1.0.32",
                "mh_leaf1": "10.1.0.33",
                "remote_leaf": "100.1.0.32",
            },
            "endpoints": {
                "h3": {
                    "gateway_ipv4": "192.0.2.1", "ipv4_prefixlen": 24,
                    "gateway_ipv6": "2001:db8:10::1", "ipv6_prefixlen": 64,
                },
                "h4": {
                    "gateway_ipv4": "198.51.100.1", "ipv4_prefixlen": 24,
                    "gateway_ipv6": "2001:db8:20::1", "ipv6_prefixlen": 64,
                },
            },
        }

    def _overlay_plan(self):
        plan = {}
        roles = ("underlay0", "underlay1", "underlay2", "remote_leaf")
        for index, role in enumerate(roles, start=1):
            plan[role] = {
                "host": FakeEosHost(role, self._running(
                    "Ethernet{}".format(index), "10.0.{}.1/24".format(index)
                )),
                "backplane_interface": "Ethernet{}".format(index),
                "backplane_ipv4": "10.0.{}.1/24".format(index),
                "backplane_ipv6": "20c0:a800::1/64",
                "transit_address": "198.18.0.{}/29".format(index),
                "transit_ip": "198.18.0.{}".format(index),
                "direct_dut_peers": (
                    ("10.1.0.0", "10.1.0.2")
                    if role == "remote_leaf"
                    else ("10.2.{}.1".format(index),)
                ),
            }
        return plan

    def test_normalization_ignores_only_volatile_headers(self):
        first = "! Command: one\nhostname eos\ninterface Ethernet9\n"
        second = "! Command: two\nhostname eos\ninterface Ethernet9\n"
        self.assertEqual(
            self.overlay.normalize_eos_config(first),
            self.overlay.normalize_eos_config(second),
        )
        self.assertIn("hostname eos", self.overlay.normalize_eos_config(first))

    def test_interface_binding_is_exact_and_ambiguity_fails_closed(self):
        running = self._running("Ethernet9", "10.0.0.1/24")
        self.assertEqual(
            self.overlay.interface_for_address(running, "10.0.0.1/24"),
            "Ethernet9",
        )
        duplicate = running + "\ninterface Ethernet10\n   ip address 10.0.0.1/24\n"
        with self.assertRaisesRegex(self.overlay.EosOverlayError, "2 EOS interfaces"):
            self.overlay.interface_for_address(duplicate, "10.0.0.1/24")

    def test_snapshot_restore_proves_exact_config_and_deletes_snapshot(self):
        original = self._running("Ethernet9", "10.0.0.1/24")
        host = FakeEosHost("A01", original)
        snapshot = self.overlay.snapshot_eos_config(host)
        self.assertRegex(snapshot["filename"], r"^flash:evpn-mh-A01-[0-9a-f]{12}\.cfg$")
        host.running_config = original + "router bgp 64600\n"
        self.overlay.restore_eos_config(host, snapshot)
        self.assertEqual(host.running_config, original)
        self.assertEqual(host.files, {})

    def test_restore_reports_replace_and_delete_failures(self):
        original = self._running("Ethernet9", "10.0.0.1/24")
        host = FakeEosHost("A01", original)
        snapshot = self.overlay.snapshot_eos_config(host)
        host.fail_delete = True
        with self.assertRaisesRegex(
                self.overlay.EosOverlayError, "snapshot deletion"):
            self.overlay.restore_eos_config(host, snapshot)

    def test_non_identical_restore_preserves_recovery_snapshot(self):
        original = self._running("Ethernet9", "10.0.0.1/24")
        host = FakeEosHost("A01", original)
        snapshot = self.overlay.snapshot_eos_config(host)
        host.running_config = original + "\nrouter bgp 64600\n"
        host.replace_noop = True
        with self.assertRaisesRegex(
                self.overlay.EosOverlayError,
                "running configuration differs from snapshot"):
            self.overlay.restore_eos_config(host, snapshot)
        self.assertIn(snapshot["filename"], host.files)
        self.assertFalse(any(
            command.startswith("delete ")
            for command in host.interactive_calls
        ))

    def test_plan_derives_physical_backplane_and_transit_without_guessing(self):
        roles = ("underlay0", "underlay1", "underlay2", "remote_leaf")
        names = ("A01", "A02", "A03", "A04")
        neighbors = {}
        snapshots = {}
        configuration = {}
        for index, (role, name) in enumerate(zip(roles, names), start=1):
            address = "10.0.{}.1/24".format(index)
            running = self._running("Ethernet{}".format(index + 40), address)
            host = FakeEosHost(name, running)
            neighbors[role] = host
            snapshots[role] = {
                "hostname": name,
                "running_config": running,
            }
            configuration[name] = {
                "bp_interface": {
                    "ipv4": address,
                    "ipv6": "20c0:a800::1/64",
                },
                "bgp": {
                    "asn": 64600,
                    "peers": {65100: ["10.1.{}.1".format(index)]},
                },
            }
        tbinfo = {"topo": {"properties": {"configuration": configuration}}}
        plan = self.overlay.build_eos_overlay_plan(
            neighbors, tbinfo, self._topology(), snapshots
        )
        self.assertEqual(plan["underlay0"]["backplane_interface"], "Ethernet41")
        self.assertEqual(plan["remote_leaf"]["transit_ip"], "198.18.0.4")
        self.assertEqual(plan["remote_leaf"]["direct_dut_peers"], ("10.1.4.1",))

    def test_configuration_phases_prove_transit_before_direct_shutdown(self):
        topology = self._topology()
        plan = self._overlay_plan()
        self.overlay.configure_eos_transit(plan, topology)
        remote_calls = plan["remote_leaf"]["host"].config_calls
        rendered = "\n".join(
            line for call in remote_calls for line in call.get("lines", [])
        )
        self.assertIn("switchport trunk allowed vlan 10,20,4094", rendered)
        self.assertIn("network 100.1.0.32/32", rendered)
        self.assertNotIn("neighbor 10.1.0.0 shutdown", rendered)
        transit_call_count = len(remote_calls)

        self.overlay.shutdown_eos_direct_peers(plan, topology)
        shutdown_rendered = "\n".join(
            line
            for call in remote_calls[transit_call_count:]
            for line in call.get("lines", [])
        )
        self.assertIn("neighbor 10.1.0.0 shutdown", shutdown_rendered)
        self.assertIn("neighbor 10.1.0.2 shutdown", shutdown_rendered)
        shutdown_call_count = len(remote_calls)

        self.overlay.configure_eos_remote_overlay(plan, topology)
        overlay_rendered = "\n".join(
            line
            for call in remote_calls[shutdown_call_count:]
            for line in call.get("lines", [])
        )
        self.assertIn("route-target both 65100:5010", overlay_rendered)
        self.assertNotIn("route-target both 64600:5010", overlay_rendered)
        self.assertNotIn("neighbor 10.1.0.0 shutdown", overlay_rendered)
        self.assertNotIn("neighbor 10.1.0.2 shutdown", overlay_rendered)
        underlay_rendered = "\n".join(
            line
            for role in ("underlay0", "underlay1", "underlay2")
            for call in plan[role]["host"].config_calls
            for line in call.get("lines", [])
        )
        self.assertIn(
            "neighbor 10.2.1.1 as-path remote-as replace-out",
            underlay_rendered,
        )

    def test_evidence_helpers_require_two_aliasing_vteps(self):
        routes = {
            "routes": [{
                "mac": "00:11:22:33:44:55",
                "paths": [{"vtep": "10.1.0.32"}, {"vtep": "10.1.0.33"}],
            }]
        }
        self.assertEqual(
            self.overlay.eos_aliasing_vteps(
                routes, "00:11:22:33:44:55", ("10.1.0.32", "10.1.0.33")
            ),
            {"10.1.0.32", "10.1.0.33"},
        )

    def test_peer_parser_requires_exact_unique_addresses(self):
        summary = {"vrfs": {"default": {"peers": {
            "10.1.0.32": {"peerState": "Established"},
            "192.0.2.99": {"peerState": "Established"},
        }}}}
        self.assertEqual(
            self.overlay.eos_established_peers(summary),
            {"10.1.0.32", "192.0.2.99"},
        )
        host = FakeEosHost("A04", self._running("Ethernet4", "10.0.4.1/24"))
        host.json_responses["show bgp evpn summary"] = summary
        self.assertFalse(self.overlay.eos_evpn_peers_ready(
            host, {"10.1.0.32", "10.1.0.33"}
        ))

        records = {"peers": [
            {"peerAddress": "10.1.0.33", "state": "Established"},
            {"peerAddress": "10.1.0.33", "state": "Established"},
        ]}
        self.assertEqual(
            self.overlay.eos_established_peers(records), {"10.1.0.33"}
        )
        records["peers"].append(
            {"peerAddress": "10.1.0.33", "state": "Idle"}
        )
        self.assertEqual(self.overlay.eos_established_peers(records), set())

    def test_transit_readiness_proves_all_paths_and_direct_peer_cutover(self):
        topology = self._topology()
        plan = self._overlay_plan()
        remote = plan["remote_leaf"]
        remote_host = remote["host"]
        transit_peers = [
            plan[role]["transit_ip"] for role in self.overlay.UNDERLAY_ROLES
        ]
        remote_host.json_responses["show ip bgp summary"] = {
            "peers": {
                peer: {"peerState": "Established"}
                for peer in transit_peers
            }
        }
        for role in ("mh_leaf0", "mh_leaf1"):
            prefix = "{}/32".format(topology["vtep_ip"][role])
            remote_host.json_responses[
                "show ip route {}".format(prefix)
            ] = {"routes": {prefix: {}}}
            remote_host.json_responses[
                "show ip bgp {}".format(prefix)
            ] = {"routes": {prefix: {
                "paths": [{"nextHop": peer} for peer in transit_peers]
            }}}

        remote_prefix = "{}/32".format(topology["vtep_ip"]["remote_leaf"])
        for role in self.overlay.UNDERLAY_ROLES:
            host = plan[role]["host"]
            host.json_responses["show ip bgp summary"] = {
                "peers": {
                    remote["transit_ip"]: {"peerState": "Established"}
                }
            }
            host.json_responses[
                "show ip route {}".format(remote_prefix)
            ] = {"routes": {remote_prefix: {}}}

        self.assertTrue(self.overlay.eos_transit_ready(plan, topology))
        remote_host.json_responses["show ip bgp summary"]["peers"][
            remote["direct_dut_peers"][0]
        ] = {"peerState": "Established"}
        self.assertFalse(self.overlay.eos_transit_ready(
            plan, topology, require_direct_down=True
        ))
        remote_host.json_responses["show ip bgp summary"]["peers"][
            remote["direct_dut_peers"][0]
        ] = {"peerState": "Idle"}
        self.assertTrue(self.overlay.eos_transit_ready(
            plan, topology, require_direct_down=True
        ))

        prefix = "{}/32".format(topology["vtep_ip"]["mh_leaf0"])
        remote_host.json_responses[
            "show ip bgp {}".format(prefix)
        ] = {"routes": {prefix: {
            "paths": [{"nextHop": transit_peers[0]}]
        }}}
        self.assertFalse(self.overlay.eos_transit_ready(plan, topology))

    def test_single_survivor_check_exposes_a_stale_second_vtep(self):
        routes = {
            "routes": [{
                "mac": "00:11:22:33:44:55",
                "paths": [
                    {"vtep": "10.1.0.32"},
                    {"vtep": "10.1.0.33"},
                ],
            }]
        }
        full_candidates = {"10.1.0.32", "10.1.0.33"}
        expected_survivor = {"10.1.0.33"}
        observed = self.overlay.eos_aliasing_vteps(
            routes, "00:11:22:33:44:55", full_candidates)
        self.assertEqual(observed, full_candidates)
        self.assertNotEqual(observed, expected_survivor)

    def test_aliasing_cannot_combine_unrelated_sibling_routes(self):
        routes = {"routes": [
            {"mac": "00:11:22:33:44:55", "paths": []},
            {"mac": "00:aa:bb:cc:dd:ee", "paths": [
                {"vtep": "10.1.0.32"}, {"vtep": "10.1.0.33"},
            ]},
        ]}
        self.assertEqual(
            self.overlay.eos_aliasing_vteps(
                routes, "00:11:22:33:44:55",
                ("10.1.0.32", "10.1.0.33"),
            ),
            set(),
        )


if __name__ == "__main__":
    unittest.main()

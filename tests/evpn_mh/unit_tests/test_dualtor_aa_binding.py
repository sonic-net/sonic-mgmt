"""Static and dependency-light contracts for the immutable topology binding."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPO_ROOT / "tests" / "evpn_mh"
TOPOLOGY_RELATIVE = Path("ansible/vars/topo_dualtor-aa.yml")


def _sonic_mgmt_root():
    configured = os.environ.get("SONIC_MGMT_ROOT")
    if configured:
        root = Path(configured).resolve()
        if (root / TOPOLOGY_RELATIVE).is_file():
            return root
        raise RuntimeError("SONIC_MGMT_ROOT lacks {}".format(TOPOLOGY_RELATIVE))
    for start in (Path.cwd(), Path(__file__).resolve()):
        for parent in (start,) + tuple(start.parents):
            if (parent / TOPOLOGY_RELATIVE).is_file():
                return parent
    raise RuntimeError("set SONIC_MGMT_ROOT to an unmodified sonic-mgmt tree")


def _load_runtime_modules():
    package_name = "evpn_mh_dualtor_contract_runtime"
    package = types.ModuleType(package_name)
    package.__path__ = [str(PACKAGE_ROOT)]
    sys.modules[package_name] = package
    loaded = {}
    for name in ("topology", "dualtor_overlay", "state", "operations"):
        qualified = "{}.{}".format(package_name, name)
        spec = importlib.util.spec_from_file_location(
            qualified, PACKAGE_ROOT / "{}.py".format(name)
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[qualified] = module
        spec.loader.exec_module(module)
        loaded[name] = module
    return package_name, loaded


def _tbinfo(document):
    return {
        "topo": {
            "name": "dualtor-aa",
            "type": "t0",
            "properties": {
                "topology": document["topology"],
                "configuration": document["configuration"],
            },
        },
        "group-name": "vms17-8",
    }


def _config_from_portchannel_snapshot(snapshot):
    config = {
        "PORTCHANNEL": {},
        "PORTCHANNEL_MEMBER": {},
        "VLAN_MEMBER": {},
        "EVPN_ETHERNET_SEGMENT": {},
    }
    bindings = (
        ("portchannel", "PORTCHANNEL", "PortChannel100"),
        ("member", "PORTCHANNEL_MEMBER", "PortChannel100|Ethernet25"),
        ("vlan_member", "VLAN_MEMBER", "Vlan10|PortChannel100"),
        ("ethernet_segment", "EVPN_ETHERNET_SEGMENT", "PortChannel100"),
    )
    for component, table, key in bindings:
        if snapshot.get(component) is not None:
            config[table][key] = json.loads(json.dumps(snapshot[component]))
    return config


class FakePortchannelDut:
    hostname = "upper"

    def __init__(self, snapshot, desired, fail_after_mutation=None):
        self.config = _config_from_portchannel_snapshot(snapshot)
        self.desired = desired
        self.fail_after_mutation = fail_after_mutation
        self.commands = []

    def shell(self, command, **_kwargs):
        self.commands.append(command)
        if command == "sonic-cfggen -d --print-data":
            return {"rc": 0, "stdout": json.dumps(self.config)}

        if command == "sudo config portchannel add PortChannel100":
            row = dict(self.desired["portchannel"])
            row.pop("system_mac", None)
            self.config["PORTCHANNEL"]["PortChannel100"] = row
        elif command == (
                "sudo config interface ipv6 disable use-link-local-only "
                "Ethernet25"):
            pass
        elif command == (
                "sudo config portchannel member add PortChannel100 "
                "Ethernet25"):
            self.config["PORTCHANNEL_MEMBER"][
                "PortChannel100|Ethernet25"
            ] = dict(self.desired["member"])
        elif command == (
                "sudo config vlan member add -u 10 PortChannel100"):
            self.config["VLAN_MEMBER"][
                "Vlan10|PortChannel100"
            ] = dict(self.desired["vlan_member"])
        elif command == (
                "sudo config interface sys-mac add PortChannel100 "
                "00:44:33:22:11:00"):
            self.config["PORTCHANNEL"]["PortChannel100"][
                "system_mac"
            ] = "00:44:33:22:11:00"
        elif command == (
                "sudo config interface evpn-esi add PortChannel100 "
                "auto-system-mac"):
            self.config["EVPN_ETHERNET_SEGMENT"][
                "PortChannel100"
            ] = dict(self.desired["ethernet_segment"])
        else:
            raise AssertionError("unexpected command {}".format(command))

        if command == self.fail_after_mutation:
            return {"rc": 1, "stderr": "injected post-mutation failure"}
        return {"rc": 0, "stdout": ""}


class DualtorAaBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package_name, cls.modules = _load_runtime_modules()
        cls.path = _sonic_mgmt_root() / TOPOLOGY_RELATIVE
        cls.document = yaml.safe_load(cls.path.read_text(encoding="utf-8"))
        cls.tbinfo = _tbinfo(cls.document)

    @classmethod
    def tearDownClass(cls):
        prefix = cls.package_name + "."
        for name in tuple(sys.modules):
            if name == cls.package_name or name.startswith(prefix):
                sys.modules.pop(name, None)

    @staticmethod
    def _portchannel_baseline():
        return {
            "portchannel": {
                "admin_status": "up",
                "mtu": "9100",
                "system_mac": "00:44:33:22:11:00",
            },
            "member": {},
            "vlan_member": {"tagging_mode": "untagged"},
            "ethernet_segment": {
                "esi": "auto",
                "type": "TYPE_3_MAC_BASED",
            },
        }

    def test_public_topology_satisfies_runtime_contract(self):
        topology = self.modules["topology"]
        validated = topology.validate_stock_topology(self.tbinfo)
        self.assertEqual(
            validated,
            self.document["topology"],
        )
        self.assertEqual(int(validated["dut_num"]), 2)
        self.assertEqual(
            tuple(validated["VMs"]),
            tuple(topology.NEIGHBOR_NAMES.values()),
        )

    def test_stock_shape_and_ptf_roles(self):
        topology = self.modules["topology"]
        topology.validate_stock_topology(self.tbinfo)
        self.assertEqual(topology.backplane_ptf_index(self.tbinfo), 36)
        self.assertEqual(topology.resolve_ptf_ports(self.tbinfo), {
            "h1_leg0": 0,
            "sh1": 1,
            "h2_leg0": 25,
            "h2_leg1": 26,
            "h1_leg1": 27,
            "h3": 36,
            "h4": 36,
            "backplane": 36,
        })
        self.assertEqual(topology.STOCK_DISABLED_PAIRS, (0, 25, 26, 27))
        self.assertEqual(topology.FEATURE_PINNED_PAIRS, (0, 1, 25, 26, 27))

    def test_service_model_is_separate_and_attachment_aware(self):
        topology = self.modules["topology"]
        service = topology.load_service_model()
        self.assertEqual(
            set(service["endpoints"]), {"h1", "h2", "h3", "h4", "sh1"})
        self.assertEqual(service["endpoints"]["h3"]["tagged_vlan"], 10)
        self.assertEqual(service["endpoints"]["h4"]["tagged_vlan"], 20)
        self.assertEqual(service["primary_test_segment"], "es_h2")
        self.assertEqual(set(service["ethernet_segments"]), {"es_h1", "es_h2"})
        h1_segment = service["ethernet_segments"]["es_h1"]
        h2_segment = service["ethernet_segments"]["es_h2"]
        self.assertEqual(h1_segment["ptf_member_roles"], ["h1_leg0", "h1_leg1"])
        self.assertEqual(h2_segment["ptf_member_roles"], ["h2_leg0", "h2_leg1"])
        self.assertEqual(h1_segment["leaf_roles"], ["mh_leaf0", "mh_leaf1"])
        self.assertEqual(h2_segment["leaf_roles"], ["mh_leaf0", "mh_leaf1"])
        self.assertEqual(service["single_homed_endpoints"], {
            "sh1": {
                "dut_role": "mh_leaf0",
                "ptf_port_role": "sh1",
                "vlan": 10,
                "l2vni": 5010,
                "stock_vlan": 1000,
                "stock_mux_cable_type": "active-active",
            }
        })
        for field in (
                "esi", "portchannel", "system_mac", "ptf_system_mac",
                "ptf_bond_interface", "ptf_host_interface"):
            self.assertNotEqual(h1_segment[field], h2_segment[field])
        for segment in (h1_segment, h2_segment):
            portchannel_id = int(segment["portchannel"].replace(
                "PortChannel", "", 1))
            discriminator = "{:06x}".format(portchannel_id)
            expected_esi = "03:{}:{}:{}:{}".format(
                segment["system_mac"], discriminator[0:2],
                discriminator[2:4], discriminator[4:6])
            self.assertEqual(segment["esi"], expected_esi)
        rendered = (PACKAGE_ROOT / "files/evpn_mh_service.yml").read_text()
        for forbidden in ("Ethernet0", "password", "username"):
            self.assertNotIn(forbidden, rendered)

    def test_stock_derived_vtep_and_underlay_data(self):
        properties = self.modules["topology"].evpn_mh_properties(self.tbinfo)
        self.assertEqual(properties["vtep_ip"], {
            "mh_leaf0": "10.1.0.32",
            "mh_leaf1": "10.1.0.33",
            "remote_leaf": "100.1.0.32",
        })
        self.assertEqual(properties["underlay_neighbor_names"], [
            "ARISTA01T1", "ARISTA02T1", "ARISTA03T1",
        ])
        self.assertEqual(len(properties["underlay_peers"]["mh_leaf0"]), 6)
        self.assertEqual(len(properties["underlay_peers"]["mh_leaf1"]), 6)

    def test_duplicate_segment_identity_is_rejected(self):
        topology = self.modules["topology"]
        service = topology.load_service_model()
        service["ethernet_segments"]["es_h1"]["esi"] = (
            service["ethernet_segments"]["es_h2"]["esi"])
        with self.assertRaisesRegex(
                topology.TopologyContractError, "esi values must be unique"):
            topology.ethernet_segments(service)

    def test_roles_never_model_remote_eos_as_sonic(self):
        topology = self.modules["topology"]
        upper = types.SimpleNamespace(hostname="upper")
        lower = types.SimpleNamespace(hostname="lower")
        self.assertEqual(
            topology.resolve_dut_roles((upper, lower), self.tbinfo),
            {"mh_leaf0": upper, "mh_leaf1": lower},
        )
        eos_hosts = {
            name: {"host": types.SimpleNamespace(hostname=name)}
            for name in topology.NEIGHBOR_NAMES.values()
        }
        neighbors = topology.resolve_neighbor_roles(eos_hosts, self.tbinfo)
        self.assertEqual(set(neighbors), {
            "underlay0", "underlay1", "underlay2", "remote_leaf",
        })
        self.assertNotIn("remote_leaf", topology.REQUIRED_DUT_ROLES)

    def test_runtime_interface_resolution_excludes_remote_path_from_spines(self):
        topology = self.modules["topology"]

        class Dut:
            def __init__(self, hostname):
                self.hostname = hostname

            @staticmethod
            def get_extended_minigraph_facts(_tbinfo):
                return {
                    "minigraph_port_indices": {
                        "Ethernet{}".format(index): index for index in range(32)
                    }
                }

        duts = {"mh_leaf0": Dut("upper"), "mh_leaf1": Dut("lower")}
        resolved = topology.resolve_dut_interfaces(
            duts, self.tbinfo, topology.resolve_ptf_ports(self.tbinfo)
        )
        self.assertEqual(resolved["h1_leg0"]["interface"], "Ethernet0")
        self.assertEqual(resolved["sh1"]["interface"], "Ethernet1")
        self.assertEqual(resolved["h2_leg0"]["interface"], "Ethernet25")
        self.assertEqual(resolved["h2_leg1"]["interface"], "Ethernet26")
        self.assertEqual(resolved["h1_leg1"]["interface"], "Ethernet27")
        for role in topology.REQUIRED_DUT_ROLES:
            self.assertEqual(
                resolved["{}_spine".format(role)]["interfaces"],
                ["Ethernet28", "Ethernet29", "Ethernet30"],
            )
            self.assertEqual(
                resolved["{}_remote_direct".format(role)]["interface"],
                "Ethernet31",
            )

    def test_case11_and_case13_have_distinct_fixture_resources(self):
        topology = self.modules["topology"]
        ports = topology.resolve_ptf_ports(self.tbinfo)
        segments = topology.ethernet_segments(topology.load_service_model())
        member_roles = {
            role for segment in segments.values()
            for role in segment["ptf_member_roles"]
        }
        self.assertNotIn("sh1", member_roles)
        self.assertEqual(len(member_roles), 4)
        self.assertEqual(len({ports[role] for role in member_roles}), 4)
        self.assertNotEqual(ports["h2_leg0"], ports["h2_leg1"])
        self.assertNotEqual(ports["h1_leg0"], ports["h1_leg1"])
        self.assertEqual(topology.ENDPOINT_ATTACHMENTS["sh1"], "mh_leaf0")

    def test_exact_peer_parser_handles_map_and_record_shapes(self):
        state = self.modules["state"]
        keyed = {"peers": {
            "10.1.0.32": {"bgpState": "Established"},
            "100.1.0.32": {"pfxRcd": 12},
        }}
        records = {"peers": [
            {"peerAddress": "10.1.0.33", "peerState": "Established"},
            {"peerAddress": "100.1.0.32", "peerState": "Established"},
        ]}
        self.assertEqual(
            state.established_peers(keyed), {"10.1.0.32", "100.1.0.32"}
        )
        self.assertEqual(
            state.established_peers(records), {"10.1.0.33", "100.1.0.32"}
        )

    def test_overlay_ready_requires_the_exact_peer_set(self):
        topology = self.modules["topology"].load_service_model()
        topology["vtep_ip"] = {
            "mh_leaf0": "10.1.0.32",
            "mh_leaf1": "10.1.0.33",
            "remote_leaf": "100.1.0.32",
        }
        duts = {
            "mh_leaf0": types.SimpleNamespace(hostname="upper"),
            "mh_leaf1": types.SimpleNamespace(hostname="lower"),
        }
        segments = self.modules["topology"].ethernet_segments(topology)

        def command_json(dut, command):
            role = "mh_leaf0" if dut is duts["mh_leaf0"] else "mh_leaf1"
            peer_role = "mh_leaf1" if role == "mh_leaf0" else "mh_leaf0"
            if command == "show bgp l2vpn evpn summary json":
                peers = {
                    topology["vtep_ip"][peer_role]: {
                        "state": "Established"
                    },
                    topology["vtep_ip"]["remote_leaf"]: {
                        "state": "Established"
                    },
                }
                return {"peers": peers}
            if command == "show evpn es json":
                return {"segments": [
                    {
                        "esi": definition["esi"],
                        "local": True,
                        "vteps": [topology["vtep_ip"][peer_role]],
                        "isDf": role == "mh_leaf0",
                    }
                    for definition in segments.values()
                ]}
            raise AssertionError("unexpected command {}".format(command))

        operations = self.modules["operations"]
        with mock.patch.object(operations, "command_json", command_json):
            self.assertTrue(operations.overlay_ready(duts, topology))

            def wrong_peer_command(dut, command):
                payload = command_json(dut, command)
                if (dut is duts["mh_leaf0"]
                        and command == "show bgp l2vpn evpn summary json"):
                    payload["peers"].pop(topology["vtep_ip"]["remote_leaf"])
                    payload["peers"]["192.0.2.99"] = {
                        "state": "Established"
                    }
                return payload

            with mock.patch.object(
                    operations, "command_json", wrong_peer_command):
                self.assertFalse(operations.overlay_ready(duts, topology))

    def test_portchannel_restore_reconciles_full_and_partial_removal(self):
        operations = self.modules["operations"]
        baseline = self._portchannel_baseline()
        absent = {component: None for component in baseline}
        dut = FakePortchannelDut(absent, baseline)
        operations.restore_portchannel_config(
            dut, "PortChannel100", "Ethernet25", 10, baseline
        )
        self.assertEqual(
            operations.portchannel_config_snapshot(
                dut, "PortChannel100", "Ethernet25", 10
            ),
            baseline,
        )

        partial = json.loads(json.dumps(baseline))
        partial["portchannel"].pop("system_mac")
        dut = FakePortchannelDut(partial, baseline)
        operations.restore_portchannel_config(
            dut, "PortChannel100", "Ethernet25", 10, baseline
        )
        mutations = [
            command for command in dut.commands
            if command != "sonic-cfggen -d --print-data"
        ]
        self.assertEqual(mutations, [
            "sudo config interface sys-mac add PortChannel100 "
            "00:44:33:22:11:00"
        ])

    def test_portchannel_restore_accepts_successful_failure_readback(self):
        operations = self.modules["operations"]
        baseline = self._portchannel_baseline()
        absent = {component: None for component in baseline}
        failed_command = "sudo config portchannel add PortChannel100"
        dut = FakePortchannelDut(
            absent, baseline, fail_after_mutation=failed_command
        )
        operations.restore_portchannel_config(
            dut, "PortChannel100", "Ethernet25", 10, baseline
        )
        self.assertEqual(
            operations.portchannel_config_snapshot(
                dut, "PortChannel100", "Ethernet25", 10
            ),
            baseline,
        )

    def test_portchannel_restore_refuses_divergent_existing_state(self):
        operations = self.modules["operations"]
        baseline = self._portchannel_baseline()
        divergent = json.loads(json.dumps(baseline))
        divergent["vlan_member"] = {"tagging_mode": "tagged"}
        dut = FakePortchannelDut(divergent, baseline)
        with self.assertRaisesRegex(AssertionError, "divergent VLAN"):
            operations.restore_portchannel_config(
                dut, "PortChannel100", "Ethernet25", 10, baseline
            )
        mutations = [
            command for command in dut.commands
            if command != "sonic-cfggen -d --print-data"
        ]
        self.assertEqual(mutations, [])


if __name__ == "__main__":
    unittest.main()

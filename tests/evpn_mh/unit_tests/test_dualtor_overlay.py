"""Unit contracts for scoped OVS/MUX mutation and rollback."""

import importlib.util
from pathlib import Path
import shlex
import sys
import types
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPO_ROOT / "tests" / "evpn_mh"


def _load_modules():
    package_name = "evpn_mh_dualtor_overlay_runtime"
    package = types.ModuleType(package_name)
    package.__path__ = [str(PACKAGE_ROOT)]
    sys.modules[package_name] = package
    loaded = {}
    for name in ("topology", "dualtor_overlay"):
        qualified = "{}.{}".format(package_name, name)
        spec = importlib.util.spec_from_file_location(
            qualified, PACKAGE_ROOT / "{}.py".format(name)
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[qualified] = module
        spec.loader.exec_module(module)
        loaded[name] = module
    return package_name, loaded


class FakeVmHost:
    def __init__(self, module, vm_set="vms17-8", pair=25):
        self.module = module
        self.bridge = module.mux_bridge_name(vm_set, pair)
        self.ptf = module.mux_ptf_port_name(vm_set, pair)
        # The upper port intentionally sorts after the lower port.  A fixture
        # that equates lexical order with ToR role would select the wrong leg.
        self.upper = "z-upper.3272"
        self.lower = "a-lower.3216"
        self.ofports = {self.ptf: 3, self.upper: 1, self.lower: 2}
        self.commands = []
        self.delete_calls = 0
        self.fail_restore_delete = False

    def shell(self, command, **_kwargs):
        self.commands.append(command)
        if command == "sudo ovs-vsctl list-ports {}".format(self.bridge):
            return {
                "rc": 0,
                "stdout": "{}\n{}\n{}\n".format(
                    self.upper, self.lower, self.ptf
                ),
            }
        if command == "sudo ovs-ofctl dump-flows {}".format(self.bridge):
            return {
                "rc": 0,
                "stdout": (
                    "NXST_FLOW reply (xid=0x4):\n"
                    " cookie=0x0, duration=9.2s, table=0, n_packets=12, "
                    "n_bytes=100, priority=0,in_port=3 actions=output:1,output:2\n"
                    " cookie=0x0, duration=9.2s, table=0, n_packets=4, "
                    "n_bytes=20, priority=0,in_port=1 actions=output:3\n"
                ),
            }
        prefix = "sudo ovs-vsctl get Interface "
        if command.startswith(prefix) and command.endswith(" ofport"):
            interface = command[len(prefix):-len(" ofport")]
            return {"rc": 0, "stdout": str(self.ofports[interface])}
        if command.startswith("sudo ovs-ofctl del-flows "):
            self.delete_calls += 1
            if self.fail_restore_delete and self.delete_calls > 1:
                return {"rc": 1, "stderr": "injected restore failure"}
            return {"rc": 0, "stdout": ""}
        if command.startswith("sudo ovs-ofctl add-flow "):
            return {"rc": 0, "stdout": ""}
        raise AssertionError("unexpected command {}".format(command))


class FakeT1VmHost:
    """Six independent stock T1 bridges with dynamic port identities."""

    def __init__(self, module, vm_set, eos_hostnames, tbinfo, graph):
        self.module = module
        self.commands = []
        self.bridges = {}
        self.ofports = {}
        self.flows = {}
        self.vxlan_adds = 0
        self.fail_vxlan_add_number = None
        vms = tbinfo["topo"]["properties"]["topology"]["VMs"]
        for role, eos_hostname in eos_hostnames.items():
            neighbor = module.NEIGHBOR_NAMES[role]
            for ordinal, link in enumerate(vms[neighbor]["vlans"]):
                dut_index, port_index, ptf_index = module._parse_vm_link(link)
                dut_name = tbinfo["duts"][dut_index]
                dut_vlan = graph["device_vlan_map_list"][dut_name][port_index]
                bridge = module.t1_bridge_name(eos_hostname, ordinal)
                ports = (
                    module.t1_vm_port_name(eos_hostname, ordinal),
                    module.t1_ptf_port_name(vm_set, ptf_index),
                    "{}-fp.{}".format(dut_name, dut_vlan),
                )
                self.bridges[bridge] = ports
                self.flows[bridge] = [
                    "cookie=0x0, duration=1s, table=0, n_packets=0, "
                    "n_bytes=0, priority=0,in_port=1 actions=output:3"
                ]
                for ofport, interface in enumerate(ports, start=1):
                    self.ofports[interface] = ofport

    def shell(self, command, **_kwargs):
        self.commands.append(command)
        list_prefix = "sudo ovs-vsctl list-ports "
        if command.startswith(list_prefix):
            bridge = command[len(list_prefix):]
            return {"rc": 0, "stdout": "\n".join(self.bridges[bridge]) + "\n"}
        dump_prefix = "sudo ovs-ofctl dump-flows "
        if command.startswith(dump_prefix):
            bridge = command[len(dump_prefix):]
            if bridge not in self.bridges:
                raise AssertionError("unknown bridge {}".format(bridge))
            rendered = [
                flow.replace(",actions=", " actions=")
                for flow in self.flows[bridge]
            ]
            return {"rc": 0, "stdout": "\n".join(rendered) + "\n"}
        ofport_prefix = "sudo ovs-vsctl get Interface "
        if command.startswith(ofport_prefix) and command.endswith(" ofport"):
            interface = command[len(ofport_prefix):-len(" ofport")]
            return {"rc": 0, "stdout": str(self.ofports[interface])}
        if command.startswith("sudo ovs-ofctl del-flows "):
            bridge = command.split()[-1]
            self.flows[bridge] = []
            return {"rc": 0, "stdout": ""}
        if command.startswith("sudo ovs-ofctl add-flow "):
            tokens = shlex.split(command)
            bridge, flow = tokens[-2:]
            if "tp_dst=4789" in flow:
                self.vxlan_adds += 1
                if self.vxlan_adds == self.fail_vxlan_add_number:
                    return {"rc": 1, "stderr": "injected VXLAN add failure"}
            self.flows[bridge].append(flow)
            return {"rc": 0, "stdout": ""}
        raise AssertionError("unexpected command {}".format(command))


class DualtorOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package_name, cls.modules = _load_modules()
        cls.overlay = cls.modules["dualtor_overlay"]

    @classmethod
    def tearDownClass(cls):
        prefix = cls.package_name + "."
        for name in tuple(sys.modules):
            if name == cls.package_name or name.startswith(prefix):
                sys.modules.pop(name, None)

    @staticmethod
    def _binding(pair=25):
        upper = types.SimpleNamespace(hostname="dut-upper")
        lower = types.SimpleNamespace(hostname="dut-lower")
        duts = {"mh_leaf0": upper, "mh_leaf1": lower}
        tbinfo = {
            "duts": [upper.hostname, lower.hostname],
            "duts_map": {upper.hostname: 0, lower.hostname: 1},
        }
        graph = {
            "device_vlan_map_list": {
                upper.hostname: {pair: 3272},
                lower.hostname: {str(pair): 3216},
            }
        }
        return duts, tbinfo, graph

    def test_adaptive_names_match_vm_topology_contract(self):
        self.assertEqual(
            self.overlay.mux_bridge_name("vms17-8", 25),
            "mbr-vms17-8-25",
        )
        self.assertEqual(
            self.overlay.mux_ptf_port_name("vms17-8", 25),
            "muxy-vms17-8-25",
        )
        self.assertLessEqual(
            len(self.overlay.mux_ptf_port_name("vms17-8", 25)), 15
        )

    def test_flow_normalization_drops_only_volatile_state(self):
        first = (
            " cookie=0x0, duration=10s, table=0, n_packets=3, n_bytes=90, "
            "priority=100,in_port=3 actions=output:1"
        )
        second = first.replace("duration=10s", "duration=99s").replace(
            "n_packets=3", "n_packets=300"
        ).replace("n_bytes=90", "n_bytes=9000")
        expected = ("cookie=0x0,table=0,priority=100,in_port=3,actions=output:1",)
        self.assertEqual(self.overlay.normalize_ovs_flow_dump(first), expected)
        self.assertEqual(self.overlay.normalize_ovs_flow_dump(second), expected)

    def test_rollback_is_lifo_and_attempts_all_actions(self):
        calls = []
        stack = self.overlay.RollbackStack()

        def record(value):
            calls.append(value)

        def fail(value):
            calls.append(value)
            raise RuntimeError("expected failure")

        stack.defer("first", record, "first")
        stack.defer("second", fail, "second")
        stack.defer("third", record, "third")
        with self.assertRaises(self.overlay.RollbackError):
            stack.rollback()
        self.assertEqual(calls, ["third", "second", "first"])
        self.assertEqual(stack.pending_labels, ())

    def test_pin_registers_restore_before_flow_deletion(self):
        host = FakeVmHost(self.overlay)
        stack = self.overlay.RollbackStack()
        duts, tbinfo, graph = self._binding()
        self.assertEqual(sorted((host.upper, host.lower))[0], host.lower)
        result = self.overlay.pin_bridge(
            host, "vms17-8", 25, "upper", stack,
            duts, tbinfo, graph,
        )
        self.assertEqual(result["selected_tor_port"], host.upper)
        self.assertEqual(result["blocked_tor_port"], host.lower)
        self.assertEqual(len(stack.pending_labels), 1)
        delete_index = host.commands.index(
            "sudo ovs-ofctl del-flows {}".format(host.bridge)
        )
        self.assertGreater(delete_index, 0)
        added = [command for command in host.commands if " add-flow " in command]
        self.assertEqual(len(added), 2)
        self.assertTrue(any("in_port=3,actions=output:1" in item for item in added))
        self.assertFalse(any("output:2" in item for item in added))
        stack.rollback()
        # Two original flows were replayed after the exact bridge snapshot.
        replayed = [command for command in host.commands[delete_index + 1:]
                    if " add-flow " in command]
        self.assertGreaterEqual(len(replayed), 4)

    def test_active_active_pair_one_is_feature_owned_and_pinned_upper(self):
        host = FakeVmHost(self.overlay, pair=1)
        stack = self.overlay.RollbackStack()
        duts, tbinfo, graph = self._binding(pair=1)
        result = self.overlay.pin_bridge(
            host, "vms17-8", 1, self.overlay.PAIR_SIDES[1], stack,
            duts, tbinfo, graph,
        )
        self.assertEqual(result["pair_index"], 1)
        self.assertEqual(result["side"], "upper")
        self.assertEqual(result["selected_tor_port"], host.upper)
        self.assertEqual(len(stack.pending_labels), 1)
        self.assertTrue(any(" del-flows " in item for item in host.commands))
        stack.rollback()

    def test_missing_inventory_binding_fails_closed_before_mutation(self):
        host = FakeVmHost(self.overlay)
        stack = self.overlay.RollbackStack()
        duts, tbinfo, _graph = self._binding()
        with self.assertRaisesRegex(
                self.overlay.OverlayCommandError,
                "connection graph has no per-port VLAN map"):
            self.overlay.pin_bridge(
                host, "vms17-8", 25, "upper", stack,
                duts, tbinfo, {"device_vlan_map_list": {}},
            )
        self.assertFalse(any(" del-flows " in item for item in host.commands))
        self.assertEqual(stack.pending_labels, ())

    def test_partial_mutation_reports_all_rollback_failures(self):
        host = FakeVmHost(self.overlay)
        stack = self.overlay.RollbackStack()
        duts, tbinfo, graph = self._binding()
        cleanup_calls = []

        def fail_service_restore():
            cleanup_calls.append("service")
            raise RuntimeError("injected service failure")

        # This mirrors prepare_mux_overlay: service rollback is registered
        # first, then one bridge is mutated before later setup fails.
        stack.defer("restore MUX simulator service", fail_service_restore)
        self.overlay.pin_bridge(
            host, "vms17-8", 25, "upper", stack,
            duts, tbinfo, graph,
        )
        host.fail_restore_delete = True
        with self.assertRaises(self.overlay.RollbackError) as context:
            stack.rollback()
        message = str(context.exception)
        self.assertIn("restore OVS flows", message)
        self.assertIn("restore MUX simulator service", message)
        self.assertEqual(cleanup_calls, ["service"])
        self.assertEqual(stack.pending_labels, ())

    def test_unowned_pair_is_rejected_before_any_command(self):
        host = FakeVmHost(self.overlay)
        stack = self.overlay.RollbackStack()
        duts, tbinfo, graph = self._binding(pair=24)
        with self.assertRaises(ValueError):
            self.overlay.pin_bridge(
                host, "vms17-8", 24, "upper", stack,
                duts, tbinfo, graph,
            )
        self.assertEqual(host.commands, [])

    def test_mux_service_state_query_fails_closed(self):
        class ServiceHost:
            def shell(self, command, **_kwargs):
                self.command = command
                return {"rc": 1, "stdout": "", "stderr": "transport error"}

        host = ServiceHost()
        with self.assertRaisesRegex(
                self.overlay.OverlayCommandError,
                "cannot prove MUX simulator service state"):
            self.overlay.mux_service_active(host, 8080)
        self.assertIn("systemctl is-active", host.command)

    def test_vxlan_path_rules_cover_only_a01_to_a03_and_restore(self):
        vm_set = "vms17-8"
        upper = types.SimpleNamespace(hostname="dut-upper")
        lower = types.SimpleNamespace(hostname="dut-lower")
        duts = {"mh_leaf0": upper, "mh_leaf1": lower}
        tbinfo = {
            "duts": [upper.hostname, lower.hostname],
            "duts_map": {upper.hostname: 0, lower.hostname: 1},
            "topo": {"properties": {"topology": {"VMs": {}}}},
        }
        graph = {"device_vlan_map_list": {
            upper.hostname: {}, lower.hostname: {},
        }}
        neighbors = {}
        eos_hostnames = {}
        ptf_index = 28
        for offset, role in enumerate((
                "underlay0", "underlay1", "underlay2", "remote_leaf")):
            name = self.overlay.NEIGHBOR_NAMES[role]
            hostname = "VM{:04d}".format(100 + offset)
            neighbors[role] = types.SimpleNamespace(hostname=hostname)
            eos_hostnames[role] = hostname
            port_index = 28 + offset
            tbinfo["topo"]["properties"]["topology"]["VMs"][name] = {
                "vlans": [
                    "0.{}@{}".format(port_index, ptf_index),
                    "1.{}@{}".format(port_index, ptf_index + 1),
                ]
            }
            graph["device_vlan_map_list"][upper.hostname][port_index] = 3200 + offset
            graph["device_vlan_map_list"][lower.hostname][port_index] = 3300 + offset
            ptf_index += 2

        host = FakeT1VmHost(
            self.overlay, vm_set, eos_hostnames, tbinfo, graph
        )
        stack = self.overlay.RollbackStack()
        mapping = self.overlay.prepare_vxlan_path_bridges(
            host, vm_set, tbinfo, duts, neighbors, graph, stack
        )
        self.assertEqual(len(mapping), 6)
        self.assertEqual(
            {details["role"] for details in mapping.values()},
            {"underlay0", "underlay1", "underlay2"},
        )
        vxlan_flows = [
            command for command in host.commands
            if " add-flow " in command and "tp_dst=4789" in command
        ]
        self.assertEqual(len(vxlan_flows), 12)
        self.assertEqual(len(stack.pending_labels), 6)
        stack.rollback()
        self.overlay.assert_mux_overlay_restored(host, mapping)

    def test_partial_vxlan_setup_is_exactly_verified_after_rollback(self):
        vm_set = "vms17-8"
        upper = types.SimpleNamespace(hostname="dut-upper")
        lower = types.SimpleNamespace(hostname="dut-lower")
        duts = {"mh_leaf0": upper, "mh_leaf1": lower}
        tbinfo = {
            "duts": [upper.hostname, lower.hostname],
            "duts_map": {upper.hostname: 0, lower.hostname: 1},
            "topo": {"properties": {"topology": {"VMs": {}}}},
        }
        graph = {"device_vlan_map_list": {
            upper.hostname: {}, lower.hostname: {},
        }}
        neighbors = {}
        eos_hostnames = {}
        ptf_index = 28
        for offset, role in enumerate((
                "underlay0", "underlay1", "underlay2", "remote_leaf")):
            name = self.overlay.NEIGHBOR_NAMES[role]
            hostname = "VM{:04d}".format(200 + offset)
            neighbors[role] = types.SimpleNamespace(hostname=hostname)
            eos_hostnames[role] = hostname
            port_index = 28 + offset
            tbinfo["topo"]["properties"]["topology"]["VMs"][name] = {
                "vlans": [
                    "0.{}@{}".format(port_index, ptf_index),
                    "1.{}@{}".format(port_index, ptf_index + 1),
                ]
            }
            graph["device_vlan_map_list"][upper.hostname][port_index] = 3400 + offset
            graph["device_vlan_map_list"][lower.hostname][port_index] = 3500 + offset
            ptf_index += 2

        host = FakeT1VmHost(
            self.overlay, vm_set, eos_hostnames, tbinfo, graph)
        mapping = self.overlay.resolve_vxlan_path_bridges(
            host, vm_set, tbinfo, duts, neighbors, graph)
        self.assertEqual(len(mapping), 6)
        host.fail_vxlan_add_number = 3
        stack = self.overlay.RollbackStack()
        with self.assertRaisesRegex(
                self.overlay.OverlayCommandError,
                "injected VXLAN add failure"):
            self.overlay.prepare_vxlan_path_bridges(
                host, vm_set, tbinfo, duts, neighbors, graph, stack,
                mapping=mapping)
        stack.rollback()
        self.overlay.assert_mux_overlay_restored(host, mapping)


if __name__ == "__main__":
    unittest.main()

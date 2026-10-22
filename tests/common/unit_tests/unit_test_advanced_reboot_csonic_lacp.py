import ast
import shlex
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).parents[2]
    / "ptftests"
    / "py3"
    / "advanced-reboot.py"
)


class FakeNeighbor:
    def __init__(self, bonds="PortChannel1-bond\nPortChannel2-bond\n", mismatch=False):
        self.bonds = bonds
        self.mismatch = mismatch
        self.calls = []
        self.disconnected = False

    def connect(self):
        self.calls.append("connect")

    def disconnect(self):
        self.disconnected = True
        self.calls.append("disconnect")

    def do_cmd(self, command):
        self.calls.append(command)
        if "find Port lacp=active" in command:
            return self.bonds
        if " get Port " in " {} ".format(command):
            return '3\n' if self.mismatch else '180\n'
        return ""


def load_method(neighbor):
    tree = ast.parse(SCRIPT.read_text())
    reload_test = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ReloadTest"
    )
    method = next(
        node for node in reload_test.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "csonic_set_lacp_all_neighs"
    )

    class HostDevice:
        @staticmethod
        def getHostDeviceInstance(*args, **kwargs):
            return neighbor

    namespace = {"HostDevice": HostDevice, "shlex": shlex}
    test_class = ast.ClassDef(
        name="Harness",
        bases=[],
        keywords=[],
        body=[method],
        decorator_list=[],
    )
    ast.fix_missing_locations(test_class)
    exec(compile(ast.Module(body=[test_class], type_ignores=[]), str(SCRIPT), "exec"), namespace)
    harness = namespace["Harness"]()
    harness.ssh_targets = ["10.0.0.1"]
    harness.test_params = {"neighbor_type": "sonic"}
    harness.logs = []
    harness.log = harness.logs.append
    return harness


def test_sets_and_verifies_every_active_ovs_bond():
    neighbor = FakeNeighbor()
    harness = load_method(neighbor)
    harness.csonic_set_lacp_all_neighs(180)

    sets = [call for call in neighbor.calls if " set Port " in " {} ".format(call)]
    gets = [call for call in neighbor.calls if " get Port " in " {} ".format(call)]
    assert sets == [
        "sudo ovs-vsctl set Port PortChannel1-bond other_config:lacp-rx-multiplier=180",
        "sudo ovs-vsctl set Port PortChannel2-bond other_config:lacp-rx-multiplier=180",
    ]
    assert len(gets) == 2
    assert neighbor.disconnected
    assert harness.logs == [
        "cSONiC LACP receive multiplier update started: requested=180",
        "cSONiC LACP receive multiplier verified: neighbor=10.0.0.1 "
        "bond=PortChannel1-bond requested=180 actual=180",
        "cSONiC LACP receive multiplier verified: neighbor=10.0.0.1 "
        "bond=PortChannel2-bond requested=180 actual=180",
        "cSONiC LACP receive multiplier update completed: requested=180",
    ]


def test_fails_when_no_active_ovs_bonds_exist():
    neighbor = FakeNeighbor(bonds="")
    with pytest.raises(RuntimeError, match="No active userspace OVS LACP bonds"):
        load_method(neighbor).csonic_set_lacp_all_neighs(180)
    assert neighbor.disconnected


def test_fails_when_readback_does_not_match():
    neighbor = FakeNeighbor(mismatch=True)
    with pytest.raises(RuntimeError, match="Failed to set LACP receive multiplier"):
        load_method(neighbor).csonic_set_lacp_all_neighs(180)
    assert neighbor.disconnected

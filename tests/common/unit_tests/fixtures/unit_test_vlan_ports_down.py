"""Exercise VLAN port restoration with real pytest fixture teardown."""

import ast
from pathlib import Path

import pytest

pytest_plugins = ["pytester"]


@pytest.mark.parametrize("failure", ["shutdown", "startup"])
def test_vlan_ports_restored_after_failure(pytester, failure):
    """Attempt independent restores after a shutdown or startup error."""
    source_path = Path(__file__).resolve().parents[3] / "vlan" / "test_vlan_ports_down.py"
    fixture = next(node for node in ast.parse(source_path.read_text(encoding="utf-8")).body
                   if isinstance(node, ast.FunctionDef) and node.name == "vlan_ports_setup")
    pytester.makeconftest(
        "from functools import partial\n"
        "from unittest.mock import Mock\n"
        "import pytest\n"
        "logger = Mock()\n"
        "time = Mock()\n"
        f"failure = {failure!r}\n"
        + ast.unparse(fixture) + """

@pytest.fixture(scope="module")
def rand_one_dut_hostname():
    return "dut"

@pytest.fixture(scope="module")
def duthosts():
    ports = {"Ethernet0": "up", "Ethernet4": "up", "Ethernet8": "up", "Ethernet12": "down"}
    dut = Mock()
    dut.get_vlan_brief.return_value = {"Vlan1000": {"members": list(ports)}}
    dut.get_interfaces_status.return_value = {
        port: {"admin": status} for port, status in ports.items()
    }
    def shell(command):
        with open("commands.txt", "a") as commands:
            commands.write(command + "\\n")
        if command.endswith(failure + " Ethernet4"):
            raise RuntimeError("injected " + failure + " failure")
    dut.shell.side_effect = shell
    return {"dut": dut}
""")
    pytester.makepyfile(
        "def test_ports(vlan_ports_setup):\n"
        "    assert vlan_ports_setup == 'Vlan1000'\n"
    )
    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=int(failure == "startup"), errors=1)
    assert f"injected {failure} failure" in result.stdout.str()
    commands = (pytester.path / "commands.txt").read_text().splitlines()
    restored = {command.split()[-1] for command in commands if " startup " in command}
    expected = {"Ethernet0", "Ethernet4", "Ethernet8"} if failure == "startup" else {"Ethernet0", "Ethernet4"}
    assert restored == expected
    assert all("Ethernet12" not in command for command in commands)

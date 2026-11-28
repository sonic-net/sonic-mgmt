"""Fail-closed activation tests for converged cSONiC T1-LAG."""

import ast
import importlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest
import yaml


pytestmark = [pytest.mark.topology("any")]

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFTEST_PATH = REPO_ROOT / "tests" / "conftest.py"
TESTBED_CLI_PATH = REPO_ROOT / "ansible" / "testbed-cli.sh"
ADD_TOPO_PLAYBOOK_PATH = REPO_ROOT / "ansible" / "testbed_add_vm_topology.yml"
MISSING = object()


def _load_pytest_convergence_helpers():
    """Load only the convergence helpers without importing pytest conftest."""
    source = CONFTEST_PATH.read_text()
    tree = ast.parse(source, filename=str(CONFTEST_PATH))
    helper_names = {
        "_load_testbed_config",
        "_normalize_use_converged_peers",
        "converge_topo_if_needed",
    }
    helper_nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in helper_names
    ]
    assert {node.name for node in helper_nodes} == helper_names

    module = ModuleType("sonic_mgmt_pytest_convergence_helpers")
    helper_logger = SimpleNamespace(
        error=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
    )
    module.__dict__.update({
        "__file__": str(CONFTEST_PATH),
        "importlib": importlib,
        "logger": helper_logger,
        "os": os,
        "pytest": pytest,
        "shutil": shutil,
        "yaml": yaml,
    })
    helpers = ast.Module(body=helper_nodes, type_ignores=[])
    exec(compile(helpers, str(CONFTEST_PATH), "exec"), module.__dict__)
    return module


PYTEST_CONVERGENCE_HELPERS = _load_pytest_convergence_helpers()
normalize_pytest_flag = (
    PYTEST_CONVERGENCE_HELPERS._normalize_use_converged_peers
)
converge_pytest_topo_if_needed = (
    PYTEST_CONVERGENCE_HELPERS.converge_topo_if_needed
)


class _PytestConfig:
    def __init__(self, testbed_file, neighbor_type, override=True):
        self._options = {
            "testbed": "unit-testbed",
            "testbed_file": str(testbed_file),
            "--neighbor_type": neighbor_type,
        }
        args = (("--neighbor_type={}".format(neighbor_type),)
                if override else ())
        self.invocation_params = SimpleNamespace(args=args)
        self.cache_values = {}
        self.cache = SimpleNamespace(set=self.cache_values.__setitem__)

    def getoption(self, name):
        return self._options[name]


def _write_testbed(tmp_path, topo, use_converged_peers, vm_type=None):
    testbed = {
        "conf-name": "unit-testbed",
        "topo": topo,
        "use_converged_peers": use_converged_peers,
    }
    if vm_type is not None:
        testbed["vm_type"] = vm_type
    testbed_file = tmp_path / "testbed.yml"
    testbed_file.write_text(yaml.safe_dump([testbed]))
    return testbed_file


def _prepare_fake_convergers(tmp_path, monkeypatch, topo):
    repo_root = tmp_path / "repo"
    tests_dir = repo_root / "tests"
    ansible_dir = repo_root / "ansible"
    vars_dir = ansible_dir / "vars"
    tests_dir.mkdir(parents=True)
    vars_dir.mkdir(parents=True)
    fake_conftest = tests_dir / "conftest.py"
    fake_conftest.write_text("")
    topo_file = vars_dir / "topo_{}.yml".format(topo)
    topo_file.write_text("stock-topology\n")

    for module_name, marker in (
            ("csonic_topo_converger", "csonic"),
            ("ceos_topo_converger", "ceos")):
        (ansible_dir / "{}.py".format(module_name)).write_text(
            "from pathlib import Path\n\n"
            "def converge_testbed(input_file, output_file):\n"
            "    Path(output_file).write_text({!r})\n".format(marker)
        )

    monkeypatch.setattr(
        PYTEST_CONVERGENCE_HELPERS, "__file__", str(fake_conftest))
    monkeypatch.setattr(
        PYTEST_CONVERGENCE_HELPERS.os, "chown",
        lambda *args, **kwargs: None)
    return topo_file


def _shell_function(name):
    lines = TESTBED_CLI_PATH.read_text().splitlines()
    start = lines.index("function {}".format(name))
    end = next(
        index for index in range(start + 1, len(lines))
        if lines[index] == "}"
    )
    return "\n".join(lines[start:end + 1])


def _write_cli_testbed(tmp_path, file_format, use_converged_peers=False):
    if file_format == "csv":
        testbed_file = tmp_path / "testbed.csv"
        testbed_file.write_text(
            "unit-testbed,vms6-2,t1-lag,docker-ptf,ptf-02,"
            "10.250.0.106/24,fec0::ffff:afa:6/64,server_1,"
            "VM0104,vlab-03,veos_vtb\n"
        )
        return testbed_file

    testbed = {
        "conf-name": "unit-testbed",
        "group-name": "vms6-2",
        "topo": "t1-lag",
        "ptf_image_name": "docker-ptf",
        "ptf": "ptf-02",
        "ptf_ip": "10.250.0.106/24",
        "ptf_ipv6": "fec0::ffff:afa:6/64",
        "server": "server_1",
        "vm_base": "VM0104",
        "dut": ["vlab-03"],
        "inv_name": "veos_vtb",
    }
    if use_converged_peers is not MISSING:
        testbed["use_converged_peers"] = use_converged_peers
    testbed_file = tmp_path / "testbed.yaml"
    testbed_file.write_text(yaml.safe_dump([testbed]))
    return testbed_file


def _run_cli(tmp_path, action, file_format="yaml",
             use_converged_peers=False, vm_type="csonic",
             testbed_file=None):
    if testbed_file is None:
        testbed_file = _write_cli_testbed(
            tmp_path, file_format, use_converged_peers)
    command_log = tmp_path / "commands.log"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    python_wrapper = fake_bin / "python"
    python_wrapper.write_text(
        "#!/bin/bash\n"
        "if [[ \"$1\" == -m && \"$2\" == *_topo_converger ]]; then\n"
        "    printf 'python %s\\n' \"$*\" >> \"$CLI_COMMAND_LOG\"\n"
        "    exit 0\n"
        "fi\n"
        "exec {!r} \"$@\"\n".format(sys.executable))
    python_wrapper.chmod(0o755)
    for command in ("ansible-playbook", "sleep"):
        executable = fake_bin / command
        executable.write_text(
            "#!/bin/bash\n"
            "printf '%s %s\\n' \"${0##*/}\" \"$*\" >> \"$CLI_COMMAND_LOG\"\n"
        )
        executable.chmod(0o755)

    env = os.environ.copy()
    env["CLI_COMMAND_LOG"] = str(command_log)
    env["PATH"] = "{}:{}".format(fake_bin, env["PATH"])
    result = subprocess.run(
        [
            "bash", str(TESTBED_CLI_PATH),
            "-t", str(testbed_file),
            "-k", vm_type,
            action, "unit-testbed", "vault-password", "sentinel",
        ],
        cwd=str(REPO_ROOT / "ansible"),
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )
    log = command_log.read_text() if command_log.exists() else ""
    return result, log


def test_direct_add_playbook_has_target_only_fail_closed_guard():
    plays = yaml.safe_load(ADD_TOPO_PLAYBOOK_PATH.read_text())
    task = next(
        task for task in plays[0]["pre_tasks"]
        if task.get("name") == "Require converged peers for cSONiC T1-LAG"
    )

    assert task["when"] == [
        "vm_type | default('ceos') == 'csonic'",
        "topo == 't1-lag'",
        "not (use_converged_peers | default(false) | bool)",
    ]
    assert "unconverged cSONiC T1-LAG is not supported" in task["fail"]["msg"]


@pytest.mark.parametrize("flag", [False, "False", "false"])
def test_pytest_rejects_false_equivalents_for_csonic_t1_lag(
        tmp_path, flag):
    config = _PytestConfig(
        _write_testbed(tmp_path, "t1-lag", flag), "csonic")

    with pytest.raises(pytest.UsageError, match=(
            "unconverged cSONiC T1-LAG is not supported")):
        converge_pytest_topo_if_needed(config)


@pytest.mark.parametrize("flag", [True, "True", "true"])
def test_pytest_accepts_true_equivalents_and_dispatches_csonic(
        tmp_path, monkeypatch, flag):
    topo_file = _prepare_fake_convergers(tmp_path, monkeypatch, "t1-lag")
    config = _PytestConfig(
        _write_testbed(tmp_path, "t1-lag", flag), "csonic")

    converge_pytest_topo_if_needed(config)

    assert topo_file.read_text() == "csonic"


@pytest.mark.parametrize("flag", [None, "", "yes", 0, 1, [], {}])
def test_pytest_rejects_invalid_convergence_flags(flag):
    with pytest.raises(pytest.UsageError, match="use_converged_peers must"):
        normalize_pytest_flag(flag)


@pytest.mark.parametrize(("topo", "neighbor_type", "marker"), [
    ("t1-lag", "ceos", "ceos"),
    ("t0", "csonic", "csonic"),
])
def test_pytest_positive_dispatch_controls(
        tmp_path, monkeypatch, topo, neighbor_type, marker):
    topo_file = _prepare_fake_convergers(tmp_path, monkeypatch, topo)
    config = _PytestConfig(
        _write_testbed(tmp_path, topo, True), neighbor_type)

    converge_pytest_topo_if_needed(config)

    assert topo_file.read_text() == marker


@pytest.mark.parametrize(("topo", "neighbor_type", "marker"), [
    ("t1-lag", "ceos", "ceos"),
    ("t0", "csonic", "csonic"),
])
def test_pytest_non_target_quoted_false_keeps_historical_truthiness(
        tmp_path, monkeypatch, topo, neighbor_type, marker):
    topo_file = _prepare_fake_convergers(tmp_path, monkeypatch, topo)
    config = _PytestConfig(
        _write_testbed(tmp_path, topo, "False"), neighbor_type)

    converge_pytest_topo_if_needed(config)

    assert topo_file.read_text() == marker


def test_pytest_infers_csonic_from_testbed_when_not_overridden(
        tmp_path, monkeypatch):
    topo_file = _prepare_fake_convergers(tmp_path, monkeypatch, "t1-lag")
    config = _PytestConfig(
        _write_testbed(tmp_path, "t1-lag", True, vm_type="csonic"),
        "eos",
        override=False,
    )

    converge_pytest_topo_if_needed(config)

    assert topo_file.read_text() == "csonic"


@pytest.mark.parametrize("file_format", ["yaml", "csv"])
@pytest.mark.parametrize("action", ["add-topo", "announce-routes"])
def test_cli_rejects_unconverged_add_or_use_before_any_playbook(
        tmp_path, file_format, action):
    result, command_log = _run_cli(tmp_path, action, file_format)

    assert result.returncode != 0
    assert "unconverged cSONiC T1-LAG is not supported" in result.stderr
    assert command_log == ""


def test_cli_rejects_redeploy_before_teardown_or_sleep(tmp_path):
    result, command_log = _run_cli(tmp_path, "redeploy-topo")

    assert result.returncode != 0
    assert "unconverged cSONiC T1-LAG is not supported" in result.stderr
    assert command_log == ""


def test_cli_propagates_yaml_parse_failure_before_any_playbook(tmp_path):
    testbed_file = tmp_path / "broken.yaml"
    testbed_file.write_text("- conf-name: unit-testbed\n  dut: [unterminated\n")

    result, command_log = _run_cli(
        tmp_path, "remove-topo", testbed_file=testbed_file)

    assert result.returncode != 0
    assert "ParserError" in result.stderr
    assert command_log == ""


@pytest.mark.parametrize("flag", [True, "True", "true"])
def test_cli_cleanup_normalizes_true_and_uses_converged_topology(
        tmp_path, flag):
    result, command_log = _run_cli(
        tmp_path, "remove-topo", use_converged_peers=flag)

    assert result.returncode == 0, result.stderr
    assert "python -m csonic_topo_converger" in command_log
    assert "testbed_remove_vm_topology.yml" in command_log


@pytest.mark.parametrize("flag", [False, "False", "false", MISSING])
def test_cli_cleanup_allows_false_or_missing_without_convergence(
        tmp_path, flag):
    result, command_log = _run_cli(
        tmp_path, "remove-topo", use_converged_peers=flag)

    assert result.returncode == 0, result.stderr
    assert "topo_converger" not in command_log
    assert "testbed_remove_vm_topology.yml" in command_log


def test_cli_redeploy_validation_does_not_add_an_extra_convergence(tmp_path):
    result, command_log = _run_cli(
        tmp_path, "redeploy-topo", use_converged_peers="true")

    assert result.returncode == 0, result.stderr
    assert command_log.count("python -m csonic_topo_converger") == 2
    assert command_log.count("testbed_remove_vm_topology.yml") == 1
    assert command_log.count("testbed_add_vm_topology.yml") == 1


def test_cli_refresh_dut_forwards_converged_flag_to_direct_playbook(tmp_path):
    result, command_log = _run_cli(
        tmp_path, "refresh-dut", use_converged_peers="true")

    assert result.returncode == 0, result.stderr
    refresh_call = next(
        line for line in command_log.splitlines()
        if "testbed_add_vm_topology.yml" in line
    )
    assert "use_converged_peers=True" in refresh_call


@pytest.mark.parametrize(
    ("vm_type", "topo", "flag", "normalized"),
    [
        ("csonic", "t1-lag", "True", "True"),
        ("csonic", "t1-lag", "true", "True"),
        ("ceos", "t1-lag", "False", ""),
        ("csonic", "t0", "False", ""),
    ],
)
def test_cli_action_validation_positive_controls(
        vm_type, topo, flag, normalized):
    script = """{function}
vm_type={vm_type}
normalized_use_converged_peers=
validate_csonic_t1_lag_mode add-topo {topo} {flag}
printf '%s\\n' "$normalized_use_converged_peers"
""".format(
        function=_shell_function("validate_csonic_t1_lag_mode"),
        vm_type=vm_type,
        topo=topo,
        flag=flag,
    )

    result = subprocess.run(
        ["bash", "-c", script],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == normalized


@pytest.mark.parametrize(("action", "expected_playbook"), [
    ("remove-topo", "testbed_remove_vm_topology.yml"),
    ("disconnect-vms", "testbed_disconnect_vms.yml"),
    ("stop-topo-vms", None),
])
def test_cli_allows_cleanup_only_actions(
        tmp_path, action, expected_playbook):
    result, command_log = _run_cli(tmp_path, action)

    assert result.returncode == 0, result.stderr
    if expected_playbook:
        assert expected_playbook in command_log


@pytest.mark.parametrize(("vm_type", "module_name"), [
    ("csonic", "csonic_topo_converger"),
    ("ceos", "ceos_topo_converger"),
])
def test_cli_positive_converger_dispatch(
        tmp_path, vm_type, module_name):
    vars_dir = tmp_path / "vars"
    vars_dir.mkdir()
    (vars_dir / "topo_t1-lag.yml").write_text("stock-topology\n")
    call_log = tmp_path / "python-call.log"
    script = """{function}
python() {{
    printf '%s\\n' "$*" > "$CALL_LOG"
}}
vm_type={vm_type}
converge_topo_if_needed t1-lag True
""".format(
        function=_shell_function("converge_topo_if_needed"),
        vm_type=vm_type,
    )

    result = subprocess.run(
        ["bash", "-c", script],
        cwd=str(tmp_path),
        env=dict(os.environ, CALL_LOG=str(call_log)),
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert call_log.read_text().split()[0:2] == ["-m", module_name]

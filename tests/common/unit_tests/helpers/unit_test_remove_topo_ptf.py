"""Exercise remove-topo with real Ansible includes and mocked host operations."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


pytest.importorskip("ansible")
TASKS = Path(__file__).resolve().parents[4] / "ansible/roles/vm_set/tasks"
ACTION_PLUGIN = """
import json
import os

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        action = self._task.action.rsplit('.', 1)[-1]
        with open(os.environ['REMOVE_TOPO_TRACE'], 'a') as trace:
            trace.write(json.dumps({'action': action, 'args': self._task.args}) + '\\n')
        if action == 'command':
            return json.loads(os.environ['PTF_PROBE_RESULT'])
        if action == 'ptf_portchannel' and os.environ['PTF_STOP_FAIL'] == '1':
            return {'failed': True, 'msg': 'simulated PTF module failure'}
        return {'changed': False}
"""


@pytest.fixture
def remove_topo(tmp_path):
    """Run the production removal tasks without contacting Docker or a testbed."""
    for name in ("remove_topo.yml", "ptf_portchannel.yml"):
        (tmp_path / name).write_text((TASKS / name).read_text())
    for name in (
        "control_mux_simulator.yml", "control_nic_simulator.yml",
        "get_dut_port.yml", "remove_ceos_list.yml", "remove_csonic_list.yml",
        "remove_dut_port.yml",
    ):
        (tmp_path / name).write_text("[]\n")
    plugins = tmp_path / "action_plugins"
    plugins.mkdir()
    for name in ("command", "ptf_portchannel", "docker_container", "vm_topology"):
        (plugins / (name + ".py")).write_text(ACTION_PLUGIN)
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled = False\n")

    def run(python_major="3", probe_rc=0, stop_fails=False, **variables):
        trace = tmp_path / "trace.jsonl"
        playbook = tmp_path / "playbook.yml"
        playbook.write_text(yaml.safe_dump([{
            "hosts": "localhost",
            "gather_facts": False,
            "vars": {
                "topo": "t0",
                "topology": {"DUT": {"portchannel_config": {}}},
                "vm_set_name": "test-vms",
                "ptf_ip": "192.0.2.1/24",
                "duts_name": "test-dut",
                "duts_fp_ports": {},
                "duts_midplane_ports": {},
                "duts_inband_ports": {},
                "duts_mgmt_port": [],
                "VM_hosts": [],
                "VM_targets": [],
                "VM_base": "VM0000",
                "vm_type": "veos",
                "max_fp_num": 1,
                "topo_is_multi_vrf": False,
                "enable_async": False,
                "remove_keysight_api_server": "1",
                **variables,
            },
            "tasks": [{"include_tasks": str(tmp_path / "remove_topo.yml")}],
        }]))
        env = {
            **os.environ,
            "ANSIBLE_CONFIG": str(config),
            "ANSIBLE_ACTION_PLUGINS": str(plugins),
            "ANSIBLE_NOCOLOR": "1",
            "REMOVE_TOPO_TRACE": str(trace),
            "PTF_PROBE_RESULT": json.dumps({
                "changed": False, "rc": probe_rc,
                "stdout": python_major, "failed": probe_rc != 0,
            }),
            "PTF_STOP_FAIL": "1" if stop_fails else "0",
        }
        result = subprocess.run(
            [sys.executable, "-m", "ansible.cli.playbook", "-i", "localhost,", str(playbook)],
            cwd=tmp_path, env=env, text=True, capture_output=True, timeout=60,
        )
        events = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        return result, events

    return run


@pytest.mark.parametrize("mode", ["teamd", "bond"])
@pytest.mark.parametrize("config", [{}, {"PortChannel101": {"intfs": [0, 1]}}])
@pytest.mark.parametrize("python_major", ["2", "3"])
def test_remove_topo_reaches_container_removal(remove_topo, python_major, config, mode):
    """Skip incompatible legacy cleanup, but retain modern teamd/bond cleanup."""
    result, events = remove_topo(
        python_major=python_major,
        stop_fails=python_major == "2",
        topology={"DUT": {"portchannel_config": config, "portchannel_mode": mode}},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    probe = next(event for event in events if event["action"] == "command")
    assert probe["args"]["argv"] == [
        "docker", "exec", "ptf_test-vms", "/usr/bin/python", "-c",
        "import sys; print(sys.version_info[0])",
    ]
    cleanup = [event for event in events if event["action"] == "ptf_portchannel"]
    assert len(cleanup) == (0 if python_major == "2" else 1)
    if cleanup:
        assert cleanup[0]["args"] == {"cmd": "stop", "portchannel_config": config, "mode": mode}
    unbind = next(i for i, event in enumerate(events)
                  if event["action"] == "vm_topology" and event["args"]["cmd"] == "unbind")
    removed = next(i for i, event in enumerate(events)
                   if event["action"] == "docker_container" and event["args"]["state"] == "absent")
    assert unbind < removed
    assert events[removed]["args"]["name"] == "ptf_test-vms"


@pytest.mark.parametrize("python_major,probe_rc", [("3", 0), ("", 1), ("2", 1), ("unknown", 0)])
def test_unconfirmed_legacy_or_modern_cleanup_failure_is_not_ignored(remove_topo, python_major, probe_rc):
    """Only a successful Python-2 probe may bypass a failing cleanup module."""
    result, events = remove_topo(python_major=python_major, probe_rc=probe_rc, stop_fails=True)

    assert result.returncode != 0
    assert "simulated PTF module failure" in result.stdout
    assert any(event["action"] == "ptf_portchannel" for event in events)
    assert not any(event["action"] in ("vm_topology", "docker_container") for event in events)


@pytest.mark.parametrize("variables", [
    {"topo": "t0-bmc"},
    {"ptf_imagename": "docker-keysight-api-server"},
    {"ptf_imagename": "docker-ptf-anvl"},
])
def test_bmc_and_vendor_teardown_do_not_probe_or_stop_ptf_portchannels(remove_topo, variables):
    """Preserve existing BMC and vendor-specific removal paths."""
    result, events = remove_topo(stop_fails=True, **variables)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not any(event["action"] in ("command", "ptf_portchannel") for event in events)
    assert any(event["action"] == "docker_container" and event["args"]["state"] == "absent"
               for event in events)

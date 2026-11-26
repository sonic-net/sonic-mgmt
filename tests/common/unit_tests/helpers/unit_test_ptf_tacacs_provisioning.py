"""Check daily TACACS task selection without requiring a testbed."""

from pathlib import Path

from jinja2 import Environment, StrictUndefined
import pytest
import yaml


TASKS_DIR = Path(__file__).resolve().parents[4] / "ansible" / "roles" / "vm_set" / "tasks"
ENV = Environment(undefined=StrictUndefined)


@pytest.fixture(params=["add_topo.yml", "renumber_topo.yml"])
def ptf_block(request):
    tasks = yaml.safe_load((TASKS_DIR / request.param).read_text(encoding="utf-8"))
    return next(task for task in tasks if any(
        child.get("include_tasks") == "start_tacacs_daily_daemon.yml"
        for child in task.get("block", [])
    ))


@pytest.fixture(params=[True, False, None], ids=["docker-network", "linux-bridge", "unset"])
def variables(request):
    values = {"container_type": "PTF", "topo": "bmc"}
    if request.param is not None:
        values["ptf_use_docker_network"] = request.param
    return values


def _enabled(task, variables):
    conditions = task.get("when", [])
    if not isinstance(conditions, list):
        conditions = [conditions]
    return all(ENV.compile_expression(condition)(**variables) for condition in conditions)


@pytest.mark.parametrize("container_type", ["PTF", "API-SERVER", "IxANVL-CONF-TESTER"])
def test_daily_tacacs_runs_for_ptf_in_all_network_modes(ptf_block, variables, container_type):
    """Provision daily TACACS in both topology paths, but only inside the PTF block."""
    variables["container_type"] = container_type
    task = next(task for task in ptf_block["block"]
                if task.get("include_tasks") == "start_tacacs_daily_daemon.yml")

    enabled = _enabled(ptf_block, variables) and _enabled(task, variables)

    assert enabled == (container_type == "PTF")


def test_docker_network_still_skips_mac_changes(ptf_block, variables):
    """Keep interface manipulation disabled when Docker owns the management network."""
    task = next(task for task in ptf_block["block"]
                if task.get("include_tasks") == "ptf_change_mac.yml")

    assert _enabled(task, variables) == (not variables.get("ptf_use_docker_network", False))


def test_daily_tacacs_delegates_to_ptf_management_address():
    """Provision configuration and scripts over the PTF IP, independent of interface names."""
    tasks = yaml.safe_load((TASKS_DIR / "start_tacacs_daily_daemon.yml").read_text(encoding="utf-8"))
    variables = {"ptf_ip": "192.0.2.10/24"}
    host_task = next(task for task in tasks if task.get("name") == "Set ptf host")
    variables.update({
        key: ENV.from_string(value).render(variables)
        for key, value in host_task["set_fact"].items()
    })
    assert variables["ptf_host"] == "192.0.2.10"
    add_host = next(task["add_host"] for task in tasks if "add_host" in task)
    assert ENV.from_string(add_host["name"]).render(variables) == "192.0.2.10"
    assert "ptf" in add_host["groups"]

    provisioning = next(task["block"] for task in tasks if any(
        child.get("name") == "Start tacacs daily daemon" for child in task.get("block", [])
    ))
    assert len(provisioning) == 4
    for task in provisioning:
        assert ENV.from_string(task["delegate_to"]).render(variables) == "192.0.2.10"

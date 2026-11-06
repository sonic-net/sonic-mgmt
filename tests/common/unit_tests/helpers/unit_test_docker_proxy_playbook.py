"""Regression tests for Docker proxy deployment transitions."""

from pathlib import Path

import yaml


PLAYBOOK_PATH = (
    Path(__file__).resolve().parents[4]
    / "ansible"
    / "config_sonic_basedon_testbed.yml"
)
PLAYBOOK = yaml.safe_load(PLAYBOOK_PATH.read_text(encoding="utf-8"))
TASKS = PLAYBOOK[0]["tasks"]


def _task(name, tasks=TASKS):
    return next(task for task in tasks if task.get("name") == name)


def test_ipv6_proxy_to_default_no_proxy_removes_docker_drop_in():
    """Remove a proxy left by an earlier IPv6-only deployment."""
    cleanup = _task("Remove docker proxy when no proxy is configured")

    assert cleanup["when"] == [
        "proxy_env is not defined",
        "deploy is defined and deploy|bool == true",
    ]

    remove = _task("Remove docker proxy config", cleanup["block"])
    assert remove["file"] == {
        "path": "/etc/systemd/system/docker.service.d/http-proxy.conf",
        "state": "absent",
    }
    assert remove["register"] == "docker_proxy_removed"

    restart = _task("Restart docker service after removing proxy", cleanup["block"])
    assert restart["systemd"] == {
        "state": "restarted",
        "daemon_reload": True,
        "name": "docker",
    }
    assert restart["when"] == "docker_proxy_removed.changed"

    wait = _task("Wait 60s for docker containers to restart", cleanup["block"])
    assert wait["when"] == "docker_proxy_removed.changed"

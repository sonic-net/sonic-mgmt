"""Regression tests for IPv6 management variable loading."""

from pathlib import Path

import yaml


PLAYBOOK_PATH = (
    Path(__file__).resolve().parents[4]
    / "ansible"
    / "config_sonic_basedon_testbed.yml"
)
PLAYBOOK = yaml.safe_load(PLAYBOOK_PATH.read_text(encoding="utf-8"))
TASKS = PLAYBOOK[0]["tasks"]


def _find_task(tasks, name):
    for task in tasks:
        if task.get("name") == name:
            return task
        for section in ("block", "rescue", "always"):
            if section in task:
                found = _find_task(task[section], name)
                if found:
                    return found
    return None


LOAD_IPV6_CONFIG = _find_task(TASKS, "Load IPv6 management configuration")


def test_explicit_group_bypasses_legacy_group_count_guard():
    """Allow explicit selection for hosts that belong to only one group."""
    assert LOAD_IPV6_CONFIG["when"][2] == (
        "ipv6_mgmt_config_group is defined or (group_names | length > 1)"
    )


def test_undefined_group_uses_existing_group_names_fallback():
    """Keep the existing group_names fallback when no selector is defined."""
    assert LOAD_IPV6_CONFIG["include_vars"] == (
        "group_vars/{{ ipv6_mgmt_config_group | default(group_names[1]) }}/ipv6.yml"
    )

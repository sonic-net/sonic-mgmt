"""Regression tests for IPv6 management variable loading."""

from pathlib import Path

from jinja2.nativetypes import NativeEnvironment
import pytest
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
    assert LOAD_IPV6_CONFIG["when"][-1] == (
        "ipv6_mgmt_config_group is defined or (group_names | length > 1)"
    )


def test_undefined_group_uses_existing_group_names_fallback():
    """Keep the existing group_names fallback when no selector is defined."""
    assert LOAD_IPV6_CONFIG["include_vars"] == (
        "group_vars/{{ ipv6_mgmt_config_group | default(group_names[1]) }}/ipv6.yml"
    )


@pytest.mark.parametrize("ipv6_only,has_ipv6,routes,ipv6_routes,expected", [
    (None, True, ["192.0.2.0/24"], ["2001:db8::/64"], ["192.0.2.0/24", "2001:db8::/64"]),
    (False, True, ["2001:db8::/64"], ["2001:db8::/64"], ["2001:db8::/64"]),
    (False, False, ["192.0.2.0/24"], ["2001:db8::/64"], ["192.0.2.0/24"]),
    (False, True, ["192.0.2.0/24"], None, ["192.0.2.0/24"]),
    (False, True, None, ["2001:db8::/64"], ["2001:db8::/64"]),
    (True, True, ["192.0.2.0/24"], ["2001:db8::/64"], ["2001:db8::/64"]),
])
def test_forced_management_routes(ipv6_only, has_ipv6, routes, ipv6_routes, expected):
    """Merge routes only for dual-stack management; retain IPv6-only replacement."""
    env = NativeEnvironment()
    env.filters["bool"] = bool
    variables = {"group_names": ["sonic", "str2"]}
    if ipv6_only is not None:
        variables["use_ipv6_mgmt"] = ipv6_only
    if has_ipv6:
        variables["ansible_hostv6"] = "2001:db8::10"
    if routes is not None:
        variables["forced_mgmt_routes"] = routes
    if ipv6_routes is not None:
        variables["forced_mgmt_routes_ipv6"] = ipv6_routes

    load_enabled = all(env.compile_expression(condition)(**variables) for condition in LOAD_IPV6_CONFIG["when"])
    assert load_enabled == (has_ipv6 or bool(ipv6_only))

    for name in ("Include IPv6 forced management routes for dual-stack management",
                 "Override management service configurations for IPv6-only mode"):
        task = _find_task(TASKS, name)
        if all(env.compile_expression(condition)(**variables) for condition in task["when"]):
            expression = task["set_fact"]["forced_mgmt_routes"]
            variables["forced_mgmt_routes"] = env.from_string(expression).render(variables)

    assert variables["forced_mgmt_routes"] == expected

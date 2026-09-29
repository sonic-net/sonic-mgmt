import pytest

from ansible import context
from ansible.module_utils.common.collections import ImmutableDict
from ansible.utils.vars import load_extra_vars

from devutil.devices.ansible_hosts import AnsibleHost, AnsibleHosts


@pytest.fixture(autouse=True)
def isolated_extra_vars(monkeypatch):
    monkeypatch.setattr(context, "CLIARGS", ImmutableDict())
    monkeypatch.setattr(load_extra_vars, "extra_vars", {}, raising=False)


@pytest.mark.parametrize("constructor_override", [False, True])
@pytest.mark.parametrize("cli_override", [False, True])
def test_independent_hosts_do_not_share_extra_vars(monkeypatch, constructor_override, cli_override):
    cli_args = ("synthetic_cli_marker=from-cli",) if cli_override else ()
    monkeypatch.setattr(context, "CLIARGS", ImmutableDict(extra_vars=cli_args))
    overrides = {"ansible_ssh_user": "synthetic-fanout-user"}
    first = AnsibleHost([], "localhost", hostvars=overrides if constructor_override else {})
    if not constructor_override:
        first.vm.extra_vars.update(overrides)

    second = AnsibleHost([], "localhost")

    assert first.vm.extra_vars["ansible_ssh_user"] == "synthetic-fanout-user"
    assert second.vm.extra_vars == ({"synthetic_cli_marker": "from-cli"} if cli_override else {})
    assert first.vm.extra_vars is not second.vm.extra_vars


def test_explicitly_shared_variable_manager_is_preserved():
    hosts = AnsibleHosts([], "localhost", hostvars={"synthetic_marker": "initial"})
    child = hosts[0]

    assert child.vm is hosts.vm
    hosts.vm.extra_vars["synthetic_marker"] = "updated"
    assert child.vm.extra_vars["synthetic_marker"] == "updated"

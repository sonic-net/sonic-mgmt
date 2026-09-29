from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar

from tests.common.helpers import dut_utils


@pytest.fixture(params=[True, False], ids=["cached-hostvars", "get-vars"])
def credential_context(tmp_path, monkeypatch, request):
    helpers = tmp_path / "tests" / "common" / "helpers"
    helpers.mkdir(parents=True)
    monkeypatch.setattr(dut_utils, "BASI_PATH", str(helpers))
    variables = tmp_path / "ansible" / "group_vars"
    (variables / "all").mkdir(parents=True)
    (variables / "fanout").mkdir()
    (variables / "all" / "creds.yml").write_text(yaml.safe_dump({
        "sonicadmin_user": "{{ dut_user }}",
        "sonicadmin_password": "{{ dut_password }}",
        "docker_registry_host": "{{ registry_host }}",
        "fanout_network_user": "default-network-user",
    }))
    (variables / "all" / "empty.yml").write_text("")
    (variables / "all" / "topo_excluded.yml").write_text("invalid: [")
    hostvars = {
        "dut_user": "synthetic-dut-user",
        "dut_password": "synthetic-dut-password",
        "registry_host": "registry.example.invalid",
        "ansible_altpassword": "synthetic-alternate-password",
        "inventory_user": "synthetic-network-user",
        "inventory_password": "synthetic-network-password",
        "console_login_options": {"synthetic-console": {"port": 7000}},
        "console_login": {
            "synthetic-console": {"user": "console-user", "passwd": "console-password"},
        },
    }
    inventory_host = Mock()
    inventory_host.get_vars.return_value = {"group_names": []}
    inventory = Mock()
    inventory.get_host.return_value = inventory_host
    variable_manager = SimpleNamespace(
        _hostvars={"synthetic-dut": hostvars} if request.param else None,
        get_vars=Mock(return_value=hostvars),
    )
    dut = SimpleNamespace(
        hostname="synthetic-dut",
        mgmt_ip="192.0.2.1",
        mgmt_ipv6=None,
        host=SimpleNamespace(options={
            "inventory_manager": inventory,
            "variable_manager": variable_manager,
        }),
    )
    password_probe = Mock(return_value="synthetic-current-password")
    monkeypatch.setattr(dut_utils, "get_dut_current_passwd", password_probe)
    return SimpleNamespace(
        dut=dut,
        hostvars=hostvars,
        fanout_file=variables / "fanout" / "creds.yml",
        password_probe=password_probe,
    )


@pytest.mark.parametrize("templated", [True, False], ids=["templates", "literals"])
def test_creds_preserve_fanout_template_provenance(credential_context, templated):
    user_fields = ("fanout_network_user", "fanout_admin_user", "fanout_tacacs_eos_user", "eos_login")
    password_fields = ("fanout_network_password", "fanout_admin_password", "fanout_tacacs_eos_password", "eos_password")
    expected = {key: "synthetic-network-user" for key in user_fields}
    expected.update({key: "synthetic-network-password" for key in password_fields})
    if templated:
        values = {key: "{{ inventory_user }}" for key in user_fields}
        values.update({key: "{{ inventory_password }}" for key in password_fields})
    else:
        values = expected
    credential_context.fanout_file.write_text(yaml.safe_dump(values))

    creds = dut_utils.creds_on_dut(credential_context.dut)
    templar = Templar(loader=DataLoader(), variables=credential_context.hostvars)

    for key, value in expected.items():
        assert templar.template(creds[key]) == value
    if templated:
        other_hostvars = dict(
            credential_context.hostvars,
            inventory_user="other-network-user",
            inventory_password="other-network-password",
        )
        other_templar = Templar(loader=DataLoader(), variables=other_hostvars)
        for key in user_fields:
            assert other_templar.template(creds[key]) == "other-network-user"
        for key in password_fields:
            assert other_templar.template(creds[key]) == "other-network-password"
    assert creds["sonicadmin_user"] == "synthetic-dut-user"
    assert creds["sonicadmin_password"] == "synthetic-current-password"
    assert creds["docker_registry_host"] == "registry.example.invalid"
    assert creds["ansible_altpasswords"] == ["synthetic-alternate-password"]
    credential_context.password_probe.assert_called_once_with(
        "192.0.2.1",
        None,
        "synthetic-dut-user",
        ["synthetic-alternate-password", "synthetic-dut-password"],
    )


def test_creds_preserve_console_and_empty_file_behavior(credential_context):
    creds = dut_utils.creds_on_dut(credential_context.dut)

    assert creds["fanout_network_user"] == "default-network-user"
    assert creds["console_login_options"] == {"synthetic-console": {"port": 7000}}
    assert creds["console_user"] == {"synthetic-console": "console-user"}
    assert creds["console_password"] == {"synthetic-console": "console-password"}


def test_creds_support_legacy_loader_signature(credential_context, monkeypatch):
    class LegacyLoader:
        def load_from_file(self, file_name):
            with open(file_name) as stream:
                return yaml.safe_load(stream)

    monkeypatch.setattr(dut_utils, "DataLoader", LegacyLoader)

    creds = dut_utils.creds_on_dut(credential_context.dut)

    assert creds["sonicadmin_user"] == "synthetic-dut-user"
    assert creds["sonicadmin_password"] == "synthetic-current-password"
    assert creds["fanout_network_user"] == "default-network-user"

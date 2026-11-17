"""Regression tests for inventory alternate-password selection."""

import ast
import glob
import logging
import os
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import Mock

import jinja2
from jinja2.nativetypes import NativeEnvironment
import pytest
import yaml


SOURCE_PATH = Path(__file__).resolve().parents[2] / "helpers" / "dut_utils.py"
TREE = ast.parse(SOURCE_PATH.read_text(encoding="utf-8"))
FUNCTION = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name == "creds_on_dut"
)


@pytest.mark.parametrize(
    "alternates,expected",
    [
        (None, ["legacy"]),
        ([], ["legacy"]),
        (["rotated", "older"], ["rotated", "older"]),
        ("{{ secret_group_vars.str.altpasswords }}", ["rotated", "older"]),
    ],
)
def test_creds_on_dut_preserves_inventory_alternates(tmp_path, monkeypatch, alternates, expected):
    variables = {
        "ansible_altpassword": "legacy",
        "secret_group_vars": {"str": {"altpasswords": ["rotated", "older"]}},
    }
    if alternates is not None:
        variables["ansible_altpasswords"] = alternates
    credentials = tmp_path / "creds.yml"
    credentials.write_text("sonicadmin_user: test-user\nsonicadmin_password: primary\n", encoding="utf-8")
    monkeypatch.setattr(
        glob, "glob",
        lambda pattern: [str(credentials)] if pattern.endswith("group_vars/all/*.yml") else [],
    )
    current_password = Mock(return_value="selected")
    namespace = {
        "BASI_PATH": str(tmp_path),
        "NativeEnvironment": NativeEnvironment,
        "get_dut_current_passwd": current_password,
        "glob": glob,
        "jinja2": jinja2,
        "logger": logging.getLogger(__name__),
        "logging": logging,
        "os": os,
        "re": re,
        "yaml": yaml,
    }
    exec(compile(ast.Module(body=[FUNCTION], type_ignores=[]), str(SOURCE_PATH), "exec"), namespace)
    inventory = SimpleNamespace(
        get_host=lambda name: SimpleNamespace(get_vars=lambda: {"group_names": ["sonic"]}),
    )
    variables_manager = SimpleNamespace(_hostvars={"dut": variables})
    dut = SimpleNamespace(
        hostname="dut",
        mgmt_ip="192.0.2.1",
        mgmt_ipv6=None,
        host=SimpleNamespace(options={"inventory_manager": inventory, "variable_manager": variables_manager}),
    )

    creds = namespace["creds_on_dut"](dut)

    current_password.assert_called_once_with("192.0.2.1", None, "test-user", expected + ["primary"])
    assert creds["sonicadmin_password"] == "selected"
    assert creds["ansible_altpasswords"] == expected
    if isinstance(alternates, list):
        assert variables["ansible_altpasswords"] == alternates
        assert creds["ansible_altpasswords"] is not alternates

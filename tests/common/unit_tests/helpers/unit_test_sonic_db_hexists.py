# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for redis_hexists in tests/common/helpers/sonic_db.py.

Run (from the repository root):
    python3 -m pytest --noconftest tests/common/unit_tests/helpers/unit_test_sonic_db_hexists.py -v
"""
import ast
import shlex
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "helpers/sonic_db.py"


class SonicAsic:
    """Stands in for tests.common.devices.sonic_asic.SonicAsic."""


@pytest.fixture(scope="module")
def redis_hexists():
    """Load redis_hexists and the runner it uses, without sonic_db.py's device imports."""
    names = {"_run_sonic_db_cli", "redis_hexists"}
    tree = ast.parse(MODULE_PATH.read_text())
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {"shlex": shlex, "SonicAsic": SonicAsic, "DEFAULT_NAMESPACE": None}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["redis_hexists"]


class Host:
    def __init__(self, stdout, rc=0, stderr=""):
        self.result = {"stdout": stdout, "rc": rc, "stderr": stderr}
        self.commands = []

    def shell(self, command, **kwargs):
        self.commands.append(command)
        return self.result


@pytest.mark.parametrize("stdout, expected", [("True\n", True), ("False\n", False)], ids=["True", "False"])
def test_reads_sonic_db_cli_output(redis_hexists, stdout, expected):
    host = Host(stdout)
    assert redis_hexists(host, "CONFIG_DB", "REDFISH|config", "port") is expected
    assert host.commands == ["sonic-db-cli CONFIG_DB HEXISTS 'REDFISH|config' port"]


@pytest.mark.parametrize("stdout", ["1", "0", "true", "false", "", "WRONGTYPE Operation against a key"])
def test_rejects_other_output(redis_hexists, stdout):
    """Output in redis-cli's 1/0 form, or anything else, is an error rather than False."""
    with pytest.raises(RuntimeError, match="HEXISTS"):
        redis_hexists(Host(stdout), "CONFIG_DB", "REDFISH|config", "port")


def test_rejects_failed_command(redis_hexists):
    with pytest.raises(RuntimeError, match="rc=1"):
        redis_hexists(Host("False", rc=1, stderr="Could not connect"), "CONFIG_DB", "REDFISH|config", "port")


def test_runs_in_the_asic_namespace(redis_hexists):
    asic = type("Asic", (SonicAsic, Host), {"sonic_db_cli": "sonic-db-cli -n asic1"})("True")
    assert redis_hexists(asic, "APPL_DB", "PORT_TABLE:Ethernet0", "admin_status") is True
    assert asic.commands == ["sonic-db-cli -n asic1 APPL_DB HEXISTS PORT_TABLE:Ethernet0 admin_status"]

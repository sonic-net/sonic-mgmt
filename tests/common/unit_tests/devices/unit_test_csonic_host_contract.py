"""Focused cSONiC host-contract regressions without testbed dependencies."""

import ast
from pathlib import Path
from types import SimpleNamespace


MODULE_PATH = Path(__file__).resolve().parents[2] / "devices/csonic.py"
TREE = ast.parse(MODULE_PATH.read_text())
CSONIC_HOST = next(
    node for node in TREE.body
    if isinstance(node, ast.ClassDef) and node.name == "CsonicHost"
)
INIT = next(
    node for node in CSONIC_HOST.body
    if isinstance(node, ast.FunctionDef) and node.name == "__init__"
)
NAMESPACE = {}
exec(compile(ast.Module(body=[INIT], type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)


def test_csonic_host_declares_single_asic_for_shared_namespace_helpers():
    host = SimpleNamespace()

    NAMESPACE["__init__"](host, "csonic_test_VM0100")

    assert host.is_multi_asic is False

"""Focused tests for sanity-recovery listener matching."""

import ast
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "plugins/sanity_check/recover.py"
TREE = ast.parse(MODULE_PATH.read_text())
NODE = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name == "_all_pids_listening"
)
NAMESPACE = {}
exec(compile(ast.Module(body=[NODE], type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)
_all_pids_listening = NAMESPACE["_all_pids_listening"]


def test_pid_match_requires_complete_ss_token():
    lines = [
        'LISTEN users:(("python",pid=12345,fd=7))',
        'LISTEN users:(("python",pid=777,fd=8))',
    ]

    assert _all_pids_listening(lines, [12345, 777])
    assert not _all_pids_listening(lines, [1234, 777])

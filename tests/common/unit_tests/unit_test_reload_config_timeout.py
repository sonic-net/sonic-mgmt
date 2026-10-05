"""Validate the platform reload outer-timeout policy without testbed imports."""

import ast
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2].joinpath(
    "platform_tests",
    "test_reload_config.py",
)
NAMES = {
    "DEFAULT_CONFIG_RELOAD_TIMEOUT",
    "NOKIA_7215_CONFIG_RELOAD_TIMEOUT",
    "NOKIA_7215_HWSKUS",
}


class TestReloadConfigTimeoutPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        nodes = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                targets = {
                    target.id
                    for target in node.targets
                    if isinstance(target, ast.Name)
                }
                if targets & NAMES:
                    nodes.append(node)
            elif isinstance(node, ast.FunctionDef) and (
                node.name == "get_config_reload_timeout"
            ):
                nodes.append(node)

        namespace = {}
        exec(
            compile(
                ast.Module(body=nodes, type_ignores=[]),
                str(MODULE_PATH),
                "exec",
            ),
            namespace,
        )
        cls.get_timeout = staticmethod(
            namespace["get_config_reload_timeout"]
        )

    def test_nokia_7215_m0_uses_300_seconds(self):
        self.assertEqual(self.get_timeout("Nokia-M0-7215"), 300)

    def test_nokia_7215_mx_uses_300_seconds(self):
        self.assertEqual(self.get_timeout("Nokia-7215"), 300)

    def test_unrelated_platform_keeps_120_seconds(self):
        self.assertEqual(self.get_timeout("Other-HwSku"), 120)


if __name__ == "__main__":
    unittest.main()

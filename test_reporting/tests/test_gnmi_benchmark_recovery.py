"""Offline recovery decisions and report retention; never connects to a DUT."""

from contextlib import contextmanager
import ast
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2] / "tests" / "gnmi_benchmark"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recovery = load("benchmark_recovery", "recovery.py")


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.host = Mock(hostname="dut")
        self.host.get_running_config_facts.return_value = {"VNET": {}}
        self.asic = Mock(namespace="")
        self.host.asics = [self.asic]

    def buffers(self, *sizes):
        self.asic.run_redis_cli_cmd.side_effect = [
            {"rc": 0, "stdout_lines": [f"id=1 db=4 flags=PU psub=1 cmd=psubscribe omem={size}"]}
            for size in sizes]

    def guard(self, service=None):
        return recovery.ConsumerRecovery(self.host, self.directory.name, "case", service, 0)

    def receipt(self):
        return json.loads((Path(self.directory.name) / "case-cleanup.json").read_text())

    def test_preexisting_backlog_fails_without_mutation(self):
        self.buffers(recovery.OMEM_LIMIT_BYTES + 1)
        with self.assertRaisesRegex(RuntimeError, "Pre-existing"):
            self.guard("verified-consumer").prepare()
        self.host.command.assert_not_called()
        self.assertEqual(self.receipt()["status"], "precheck_failed")

    def test_threshold_is_inclusive(self):
        self.buffers(recovery.OMEM_LIMIT_BYTES, recovery.OMEM_LIMIT_BYTES)
        guard = self.guard()
        guard.prepare()
        guard.finish()
        self.host.command.assert_not_called()
        self.assertEqual(self.receipt()["status"], "drained")

    def test_default_never_restarts_and_retains_diagnostics(self):
        self.buffers(0, 2500000000, 2500000000)
        guard = self.guard()
        guard.prepare()
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            guard.finish()
        self.host.command.assert_not_called()
        receipt = self.receipt()
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["samples"][-1]["instances"][0]["clients"][0]["id"], "1")

    def test_opt_in_restarts_only_named_consumer_after_config_check(self):
        self.buffers(0, 2500000000, 0)
        guard = self.guard("verified-consumer.service")
        guard.prepare()
        guard.finish()
        self.assertEqual([c.args[0] for c in self.host.command.call_args_list], [
            "systemctl is-active verified-consumer.service",
            "sudo systemctl restart verified-consumer.service",
            "systemctl is-active verified-consumer.service"])
        self.assertEqual(self.receipt()["status"], "recovered_with_restart")

    def test_config_mismatch_blocks_restart(self):
        self.buffers(0)
        guard = self.guard("verified-consumer")
        guard.prepare()
        self.host.get_running_config_facts.return_value = {"VNET": {"leftover": {}}}
        with self.assertRaisesRegex(RuntimeError, "configuration"):
            guard.finish()
        self.assertFalse(self.receipt()["restart_attempted"])

    def test_restart_failure_propagates(self):
        self.buffers(0, 2500000000)
        guard = self.guard("verified-consumer")
        guard.prepare()
        self.host.command.side_effect = RuntimeError("restart failed")
        with self.assertRaisesRegex(RuntimeError, "restart failed"):
            guard.finish()
        self.assertEqual(self.receipt()["status"], "failed")
        self.assertTrue(self.receipt()["restart_attempted"])

    def test_rejects_broad_or_invalid_service(self):
        for service in ("database", "redis.service", "gnmi", "*", "consumer;reboot", "-x"):
            with self.subTest(service=service), self.assertRaises(ValueError):
                self.guard(service)

    def test_bad_client_list_is_not_treated_as_drained(self):
        self.asic.run_redis_cli_cmd.return_value = {"rc": 1, "stdout_lines": []}
        with self.assertRaises(RuntimeError):
            self.guard().prepare()


class RunnerTest(unittest.TestCase):
    def test_measured_data_survives_resource_cleanup_failure(self):
        helpers = types.ModuleType("tests.gnmi_benchmark.helpers")
        events = []

        @contextmanager
        def connection(_):
            yield None, None

        @contextmanager
        def resources(*_):
            yield []
            events.append("cleanup")
            raise RuntimeError("delete failed")

        helpers.gnmi_connection = connection
        helpers.collect_resource_snapshot = lambda _: []
        with patch.dict(sys.modules, {"grpc": types.ModuleType("grpc"),
                                      "tests.gnmi_benchmark.helpers": helpers}):
            runner = load("benchmark_runner_under_test", "benchmark_runner.py")
        result = Mock()
        result.generate.side_effect = lambda **_: events.append("report_generated")
        blaster = Mock(warmup_seconds=0, rate=0, marker="case")
        blaster.name = "route-table"
        blaster.resources = resources
        blaster.profile.return_value = {}
        blaster.blast.return_value = {"measured": True}
        with self.assertRaises(runner.BenchmarkCleanupError):
            runner.BenchmarkRunner().run(None, None, blaster, result)
        self.assertEqual(events, ["report_generated", "cleanup"])
        self.assertEqual(result.generate.call_args.kwargs["samples"], {"measured": True})


class FixtureOrderTest(unittest.TestCase):
    def test_recovery_runs_after_dynamic_tls_rollback(self):
        # Execute the real fixture definition in an isolated pytest session, without DUT plugins.
        tree = ast.parse((ROOT / "benchmark.py").read_text())
        fixture = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                       and n.name == "benchmark_consumer_recovery")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source = '''import pytest
from types import SimpleNamespace
events = []
BENCHMARK_CONFIG = {"output_dir": ".", "recovery": {}}
class ConsumerRecovery:
    def __init__(self, *args, **kwargs): pass
    def prepare(self): events.append("precheck")
    def finish(self):
        assert events == ["precheck", "tls_setup", "measurement", "rollback"]
        events.append("recovery")
@pytest.fixture
def gnmi_tls():
    events.append("tls_setup")
    yield
    events.append("rollback")
'''
            source += ast.unparse(fixture) + '''
def test_run(request):
    request.node._benchmark_recovery_context = (None, SimpleNamespace(cid="case"))
    request.getfixturevalue("benchmark_consumer_recovery")
    request.getfixturevalue("gnmi_tls")
    events.append("measurement")
def test_final_state():
    assert events == ["precheck", "tls_setup", "measurement", "rollback", "recovery"]
'''
            (path / "test_order.py").write_text(source)
            (path / "pytest.ini").write_text("[pytest]\n")
            result = subprocess.run([sys.executable, "-m", "pytest", "--noconftest", "-q",
                                     "-c", str(path / "pytest.ini"), str(path / "test_order.py")],
                                    cwd=path, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

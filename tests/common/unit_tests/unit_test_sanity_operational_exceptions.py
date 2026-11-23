"""Dependency-free source controls; execute ONLY after the named source gate.

python3 -m unittest discover -s tests/common/unit_tests \
    -p unit_test_sanity_operational_exceptions.py -v

AST loading executes the actual functions without importing root conftest,
Ansible, pytest, testbed fixtures, or any device/network dependencies.
"""

import ast
import copy
import datetime
import json
import logging
import math
import pickle
import unittest
from collections import defaultdict
from collections.abc import Mapping
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


COMMON = Path(__file__).resolve().parents[1]
PARALLEL = COMMON / "helpers" / "parallel.py"
SANITY = COMMON / "plugins" / "sanity_check" / "__init__.py"
RECOVER = SANITY.with_name("recover.py")


class Failed(BaseException):
    """Model pytest.fail's explicit outcome, not all pytest outcomes."""


class Skipped(BaseException):
    pass


class RunAnsibleModuleFail(Exception):
    pass


class AnsibleConnectionFailure(Exception):
    pass


class PytestAnsibleConnectionFailure(Exception):
    pass


def fail(message):
    raise Failed(message)


fail.Exception = Failed


def check_assert(condition, message):
    if not condition:
        fail(message)


def load(path, names, namespace):
    tree = ast.parse(path.read_text())
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            if isinstance(node, ast.FunctionDef) and node.name == "sanity_check_full":
                node.decorator_list = []
            nodes.append(node)
    found = {node.name for node in nodes}
    if found != set(names):
        raise AssertionError((names, found))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)


class Hosts(list):
    def __getitem__(self, key):
        if isinstance(key, str):
            return next(host for host in self if host.hostname == key)
        return super().__getitem__(key)


class SanityControls(unittest.TestCase):
    def setUp(self):
        self.messages = []
        self.cache = {}
        self.ns = {
            "__name__": __name__, "ContextVar": ContextVar, "contextmanager": contextmanager,
            "_sanity_worker_check": ContextVar("test_sanity_worker_check", default=None),
            "RunAnsibleModuleFail": RunAnsibleModuleFail,
            "AnsibleConnectionFailure": AnsibleConnectionFailure,
            "PytestAnsibleConnectionFailure": PytestAnsibleConnectionFailure,
            "logger": Mock(), "pytest": SimpleNamespace(fail=fail),
            "copy": copy, "json": json, "defaultdict": defaultdict, "Mapping": Mapping,
            "DUT_CHECK_NAMESPACE": "dut", "STAGE_PRE_TEST": "pre", "STAGE_POST_TEST": "post",
            "pt_assert": check_assert,
            "add_custom_msg": lambda request, key, value: self.messages.append((key, value)),
            "SUPPORTED_CHECKS": ["check_processes", "check_dbmemory", "check_neighbor_macsec_empty"],
            "constants": SimpleNamespace(INFRA_CHECK_ITEMS=[], PRE_SANITY_CHECK_FAILED_RC=10,
                                         POST_SANITY_CHECK_FAILED_RC=11, SANITY_CHECK_FAILED_RC=12),
            "print_logs": Mock(), "filter_check_items": lambda tb, hosts, items: items,
            "recover": Mock(), "recover_chassis": Mock(),
        }
        load(PARALLEL, ["SanityWorkerError", "sanity_worker_context", "_sanity_worker_failure"], self.ns)
        # Enable round-trip pickling of the actual AST-loaded carrier class.
        globals()["SanityWorkerError"] = self.ns["SanityWorkerError"]
        load(SANITY, ["fallback_serializer", "_update_check_items", "_validate_check_result",
                      "do_checks", "_run_sanity_checks",
                      "sanity_check_full", "recover_on_sanity_check_failure", "pytest_sessionfinish"], self.ns)
        self.host = SimpleNamespace(hostname="dut1", get_facts=Mock(return_value={"modular_chassis": False}))
        self.hosts = Hosts([self.host])
        self.fixtures = {}
        options = SimpleNamespace(
            skip_pre_sanity=False, enable_pre_sanity=True, allow_recover=False, recover_method=None,
            post_check=False, skip_post_check=False, enable_macsec=False,
        )
        self.request = SimpleNamespace(
            node=SimpleNamespace(iter_markers=lambda: []), fixturenames=[],
            config=SimpleNamespace(option=options, getoption=lambda key: None,
                                   cache=SimpleNamespace(set=self.cache.__setitem__)),
            getfixturevalue=Mock(side_effect=lambda item: self.fixtures[item]),
        )
        self.fixtures["nbrhosts"] = {}
        self.process_failure = {"failed": True, "check_item": "processes", "host": "dut1"}
        self.normal = {"failed": False, "check_item": "dbmemory", "host": "dut1"}
        self.fixtures["check_processes"] = Mock(return_value=[self.process_failure])
        self.fixtures["check_dbmemory"] = Mock(side_effect=self.worker_failure)

    def worker_failure(self, *args, **kwargs):
        detail = self.ns["_sanity_worker_failure"](
            "check_dbmemory", "dut1", (RunAnsibleModuleFail("password=DO_NOT_COPY"), "private traceback")
        )
        raise self.ns["SanityWorkerError"]([detail], {})

    def checks(self, stage="pre"):
        return self.ns["_run_sanity_checks"](
            self.request, ["check_processes", "check_dbmemory"], stage=stage
        )

    def full(self):
        return self.ns["sanity_check_full"](
            None, False, None, self.hosts, self.request, {}, {"topo": {"name": "bmc"}}
        )

    def recover(self, failures, stage="pre"):
        return self.ns["recover_on_sanity_check_failure"](
            None, self.hosts, failures, {}, None, None,
            ["check_processes", "check_dbmemory"], "adaptive", self.request, {}, stage
        )

    def test_prior_failure_and_later_operational_worker_are_preserved(self):
        results = self.checks()
        self.assertIs(results[0], self.process_failure)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[1]["failed"])
        self.assertEqual(results[1]["check_fixture"], "check_dbmemory")
        self.assertEqual(results[1]["host"], "dut1")
        self.assertEqual(results[1]["check_item"], "operational_exception")
        self.assertEqual(results[1]["exception_type"], "RunAnsibleModuleFail")
        self.assertNotIn("DO_NOT_COPY", json.dumps(results))
        self.assertNotIn("private traceback", json.dumps(results))
        self.assertIsNone(self.ns["_sanity_worker_check"].get())

    def test_actual_supported_worker_exception_categories_are_typed_not_text_matched(self):
        for exception_type in [RunAnsibleModuleFail, AnsibleConnectionFailure, PytestAnsibleConnectionFailure]:
            detail = self.ns["_sanity_worker_failure"](
                "check_dbmemory", "dut1", (exception_type("SECRET"), "SECRET traceback"))
            self.fixtures["check_dbmemory"].side_effect = self.ns["SanityWorkerError"]([detail], {})
            results = self.checks()
            self.assertTrue(results[-1]['failed'])
            self.assertEqual(results[-1]['exception_type'], exception_type.__name__)
            self.assertNotIn('SECRET', json.dumps(results))
        # A programming exception with a connection-looking message is NOT operational.
        detail = self.ns["_sanity_worker_failure"](
            "check_dbmemory", "dut1", (KeyError("Host unreachable in the inventory"), "traceback"))
        self.assertFalse(detail['operational'])

    def test_other_workers_completed_results_are_retained(self):
        completed = dict(self.normal, host="dut2")
        detail = self.ns["_sanity_worker_failure"](
            "check_dbmemory", "dut1", (RunAnsibleModuleFail("command"), "traceback")
        )
        self.fixtures["check_dbmemory"].side_effect = self.ns["SanityWorkerError"](
            [detail], {"dut2": completed}
        )
        results = self.checks()
        self.assertEqual(results, [self.process_failure, completed, results[2]])
        self.assertTrue(results[2]["failed"])
        self.assertEqual(results[2]["host"], "dut1")

    def test_fixture_resolution_error_is_not_operational_invocation(self):
        self.request.getfixturevalue.side_effect = lambda item: (
            self.fixtures[item] if item == "check_processes" else fail("fixture setup failed")
        )
        with self.assertRaises(Failed) as caught:
            self.checks()
        self.assertEqual(caught.exception.sanity_check_results, [self.process_failure])
        self.fixtures["check_dbmemory"].assert_not_called()
        self.ns["recover"].assert_not_called()
        self.assertTrue(self.cache["pre_sanity_check_failed"])

    def test_direct_unattributed_operational_error_is_visible_not_guessed(self):
        self.fixtures["check_dbmemory"].side_effect = AnsibleConnectionFailure("unknown target")
        with self.assertRaises(AnsibleConnectionFailure) as caught:
            self.checks()
        self.assertEqual(caught.exception.sanity_check_results, [self.process_failure])
        self.ns["recover"].assert_not_called()

    def test_programming_and_unmarked_pytest_failures_are_not_recovered(self):
        for error in [KeyError("bug"), Failed("ordinary assertion")]:
            with self.subTest(error=type(error).__name__):
                self.fixtures["check_dbmemory"].side_effect = error
                with self.assertRaises(type(error)) as caught:
                    self.checks("post")
                self.assertEqual(caught.exception.sanity_check_results, [self.process_failure])
                self.assertTrue(self.cache["post_sanity_check_failed"])
                self.ns["recover"].assert_not_called()

    def test_unexpected_or_unattributed_worker_failure_stays_visible(self):
        for error, hostname in [(KeyError("bug"), "dut1"), (RunAnsibleModuleFail("cmd"), None)]:
            detail = self.ns["_sanity_worker_failure"]("check_dbmemory", hostname, (error, "traceback"))
            self.fixtures["check_dbmemory"].side_effect = self.ns["SanityWorkerError"]([detail], {})
            expected = self.ns["SanityWorkerError"] if hostname else ValueError
            with self.assertRaises(expected) as caught:
                self.checks()
            self.assertEqual(caught.exception.sanity_check_results, [self.process_failure])
            self.ns["recover"].assert_not_called()

    def test_malformed_records_fail_inside_stage_guard_preserving_valid_peers(self):
        for malformed in [{}, True, "invalid", {"failed": 1, "check_item": "dbmemory"},
                          {"failed": False, "check_item": ""}, {"failed": False, "check_item": None}]:
            for stage in ["pre", "post"]:
                with self.subTest(record=malformed, stage=stage):
                    self.fixtures["check_dbmemory"].side_effect = None
                    self.fixtures["check_dbmemory"].return_value = [self.normal, malformed]
                    with self.assertRaises(ValueError) as caught:
                        self.checks(stage)
                    self.assertEqual(caught.exception.sanity_check_results, [self.process_failure, self.normal])
                    self.assertTrue(self.cache[stage + "_sanity_check_failed"])

    def test_malformed_completed_peer_keeps_prior_and_completed_evidence(self):
        detail = self.ns["_sanity_worker_failure"]("check_dbmemory", "dut1", (RunAnsibleModuleFail("cmd"), "tb"))
        self.fixtures["check_dbmemory"].side_effect = self.ns["SanityWorkerError"](
            [detail], {"dut2": self.normal, "dut3": {}})
        with self.assertRaises(ValueError) as caught:
            self.checks("post")
        self.assertEqual(caught.exception.sanity_check_results, [self.process_failure, self.normal])
        self.assertTrue(self.cache["post_sanity_check_failed"])
        self.ns["recover"].assert_not_called()

    def test_mixed_unknown_and_operational_worker_stays_failure_with_peers(self):
        details = [self.ns["_sanity_worker_failure"]("check_dbmemory", "dut1", (error, "tb"))
                   for error in [RunAnsibleModuleFail("cmd"), KeyError("bug")]]
        self.fixtures["check_dbmemory"].side_effect = self.ns["SanityWorkerError"](details, {"dut2": self.normal})
        with self.assertRaises(self.ns["SanityWorkerError"]) as caught:
            self.checks()
        self.assertEqual(caught.exception.sanity_check_results, [self.process_failure, self.normal])
        self.assertEqual(caught.exception.failures, details)
        self.ns["recover"].assert_not_called()

    def test_worker_host_and_check_must_be_nonempty_strings(self):
        for field in ["host", "check_item"]:
            for value in [42, True, "", "  "]:
                detail = self.ns["_sanity_worker_failure"](
                    "check_dbmemory", "dut1", (RunAnsibleModuleFail("cmd"), "tb"))
                detail[field] = value
                self.fixtures["check_dbmemory"].side_effect = self.ns["SanityWorkerError"]([detail], {})
                with self.assertRaises(ValueError) as caught:
                    self.checks()
                self.assertEqual(caught.exception.sanity_check_results, [self.process_failure])

    def test_two_original_worker_hosts_remain_distinct_recovery_targets(self):
        self.hosts.append(SimpleNamespace(hostname="dut2"))
        details = [self.ns["_sanity_worker_failure"]("check_dbmemory", hostname,
                   (RunAnsibleModuleFail("cmd"), "tb")) for hostname in ["dut1", "dut2"]]
        self.fixtures["check_dbmemory"].side_effect = self.ns["SanityWorkerError"](details, {})
        failures = self.checks()
        self.fixtures["check_processes"].return_value = [dict(self.process_failure, failed=False)]
        self.fixtures["check_dbmemory"].side_effect = None
        self.fixtures["check_dbmemory"].return_value = [self.normal]
        self.recover(failures)
        calls = self.ns["recover"].call_args_list
        self.assertEqual([call.args[1].hostname for call in calls], ["dut1", "dut2"])
        self.assertEqual([result['host'] for result in calls[0].args[-2]], ["dut1", "dut1"])
        self.assertEqual([result['host'] for result in calls[1].args[-2]], ["dut2"])

    def test_nested_context_restores_original_even_after_error(self):
        with self.ns["sanity_worker_context"]("outer"):
            self.assertEqual(self.ns["_sanity_worker_check"].get(), "outer")
            with self.assertRaises(KeyError):
                with self.ns["sanity_worker_context"]("inner"):
                    self.assertEqual(self.ns["_sanity_worker_check"].get(), "inner")
                    raise KeyError("bug")
            self.assertEqual(self.ns["_sanity_worker_check"].get(), "outer")
        self.assertIsNone(self.ns["_sanity_worker_check"].get())

    def test_infrastructure_record_does_not_require_a_host(self):
        infra = {"failed": False, "check_item": "mux_simulator"}
        self.fixtures["check_dbmemory"].side_effect = None
        self.fixtures["check_dbmemory"].return_value = infra
        self.assertEqual(self.checks(), [self.process_failure, infra])

    def test_empty_result_is_not_pass(self):
        for empty in [None, [], {}]:
            self.fixtures["check_dbmemory"].side_effect = None
            self.fixtures["check_dbmemory"].return_value = empty
            with self.assertRaises(ValueError):
                self.checks()

    def test_skip_and_system_exit_are_not_caught(self):
        for error in [Skipped(), SystemExit(2), KeyboardInterrupt()]:
            self.fixtures["check_dbmemory"].side_effect = error
            with self.assertRaises(type(error)):
                self.checks()
            self.assertFalse(self.cache)
            self.assertIsNone(self.ns["_sanity_worker_check"].get())

    def test_enabled_recovery_pre_and_post_reruns_exact_stage_and_all_checks(self):
        for stage in ["pre", "post"]:
            with self.subTest(stage=stage):
                failures = self.checks(stage)
                self.fixtures["check_processes"].return_value = dict(self.process_failure, failed=False)
                self.fixtures["check_dbmemory"].side_effect = None
                self.fixtures["check_dbmemory"].return_value = [self.normal]
                self.recover(failures, stage)
                self.ns["recover"].assert_called_once()
                self.assertEqual(self.ns["recover"].call_args.args[-2], failures)
                self.fixtures["check_processes"].assert_called_with(stage=stage, after_recovery=True)
                self.fixtures["check_dbmemory"].assert_called_with(stage=stage, after_recovery=True)
                self.assertIn(("dut.{}_sanity_recovery_failed".format(stage), False), self.messages)
                self.assertFalse(self.cache)
                self.assertTrue(failures[0]["failed"])
                self.ns["recover"].reset_mock()
                self.fixtures["check_processes"].return_value = [self.process_failure]
                self.fixtures["check_dbmemory"].side_effect = self.worker_failure

    def test_dispatch_and_verification_errors_keep_original_and_flags(self):
        for stage in ["pre", "post"]:
            for boundary in ["dispatch", "verify"]:
                with self.subTest(stage=stage, boundary=boundary):
                    failures = self.checks(stage)
                    self.ns["recover"].side_effect = RuntimeError("reboot failed") if boundary == "dispatch" else None
                    if boundary == "verify":
                        self.fixtures["check_dbmemory"].side_effect = KeyError("verification bug")
                    with self.assertRaises((RuntimeError, KeyError)) as caught:
                        self.recover(failures, stage)
                    self.assertIs(caught.exception.sanity_original_failures, failures)
                    self.assertTrue(self.cache[stage + "_sanity_check_failed"])
                    self.assertIn(("dut.{}_sanity_recovery_failed".format(stage), True), self.messages)
                    self.fixtures["check_dbmemory"].side_effect = self.worker_failure

    def test_failed_operational_verification_does_not_pass(self):
        failures = self.checks()
        with self.assertRaises(Failed) as caught:
            self.recover(failures)
        self.assertIs(caught.exception.sanity_original_failures, failures)
        self.assertTrue(self.cache["pre_sanity_check_failed"])
        self.assertNotIn(("dut.pre_sanity_recovery_failed", False), self.messages)

    def test_recovery_fixture_dependency_failure_is_reported(self):
        failures = self.checks()
        del self.fixtures["nbrhosts"]
        with self.assertRaises(KeyError) as caught:
            self.recover(failures)
        self.assertIs(caught.exception.sanity_original_failures, failures)
        self.assertTrue(self.cache["pre_sanity_check_failed"])
        self.assertIn(("dut.pre_sanity_recovery_failed", True), self.messages)

    def test_full_fixture_disabled_recovery_pre_and_post_has_no_mutation(self):
        for stage in ["pre", "post"]:
            self.request.config.option.enable_pre_sanity = stage == "pre"
            generator = self.full()
            if stage == "post":
                next(generator)
            with self.assertRaises(Failed) as caught:
                next(generator)
            self.assertIn("operational_exception", str(caught.exception))
            self.assertIn("processes", str(caught.exception))
            self.assertTrue(self.cache[stage + "_sanity_check_failed"])
            self.assertIn(("dut.{}_sanity_check_failed".format(stage), True), self.messages)
            self.ns["recover"].assert_not_called()
            self.assertNotIn("nbrhosts", [call.args[0] for call in self.request.getfixturevalue.call_args_list])

    def test_full_fixture_enabled_recovery_pre_and_post(self):
        for stage in ["pre", "post"]:
            self.request.config.option.enable_pre_sanity = stage == "pre"
            self.request.config.option.allow_recover = True
            self.request.config.option.skip_post_check = stage == "pre"
            self.fixtures["check_processes"].return_value = [self.process_failure]
            self.fixtures["check_dbmemory"].side_effect = self.worker_failure

            def recovered(*args):
                self.fixtures["check_processes"].return_value = [dict(self.process_failure, failed=False)]
                self.fixtures["check_dbmemory"].side_effect = None
                self.fixtures["check_dbmemory"].return_value = [self.normal]

            self.ns["recover"].side_effect = recovered
            generator = self.full()
            next(generator)
            with self.assertRaises(StopIteration):
                next(generator)
            self.ns["recover"].assert_called_once()
            self.assertIn(("dut.{}_sanity_check_failed".format(stage), True), self.messages)
            self.assertIn(("dut.{}_sanity_recovery_failed".format(stage), False), self.messages)
            self.assertFalse(self.cache)
            self.ns["recover"].reset_mock()

    def test_full_fixture_programming_failure_sets_stage_flag_without_recovery(self):
        for stage in ['pre', 'post']:
            self.request.config.option.allow_recover = True
            self.request.config.option.enable_pre_sanity = stage == 'pre'
            self.fixtures['check_dbmemory'].side_effect = KeyError('check implementation bug')
            generator = self.full()
            if stage == 'post':
                next(generator)
            with self.assertRaises(KeyError) as caught:
                next(generator)
            self.assertEqual(caught.exception.sanity_check_results, [self.process_failure])
            self.assertTrue(self.cache[stage + '_sanity_check_failed'])
            self.ns['recover'].assert_not_called()

    def test_upfront_fixture_resolution_is_outside_operational_context(self):
        def setup(item):
            self.assertIsNone(self.ns["_sanity_worker_check"].get())
            raise RunAnsibleModuleFail("fixture setup, not check invocation")

        self.request.getfixturevalue.side_effect = setup
        self.request.config.option.allow_recover = True
        with self.assertRaises(RunAnsibleModuleFail):
            next(self.full())
        self.ns["recover"].assert_not_called()
        self.assertTrue(self.cache["pre_sanity_check_failed"])

    def test_normal_full_fixture_pass_and_post_disabled(self):
        self.fixtures["check_processes"].return_value = [dict(self.process_failure, failed=False)]
        self.fixtures["check_dbmemory"].side_effect = None
        self.fixtures["check_dbmemory"].return_value = [self.normal]
        for disabled in [False, True]:
            self.request.config.option.skip_post_check = disabled
            self.fixtures["check_dbmemory"].reset_mock()
            generator = self.full()
            next(generator)
            with self.assertRaises(StopIteration):
                next(generator)
            self.assertEqual(self.fixtures["check_dbmemory"].call_count, 1 if disabled else 2)
            self.assertFalse(self.cache)
            self.ns["recover"].assert_not_called()

    def test_existing_adaptive_dispatch_picks_one_reboot_without_redis_diagnosis(self):
        failures = self.checks()
        namespace = {"logging": logging, "constants": SimpleNamespace(RECOVER_METHODS={
            "reboot": {"recover_wait": 120, "reload": False, "reboot": True, "cmd": "reboot"},
        }), "reboot_dut": Mock(), "config_reload": Mock()}
        load(RECOVER, ["adaptive_recover"], namespace)
        namespace["adaptive_recover"](None, self.host, None, {}, {}, {}, failures, 30)
        namespace["reboot_dut"].assert_called_once_with(
            self.host, None, "reboot", reboot_with_running_golden_config=True
        )
        namespace["config_reload"].assert_not_called()

    def test_sessionfinish_retains_existing_pre_post_exit_semantics(self):
        for pre, post, expected in [(True, False, 10), (False, True, 11), (True, True, 12)]:
            self.cache.update(pre_sanity_check_failed=pre, post_sanity_check_failed=post)
            self.request.config.cache.get = self.cache.get
            session = SimpleNamespace(config=self.request.config, exitstatus=0)
            self.ns["pytest_sessionfinish"](session, 0)
            self.assertEqual(session.exitstatus, expected)
            self.assertFalse(self.cache["pre_sanity_check_failed"])
            self.assertFalse(self.cache["post_sanity_check_failed"])

    def test_carrier_pickle_roundtrip_has_safe_category_and_host(self):
        detail = self.ns["_sanity_worker_failure"](
            "check_dbmemory", "dut1", (AnsibleConnectionFailure("SECRET"), "SECRET traceback")
        )
        error = self.ns["SanityWorkerError"]([detail], {"dut2": self.normal})
        restored = pickle.loads(pickle.dumps(error))
        self.assertEqual(restored.failures, error.failures)
        self.assertEqual(restored.results, error.results)
        self.assertNotIn("SECRET", str(restored))

    def test_parallel_run_default_and_opt_in_boundary(self):
        # Fake workers/manager exercise actual parallel_run without processes,
        # sockets, Ansible imports, or a manager server.
        load(PARALLEL, ["parallel_run"], self.ns)
        for opt_in, error in [(False, RunAnsibleModuleFail("legacy command details")),
                              (True, RunAnsibleModuleFail("command")), (True, KeyError("bug"))]:
            worker = SimpleNamespace(
                name="worker", exitcode=1, pid=123, start=Mock(), is_alive=lambda: False,
                is_running=lambda: False,
                exception=(error, "legacy traceback"),
            )

            def process(**kwargs):
                worker.name = kwargs["name"]
                return worker

            def wait(workers, **kwargs):
                kwargs["callback"](worker)
                return list(workers), []

            self.ns.update({
                "Manager": lambda: SimpleNamespace(dict=dict), "datetime": datetime, "math": math,
                "fix_logging_handler_fork_lock": Mock(), "SonicProcess": process, "wait_procs": wait,
            })
            context = self.ns["sanity_worker_context"]("check_dbmemory") if opt_in else nullcontext()

            class LegacyNode:
                @property
                def hostname(self):
                    raise AssertionError("Legacy caller must not perform new host lookup")

            node = self.host if opt_in else LegacyNode()
            initial = {"failed": False} if opt_in else None
            with context:
                if opt_in:
                    with self.assertRaises(self.ns["SanityWorkerError"]) as caught:
                        self.ns["parallel_run"](self.worker_failure, (), {}, [node], init_result=initial)
                    self.assertEqual(caught.exception.failures[0]["host"], "dut1")
                    self.assertEqual(caught.exception.failures[0]["operational"],
                                     isinstance(error, RunAnsibleModuleFail))
                    self.assertEqual(caught.exception.results, {})
                else:
                    with self.assertRaises(Failed) as caught:
                        self.ns["parallel_run"](self.worker_failure, (), {}, [node], init_result=initial)
                    self.assertIn("legacy command details", str(caught.exception))
                    self.assertIn("legacy traceback", str(caught.exception))
            self.assertIsNone(self.ns["_sanity_worker_check"].get())


if __name__ == "__main__":
    unittest.main()

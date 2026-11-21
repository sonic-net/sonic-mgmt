"""Focused contracts for the native PTF engine and remote job controller."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[3]
TRAFFIC_PATH = REPO_ROOT / "tests/evpn_mh/traffic.py"
PTF_PATH = (
    REPO_ROOT
    / "ansible/roles/test/files/ptftests/py3/evpn_mh_traffic.py")
PTF_PLATFORM_PATH = (
    REPO_ROOT
    / "ansible/roles/test/files/ptftests/evpn_mh_remote.py")
LAG_PATH = REPO_ROOT / "tests/evpn_mh/lag.py"
PROVISION_PATH = REPO_ROOT / "tests/evpn_mh/provision.py"
CONFTEST_PATH = REPO_ROOT / "tests/evpn_mh/conftest.py"


def _load_traffic_module():
    package = types.ModuleType("evpn_mh_controller_test")
    package.__path__ = []
    operations = types.ModuleType(package.__name__ + ".operations")
    operations.wait_until = lambda *args, **kwargs: True
    profiles = types.ModuleType(package.__name__ + ".traffic_profile")
    profiles.load_profiles = lambda: {"profiles": {}}
    profiles.resolved_profile = lambda name, topology, runtime=None: {
        "name": name, "runtime": runtime or {}}
    runner = types.ModuleType("tests.ptf_runner")
    runner.ptf_runner = lambda *args, **kwargs: True
    runner.ptf_collect = lambda *args, **kwargs: None
    module_name = package.__name__ + ".traffic"
    spec = importlib.util.spec_from_file_location(module_name, TRAFFIC_PATH)
    module = importlib.util.module_from_spec(spec)
    modules = {
        package.__name__: package,
        operations.__name__: operations,
        profiles.__name__: profiles,
        "tests.ptf_runner": runner,
        module_name: module,
    }
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class _Layer:
    pass


def _load_ptf_module():
    ptf = types.ModuleType("ptf")
    ptf.__path__ = []
    ptf.config = {}
    ptf.dataplane_instance = object()
    ptf.dataplane = types.SimpleNamespace(match_exp_pkt=lambda *args: True)
    packet = types.ModuleType("ptf.packet")
    for name in ("UDP", "IP", "IPv6", "Ether", "ICMP"):
        setattr(packet, name, type(name, (_Layer,), {}))
    testutils = types.ModuleType("ptf.testutils")
    testutils.test_params_get = lambda: {}
    base_tests = types.ModuleType("ptf.base_tests")
    base_tests.BaseTest = type("BaseTest", (object,), {})
    mask = types.ModuleType("ptf.mask")
    mask.Mask = type("Mask", (object,), {})
    scapy = types.ModuleType("scapy")
    scapy.__path__ = []
    config = types.ModuleType("scapy.config")
    config.conf = types.SimpleNamespace()
    layers = types.ModuleType("scapy.layers")
    layers.__path__ = []
    inet6 = types.ModuleType("scapy.layers.inet6")
    for name in (
            "ICMPv6ND_NA", "ICMPv6ND_NS", "ICMPv6NDOptDstLLAddr",
            "ICMPv6NDOptSrcLLAddr", "IPv6"):
        setattr(inet6, name, type(name, (_Layer,), {}))
    inet6.in6_getnsmac = lambda value: value
    inet6.in6_getnsma = lambda value: value
    l2 = types.ModuleType("scapy.layers.l2")
    l2.Dot1Q = type("Dot1Q", (_Layer,), {})
    l2.Ether = type("Ether", (_Layer,), {})
    scapy_packet = types.ModuleType("scapy.packet")
    scapy_packet.Raw = type("Raw", (_Layer,), {})
    modules = {
        "ptf": ptf,
        "ptf.packet": packet,
        "ptf.testutils": testutils,
        "ptf.base_tests": base_tests,
        "ptf.mask": mask,
        "scapy": scapy,
        "scapy.config": config,
        "scapy.layers": layers,
        "scapy.layers.inet6": inet6,
        "scapy.layers.l2": l2,
        "scapy.packet": scapy_packet,
    }
    ptf.packet = packet
    ptf.testutils = testutils
    module_name = "evpn_mh_ptf_engine_test"
    spec = importlib.util.spec_from_file_location(module_name, PTF_PATH)
    module = importlib.util.module_from_spec(spec)
    modules[module_name] = module
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module, ptf


def _load_ptf_platform_module():
    calls = []
    remote = types.ModuleType("remote")

    def platform_config_update(config):
        calls.append(dict(config))
        config["port_map"] = {(0, 36): "backplane"}

    remote.platform_config_update = platform_config_update
    module_name = "evpn_mh_remote_platform_test"
    spec = importlib.util.spec_from_file_location(module_name, PTF_PLATFORM_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"remote": remote, module_name: module}):
        spec.loader.exec_module(module)
    return module, calls


def _load_lag_module():
    utilities = types.ModuleType("tests.common.utilities")
    utilities.wait_until = lambda *args, **kwargs: True
    module_name = "evpn_mh_lag_contract_test"
    spec = importlib.util.spec_from_file_location(module_name, LAG_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {
            "tests.common.utilities": utilities,
            module_name: module,
    }):
        spec.loader.exec_module(module)
    return module


def _load_provision_module():
    package = types.ModuleType("evpn_mh_provision_contract_test")
    package.__path__ = []
    operations = types.ModuleType(package.__name__ + ".operations")
    operations.portchannel_members = lambda *args, **kwargs: []
    operations.wait_overlay = lambda *args, **kwargs: True
    operations.wait_until = (
        lambda timeout, interval, delay, function, *args, **kwargs:
        function(*args, **kwargs)
    )
    topology = types.ModuleType(package.__name__ + ".topology")
    topology.ethernet_segments = lambda document: document["ethernet_segments"]
    module_name = package.__name__ + ".provision"
    spec = importlib.util.spec_from_file_location(module_name, PROVISION_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {
            package.__name__: package,
            operations.__name__: operations,
            topology.__name__: topology,
            module_name: module,
    }):
        spec.loader.exec_module(module)
    return module


class FakeHost:
    def __init__(self):
        self.commands = []
        self.files = {}

    def shell(self, command, **kwargs):
        self.commands.append((command, kwargs))
        if command.startswith("if [ -x /root/env-python3/bin/ptf"):
            return {"rc": 0, "stdout": "/root/env-python3/bin/ptf"}
        if command.startswith("if [ ! -r "):
            return {"rc": 1, "stdout": ""}
        if command.startswith("test -f "):
            path = command[len("test -f "):].strip("'")
            return {"rc": 0 if path in self.files else 1, "stdout": ""}
        if command.startswith("cat "):
            path = command[len("cat "):].strip("'")
            if path in self.files:
                return {"rc": 0, "stdout": self.files[path]}
            return {"rc": 1, "stdout": ""}
        return {"rc": 0, "stdout": ""}


class TrafficControllerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_traffic_module()

    def test_jobs_and_logs_are_suite_owned_and_never_use_tmp(self):
        job = self.module._new_job("continuous")
        self.assertTrue(job["job_dir"].startswith("/root/evpn_mh_jobs/"))
        self.assertTrue(job["require_ownership"])
        self.assertNotIn(
            "/tmp", " ".join(
                value for value in job.values()
                if isinstance(value, str)))
        with self.assertRaises(ValueError):
            self.module._safe_job_dir({
                "job_dir": "/root/evpn_mh_jobs/.."})

    def test_explicit_launch_uses_feature_platform_and_result_file(self):
        host = FakeHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        self.module._launch_job(job, {
            "profile": {"flows": []}, "port_map": {"h3": 7},
            "kvm_support": True})
        command = host.commands[-1][0]
        self.assertIn("setsid sh -c", command)
        self.assertIn("/root/env-python3/bin/ptf", command)
        self.assertIn(job["result_file"], command)
        self.assertIn(job["identity_file"], command)
        self.assertIn('/proc/"$pid"/stat', command)
        self.assertIn("--platform evpn_mh_remote", command)
        self.assertNotIn("need_backplane", command)
        self.assertNotIn("/tmp", command)

    def test_identity_failure_gate_precedes_ptf_execution(self):
        job = self.module._new_job("continuous")
        sentinel = "PTF_EXECUTION_SENTINEL"
        worker = self.module._continuous_worker_command(job, sentinel)
        identity_write = worker.index(job["identity_file"] + ".pending")
        identity_publish = worker.index(
            "mv -- {} {}".format(
                job["identity_file"] + ".pending", job["identity_file"]))
        launch_gate = worker.index("[ -f {} ] || launch_fail".format(
            job["launch_file"]))
        ptf_execution = worker.index(sentinel)
        self.assertLess(identity_write, identity_publish)
        self.assertLess(identity_publish, launch_gate)
        self.assertLess(launch_gate, ptf_execution)
        self.assertIn(">{} || launch_fail".format(
            job["identity_file"] + ".pending"), worker)
        self.assertIn('[ "$pgid" = "$pid" ] || launch_fail', worker)

    def test_event_window_creates_start_and_end_markers(self):
        host = FakeHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        now = [0.0]

        def clock():
            return now[0]

        def sleeper(seconds):
            now[0] += seconds

        elapsed = self.module.hold_traffic_event(
            job, 2, poll_interval=0.5, clock=clock, sleeper=sleeper)
        self.assertEqual(elapsed, 2)
        commands = [command for command, _ in host.commands]
        self.assertIn("touch {}".format(job["event_start_file"]), commands)
        self.assertIn("touch {}".format(job["event_end_file"]), commands)

    def test_startup_failure_terminates_before_cleanup(self):
        host = FakeHost()
        order = []
        with patch.object(self.module, "ensure_native_ptf_tests"), \
                patch.object(self.module, "_prepare_job"), \
                patch.object(
                    self.module, "_launch_job",
                    side_effect=RuntimeError("launch failed")), \
                patch.object(
                    self.module, "_terminate_bounded",
                    side_effect=lambda job: order.append("terminate")), \
                patch.object(
                    self.module, "_collect_job",
                    side_effect=lambda job: order.append("collect")), \
                patch.object(
                    self.module, "_cleanup_job",
                    side_effect=lambda job: order.append("cleanup")):
            with self.assertRaisesRegex(RuntimeError, "launch failed"):
                self.module.start_traffic_profile(
                    host, "profile", {"h3": 7}, {})
        self.assertEqual(order, ["terminate", "collect", "cleanup"])

    def test_startup_termination_failure_still_collects_and_safely_cleans(self):
        host = FakeHost()
        order = []
        with patch.object(self.module, "ensure_native_ptf_tests"), \
                patch.object(self.module, "_prepare_job"), \
                patch.object(
                    self.module, "_launch_job",
                    side_effect=RuntimeError("launch failed")), \
                patch.object(
                    self.module, "_terminate_bounded",
                    side_effect=RuntimeError("TERM failed")) as terminate, \
                patch.object(
                    self.module, "_collect_job",
                    side_effect=lambda job: order.append("collect")), \
                patch.object(
                    self.module, "_cleanup_job",
                    side_effect=lambda job: order.append("cleanup")):
            with self.assertRaisesRegex(
                    RuntimeError,
                    "launch failed; continuous startup cleanup also failed: "
                    "worker termination: TERM failed"):
                self.module.start_traffic_profile(
                    host, "profile", {"h3": 7}, {})
        terminate.assert_called_once()
        self.assertEqual(order, ["collect", "cleanup"])

    def test_keyboard_interrupt_during_barrier_reaps_unreturned_worker(self):
        host = FakeHost()
        order = []
        with patch.object(self.module, "ensure_native_ptf_tests"), \
                patch.object(self.module, "_prepare_job"), \
                patch.object(self.module, "_launch_job"), \
                patch.object(
                    self.module, "_test_file",
                    side_effect=KeyboardInterrupt), \
                patch.object(
                    self.module, "_terminate_bounded",
                    side_effect=lambda job: order.append("terminate")), \
                patch.object(
                    self.module, "_collect_job",
                    side_effect=lambda job: order.append("collect")), \
                patch.object(
                    self.module, "_cleanup_job",
                    side_effect=lambda job: order.append("cleanup")):
            with self.assertRaises(KeyboardInterrupt):
                self.module.start_traffic_profile(
                    host, "profile", {"h3": 7}, {})
        self.assertEqual(order, ["terminate", "collect", "cleanup"])

    def test_bounded_termination_escalates_term_then_kill(self):
        host = FakeHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        signals = []
        with patch.object(self.module, "_job_result", return_value=None), \
                patch.object(self.module, "_job_process_alive",
                             return_value=True), \
                patch.object(self.module, "_wait_job_stopped",
                             side_effect=(False, True)), \
                patch.object(
                    self.module, "_terminate_job",
                    side_effect=lambda unused_job, signal: signals.append(signal)):
            self.assertIsNone(
                self.module._terminate_bounded(job, grace_seconds=1))
        self.assertEqual(signals, ["TERM", "KILL"])

    def test_signal_uses_external_kill_not_dash_builtin_double_dash(self):
        host = FakeHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        with patch.object(self.module, "_job_process_alive",
                          side_effect=(True, False)):
            self.module._terminate_job(job, "TERM")
        command = host.commands[-1][0]
        self.assertIn("killer=/bin/kill", command)
        self.assertIn('"$killer" -TERM -- -"$pid"', command)
        self.assertNotIn('"$killer" -TERM -- "$pid"', command)
        self.assertNotIn("kill -TERM --", command)

    def test_failed_group_kill_reprobes_and_never_falls_back_to_pid(self):
        class FailedGroupKillHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if '"$killer" -TERM -- -"$pid"' in command:
                    return {"rc": 1, "stderr": "group disappeared"}
                return {"rc": 0, "stdout": ""}

        host = FailedGroupKillHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        with patch.object(
                self.module, "_job_process_alive",
                side_effect=(True, RuntimeError("PID identity changed"))):
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                self.module._terminate_job(job, "TERM")
        signal_command = host.commands[-1][0]
        self.assertIn('"$killer" -TERM -- -"$pid"', signal_command)
        self.assertNotIn('"$killer" -TERM -- "$pid"', signal_command)

    def test_kill_verification_fails_closed_and_cleanup_preserves_job(self):
        host = FakeHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        with patch.object(self.module, "_job_result", return_value=None), \
                patch.object(self.module, "_job_process_alive",
                             return_value=True), \
                patch.object(self.module, "_wait_job_stopped",
                             side_effect=(False, False)), \
                patch.object(self.module, "_terminate_job"):
            with self.assertRaisesRegex(RuntimeError, "still live"):
                self.module._terminate_bounded(job, grace_seconds=0)
        with patch.object(self.module, "_wait_job_stopped",
                          return_value=False):
            with self.assertRaisesRegex(RuntimeError, "refusing to remove live"):
                self.module._cleanup_job(job)
        self.assertFalse(any(command.startswith("rm -rf -- ")
                             for command, _ in host.commands))

    def test_unknown_worker_liveness_preserves_continuous_job(self):
        class UnknownLivenessHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if command.startswith("if [ ! -r "):
                    return {"rc": 2, "stderr": "malformed pid"}
                return {"rc": 0, "stdout": ""}

        host = UnknownLivenessHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        with self.assertRaisesRegex(RuntimeError, "liveness is unknown"):
            self.module._job_process_alive(job)
        with self.assertRaisesRegex(RuntimeError, "liveness is unknown"):
            self.module._cleanup_job(job)
        self.assertFalse(any(
            command.startswith("rm -rf -- ") for command, _ in host.commands
        ))

    def test_stale_live_worker_is_terminated_then_removed(self):
        host = FakeHost()
        basename = "continuous-" + "a" * 32
        job = self.module._job_files(
            self.module.PTF_JOB_ROOT + "/" + basename,
            token="a" * 32)
        job.update({
            "ptfhost": host,
            "require_ownership": True,
        })
        with patch.object(
                self.module, "_stale_continuous_jobs",
                return_value=[job]), \
                patch.object(
                    self.module, "_job_process_alive", return_value=True), \
                patch.object(
                    self.module, "_wait_job_stopped", return_value=True), \
                patch.object(self.module, "_terminate_job") as terminate:
            self.module.reap_stale_traffic_jobs(host)
        terminate.assert_called_once_with(job, "TERM")
        self.assertTrue(any(
            command.startswith("rm -rf -- ") for command, _ in host.commands
        ))

    def test_stale_worker_probe_requires_exact_command_ownership(self):
        class LiveOwnedHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                return {"rc": 0, "stdout": ""}

        host = LiveOwnedHost()
        basename = "continuous-" + "b" * 32
        job = self.module._job_files(
            self.module.PTF_JOB_ROOT + "/" + basename,
            token="b" * 32)
        job.update({
            "ptfhost": host,
            "require_ownership": True,
        })
        self.assertTrue(self.module._job_process_alive(job))
        command = host.commands[-1][0]
        self.assertIn(self.module.PTF_TEST_NAME, command)
        self.assertIn(job["job_dir"], command)
        self.assertIn(job["result_file"], command)
        self.assertIn(job["log_file"], command)
        self.assertIn("/root/env-python3/bin/ptf", command)
        self.assertIn("/usr/local/bin/ptf", command)
        self.assertIn(job["identity_file"], command)
        self.assertIn('/proc/"$pid"/stat', command)
        self.assertNotIn('"$group" | grep', command)
        self.assertIn('"$leader" | grep', command)

    def test_current_job_pid_reuse_is_not_signalled(self):
        class ReusedPidHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if command.startswith("if [ ! -r "):
                    return {"rc": 5, "stderr": "process start time changed"}
                return {"rc": 0, "stdout": ""}

        host = ReusedPidHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        with self.assertRaisesRegex(RuntimeError, "liveness is unknown"):
            self.module._terminate_job(job, "TERM")
        self.assertEqual(len(host.commands), 1)
        self.assertNotIn('"$killer"', host.commands[0][0])

    def test_probe_shell_cannot_self_match_worker_ownership(self):
        job = self.module._new_job("continuous")
        command = self.module._process_probe_command(job)
        self.assertIn("identity_start", command)
        self.assertIn("current_start", command)
        self.assertIn('"$identity_pgid" = "$pid"', command)
        self.assertIn('"$current_pgid" = "$pid"', command)
        self.assertIn('/proc/"$pid"/stat', command)
        self.assertIn("$1 == id", command)
        self.assertNotIn('"$group" | grep', command)
        self.assertGreaterEqual(command.count('"$leader" | grep'), 5)

    def test_unknown_stale_pid_is_preserved_without_signal_or_removal(self):
        class UnknownStaleHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if command.startswith(
                        "if [ ! -e /root/evpn_mh_jobs"):
                    return {
                        "rc": 0,
                        "stdout": "continuous-{}\n".format("c" * 32),
                    }
                if command.startswith("if [ ! -r "):
                    return {"rc": 5, "stderr": "ownership mismatch"}
                return {"rc": 0, "stdout": ""}

        host = UnknownStaleHost()
        with self.assertRaisesRegex(
                RuntimeError, "preserved ambiguous jobs"):
            self.module.reap_stale_traffic_jobs(host)
        commands = [command for command, _ in host.commands]
        self.assertFalse(any("\"$killer\"" in command for command in commands))
        self.assertFalse(any(
            command.startswith("rm -rf -- ") for command in commands
        ))

    def test_malformed_stale_job_name_is_preserved(self):
        class MalformedNameHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                return {"rc": 0, "stdout": "continuous-not-a-token\n"}

        host = MalformedNameHost()
        with self.assertRaisesRegex(RuntimeError, "ambiguous stale"):
            self.module.reap_stale_traffic_jobs(host)
        self.assertFalse(any(
            command.startswith("rm -rf -- ")
            for command, _ in host.commands
        ))

    def test_cleanup_checks_command_result_and_remote_absence(self):
        class CleanupFailureHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if command.startswith("if [ ! -r "):
                    return {"rc": 1, "stdout": ""}
                if command.startswith("rm -rf -- "):
                    return {"rc": 1, "stdout": ""}
                if command.startswith("test ! -e "):
                    return {"rc": 1, "stdout": ""}
                return {"rc": 0, "stdout": ""}

        host = CleanupFailureHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        with self.assertRaisesRegex(
                RuntimeError, "failed to remove PTF job directory"):
            self.module._cleanup_job(job)
        commands = [command for command, _ in host.commands]
        self.assertTrue(any(command.startswith("rm -rf -- ")
                            for command in commands))
        self.assertTrue(any(command.startswith("test ! -e ")
                            for command in commands))

    def test_failed_stop_marker_still_reaps_worker_and_aggregates_failures(self):
        host = FakeHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        with patch.object(
                self.module, "stop_traffic_profile",
                side_effect=RuntimeError("marker write failed")), \
                patch.object(
                    self.module, "wait_traffic_profile",
                    side_effect=RuntimeError("worker still live")) as wait, \
                patch.object(self.module, "_terminate_bounded") as terminate, \
                patch.object(self.module, "_cleanup_job") as cleanup:
            with self.assertRaisesRegex(
                    RuntimeError,
                    "stop marker: marker write failed; worker reap: worker still live"):
                self.module.finish_traffic_profile(job, 60)
        wait.assert_called_once_with(job, 0)
        terminate.assert_called_once_with(job)
        cleanup.assert_called_once_with(job)

    def test_stop_marker_command_is_checked(self):
        class StopFailureHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                return {"rc": 1, "stderr": "read-only filesystem"}

        host = StopFailureHost()
        job = self.module._new_job("continuous")
        job["ptfhost"] = host
        with self.assertRaisesRegex(RuntimeError, "failed to create PTF stop marker"):
            self.module.stop_traffic_profile(job)
        self.assertTrue(host.commands[-1][1]["module_ignore_errors"])


class PtfEngineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.ptf = _load_ptf_module()

    def test_engine_has_no_import_time_platform_config_mutation(self):
        self.assertNotIn("need_backplane", self.ptf.config)

    def test_feature_platform_sets_backplane_before_delegating(self):
        platform, calls = _load_ptf_platform_module()
        config = {"platform": "evpn_mh_remote"}
        platform.platform_config_update(config)
        self.assertEqual(calls[0]["need_backplane"], True)
        self.assertEqual(config["port_map"], {(0, 36): "backplane"})

    def test_vlan_distinguishes_endpoints_on_one_backplane_port(self):
        engine = object.__new__(self.module.EvpnMhTraffic)
        engine.profile = {
            "endpoint_vlans": {"h3": 10, "h4": 20},
            "runtime": {}, "bond_endpoints": {}}
        engine.port_map = {"h3": 17, "h4": 17}
        groups, forbidden = engine._resolve_observations({
            "name": "bum", "receive_groups": [["h3"]],
            "forbidden_endpoints": ["h4"]})
        self.assertEqual(groups, [[(17, 10)]])
        self.assertEqual(forbidden, [(17, 20)])

    def test_loss_and_duplicate_copies_cannot_cancel(self):
        engine = object.__new__(self.module.EvpnMhTraffic)
        engine.profile = {
            "defaults": {"max_loss_percent": 0, "max_duplicate_percent": 0,
                         "forbidden_max_percent": 0},
            "runtime": {}}
        flow = {"name": "graded"}
        observation = (3, 0)
        with self.assertRaises(AssertionError):
            engine._assert_delivery(
                flow, 5, {observation: 5}, [[observation]], [],
                {observation: {0, 1, 2, 3}})
        with self.assertRaises(AssertionError):
            engine._assert_delivery(
                flow, 5, {observation: 6}, [[observation]], [],
                {observation: {0, 1, 2, 3, 4}})
        engine._assert_delivery(
            flow, 5, {observation: 5}, [[observation]], [],
            {observation: {0, 1, 2, 3, 4}})

    def test_engine_source_varies_both_udp_ports_and_tags_neighbor_priming(self):
        text = PTF_PATH.read_text(encoding="utf-8")
        self.assertIn("def _vary_udp_ports", text)
        self.assertIn("varied[packet.UDP].sport = sport", text)
        self.assertIn("varied[packet.UDP].dport = dport", text)
        self.assertIn("dl_vlan_enable=bool(vlan_id)", text)
        self.assertIn("ns /= Dot1Q(vlan=vlan_id)", text)
        self.assertIn("if variation or identity is not None else None", text)

    def test_foreign_udp_tuple_cannot_satisfy_varied_delivery(self):
        engine = object.__new__(self.module.EvpnMhTraffic)
        observation = (7, 0)
        expected = {(10000, 20000), (10001, 20001)}
        received = [
            (10000, 20000),
            (55555, 44444),  # Header-masked foreign tuple.
        ]
        accepted = {
            value for value in received
            if engine._identity_is_allowed(value, expected)
        }
        self.assertFalse(engine._identity_is_allowed(
            (55555, 44444), expected))
        self.assertEqual(accepted, {(10000, 20000)})
        engine.profile = {
            "defaults": {"max_loss_percent": 0,
                         "max_duplicate_percent": 100,
                         "forbidden_max_percent": 0},
            "runtime": {},
        }
        with self.assertRaisesRegex(AssertionError, "delivered 1 unique"):
            engine._assert_delivery(
                {"name": "varied"}, 2,
                {observation: len(received)}, [[observation]], [],
                {observation: accepted})

    def test_foreign_raw_sequence_cannot_satisfy_bounded_delivery(self):
        engine = object.__new__(self.module.EvpnMhTraffic)
        observation = (7, 0)
        expected = set(range(2))
        received = [0, 2 ** 48 + 7]  # Header-matching foreign raw payload.
        accepted = {
            value for value in received
            if engine._identity_is_allowed(value, expected)
        }
        self.assertEqual(accepted, {0})
        engine.profile = {
            "defaults": {"max_loss_percent": 0,
                         "max_duplicate_percent": 100,
                         "forbidden_max_percent": 0},
            "runtime": {},
        }
        with self.assertRaisesRegex(AssertionError, "delivered 1 unique"):
            engine._assert_delivery(
                {"name": "bounded"}, 2,
                {observation: len(received)}, [[observation]], [],
                {observation: accepted})

    def test_event_markers_are_acknowledged_at_exact_sequence_boundaries(self):
        engine = object.__new__(self.module.EvpnMhTraffic)
        state = {
            "sent": 17,
            "event_sent_start": None,
            "event_sent_end": None,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine.profile = {
                "event_start_file": str(root / "start"),
                "event_start_ack_file": str(root / "start-ack"),
                "event_end_file": str(root / "end"),
                "event_end_ack_file": str(root / "end-ack"),
            }
            (root / "start").touch()
            engine._update_event_window([state])
            self.assertEqual(state["event_sent_start"], 17)
            self.assertTrue((root / "start-ack").is_file())

            state["sent"] = 29
            (root / "end").touch()
            engine._update_event_window([state])
            self.assertEqual(state["event_sent_end"], 29)
            self.assertTrue((root / "end-ack").is_file())


class LagCleanupContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_lag_module()

    def test_link_query_error_cannot_prove_ptf_object_absence(self):
        class LinkQueryHost(FakeHost):
            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if command.startswith("ip -j link show dev evpn-h2"):
                    return {"rc": 2, "stderr": "netlink query failed"}
                if command.startswith("ip -j link show dev bond-evpn-mh"):
                    return {"rc": 1, "stderr": 'Device "bond-evpn-mh" does not exist.'}
                if command.startswith("ip -j link show dev eth"):
                    interface = command.rsplit(" ", 1)[-1]
                    return {
                        "rc": 0,
                        "stdout": '[{{"ifname": "{}", "flags": ["UP"]}}]'.format(
                            interface),
                    }
                return {"rc": 0, "stdout": ""}

        host = LinkQueryHost()
        segment = {
            "ptf_host_interface": "evpn-h2",
            "ptf_bond_interface": "bond-evpn-mh",
            "ptf_member_roles": ("h2_leg0", "h2_leg1"),
        }
        with self.assertRaisesRegex(
                RuntimeError, "evpn-h2 link-state query failed"):
            self.module.remove_ptf_segment(
                host, {"h2_leg0": 25, "h2_leg1": 26}, segment)

    def test_physically_up_but_unselected_member_is_not_operational(self):
        class BondStateHost(FakeHost):
            def __init__(self, port_state):
                super().__init__()
                self.port_state = port_state

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                return {
                    "rc": 0,
                    "stdout": (
                        "Number of ports: 2\n"
                        "Partner Mac Address: 02:00:00:00:00:01\n"
                        "Slave Interface: eth25\n"
                        "MII Status: up\n"
                        "details actor lacp pdu:\n"
                        "port state: {}\n"
                        "details partner lacp pdu:\n"
                        "port state: 63\n"
                        "Slave Interface: eth26\n"
                        "MII Status: up\n"
                        "details actor lacp pdu:\n"
                        "port state: 63\n"
                        "details partner lacp pdu:\n"
                        "port state: 63\n"
                    ).format(self.port_state),
                }

        self.assertFalse(self.module.ptf_bond_member_operational(
            BondStateHost(7), "eth25"))
        self.assertTrue(self.module.ptf_bond_member_operational(
            BondStateHost(63), "eth25"))

    def test_two_segments_create_disjoint_bonds_and_host_interfaces(self):
        host = FakeHost()
        duts = {"mh_leaf0": FakeHost(), "mh_leaf1": FakeHost()}
        ports = {
            "h1_leg0": 0, "h1_leg1": 27,
            "h2_leg0": 25, "h2_leg1": 26,
        }
        endpoints = {
            "h1": {
                "mac": "00:00:00:00:00:01",
                "ipv4": "10.212.10.1", "ipv6": "2001:db8:10::1",
            },
            "h2": {
                "mac": "00:00:00:00:00:02",
                "ipv4": "10.212.10.2", "ipv6": "2001:db8:10::2",
            },
        }
        segments = ({
            "endpoint": "h1",
            "leaf_roles": ("mh_leaf0", "mh_leaf1"),
            "portchannel": "PortChannel105",
            "ptf_member_roles": ("h1_leg0", "h1_leg1"),
            "ptf_bond_interface": "bond-evpn-h1",
            "ptf_host_interface": "evpn-h1",
            "ptf_system_mac": "02:00:00:00:00:01",
        }, {
            "endpoint": "h2",
            "leaf_roles": ("mh_leaf0", "mh_leaf1"),
            "portchannel": "PortChannel100",
            "ptf_member_roles": ("h2_leg0", "h2_leg1"),
            "ptf_bond_interface": "bond-evpn-h2",
            "ptf_host_interface": "evpn-h2",
            "ptf_system_mac": "02:00:00:00:00:02",
        })

        for segment in segments:
            self.module.configure_ptf_segment(
                host, ports, segment, endpoints, duts)

        commands = [command for command, _ in host.commands]
        self.assertIn("ip link add bond-evpn-h1 type bond", commands)
        self.assertIn("ip link add bond-evpn-h2 type bond", commands)
        self.assertIn("ip link set eth0 master bond-evpn-h1", commands)
        self.assertIn("ip link set eth27 master bond-evpn-h1", commands)
        self.assertIn("ip link set eth25 master bond-evpn-h2", commands)
        self.assertIn("ip link set eth26 master bond-evpn-h2", commands)
        self.assertIn(
            "ip link add link bond-evpn-h1 name evpn-h1 type macvlan mode bridge",
            commands)
        self.assertIn(
            "ip link add link bond-evpn-h2 name evpn-h2 type macvlan mode bridge",
            commands)

    def test_partial_second_bond_setup_still_cleans_both_in_reverse_order(self):
        source = CONFTEST_PATH.read_text(encoding="utf-8")
        fixture = source[source.index("def evpn_mh_ptf_lags("):
                         source.index("def evpn_mh_ptf_lag(")]
        self.assertLess(
            fixture.index("configured.append(segment)"),
            fixture.index("configure_ptf_segment("),
        )
        self.assertIn("for segment in reversed(configured):", fixture)
        self.assertIn("remove_ptf_segment(", fixture)


class ProvisionCleanStartContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_provision_module()

    @staticmethod
    def _topology():
        return {
            "mh_vlan": 10,
            "remote_vlan": 20,
            "endpoints": {"h2": {"mac": "00:00:00:00:00:02"}},
            "ethernet_segments": {"es_h2": {
                "endpoint": "h2",
                "leaf_roles": ("mh_leaf0",),
                "vlan": 10,
                "portchannel": "PortChannel100",
                "ptf_system_mac": "02:00:00:00:00:02",
            }},
        }

    def test_asic_query_failure_is_not_treated_as_fdb_absence(self):
        class AsicFailureHost(FakeHost):
            hostname = "leaf0"

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if "ASIC_DB KEYS" in command:
                    return {"rc": 2, "stderr": "redis query failed"}
                return {"rc": 0, "stdout": ""}

        with self.assertRaisesRegex(RuntimeError, "ASIC_DB KEYS"):
            self.module._known_task_fdb_absent(
                {"mh_leaf0": AsicFailureHost()},
                {"00:00:00:00:00:02"},
            )

    def test_static_task_mac_in_asic_db_is_not_treated_as_clean(self):
        class StaticAsicHost(FakeHost):
            hostname = "leaf0"

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if "ASIC_DB KEYS" in command:
                    return {
                        "rc": 0,
                        "stdout": (
                            'ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:'
                            '{"mac":"00:00:00:00:00:02","bvid":"oid:1"}'
                        ),
                    }
                return {"rc": 0, "stdout": ""}

        self.assertFalse(self.module._known_task_fdb_absent(
            {"mh_leaf0": StaticAsicHost()},
            {"00:00:00:00:00:02"},
        ))

    def test_stale_neighbor_and_static_proxy_are_not_clean(self):
        class StaleStateHost(FakeHost):
            hostname = "leaf0"

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if "/sys/class/net/Vlan10" in command:
                    return {"rc": 0, "stdout": ""}
                if command.startswith("ip neigh show dev Vlan10"):
                    return {"rc": 0, "stdout": "10.212.10.2 lladdr 00:00:00:00:00:02"}
                if "docker exec syncd sh -c" in command:
                    return {"rc": 0, "stdout": ""}
                if "bridge fdb show dev PortChannel100" in command:
                    return {
                        "rc": 0,
                        "stdout": "00:00:00:00:00:02 vlan 10 master static",
                    }
                return {"rc": 0, "stdout": ""}

        host = StaleStateHost()
        duts = {"mh_leaf0": host}
        self.assertFalse(
            self.module._known_task_neighbors_absent(duts, {10}))
        self.assertFalse(self.module._known_static_proxy_fdb_absent(
            duts,
            (("mh_leaf0", "00:00:00:00:00:02", "PortChannel100", 10),),
        ))

    def test_neighbor_flush_failure_aborts_clean_start(self):
        class FlushFailureHost(FakeHost):
            hostname = "leaf0"

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if "/sys/class/net/Vlan" in command:
                    return {"rc": 0, "stdout": ""}
                if command.startswith("sudo ip neigh flush"):
                    return {"rc": 5, "stderr": "flush failed"}
                return {"rc": 0, "stdout": ""}

        with self.assertRaisesRegex(RuntimeError, "ip neigh flush"):
            self.module.clear_evpn_mh_runtime_state(
                {"mh_leaf0": FlushFailureHost()}, self._topology())

    def test_static_proxy_delete_failure_aborts_clean_start(self):
        class DeleteFailureHost(FakeHost):
            hostname = "leaf0"

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if ("/sys/class/net/Vlan" in command
                        and "docker exec syncd" not in command):
                    return {"rc": 10, "stdout": ""}
                if "docker exec syncd sh -c" in command:
                    return {"rc": 0, "stdout": ""}
                if "bridge fdb show dev PortChannel100" in command:
                    return {
                        "rc": 0,
                        "stdout": "00:00:00:00:00:02 vlan 10 master static",
                    }
                if "bridge fdb del" in command:
                    return {"rc": 2, "stderr": "delete failed"}
                return {"rc": 0, "stdout": ""}

        host = DeleteFailureHost()
        with self.assertRaisesRegex(RuntimeError, "bridge fdb del"):
            self.module.clear_evpn_mh_runtime_state(
                {"mh_leaf0": host}, self._topology())
        self.assertFalse(any(
            "|| true" in command for command, _ in host.commands
        ))

    def test_stock_active_active_port_is_released_only_after_exact_proof(self):
        class StockPortHost(FakeHost):
            hostname = "leaf0"

            def __init__(self):
                super().__init__()
                self.keys = {
                    "VLAN_MEMBER|Vlan1000|Ethernet1",
                    "MUX_CABLE|Ethernet1",
                }

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if "CONFIG_DB EXISTS" in command:
                    key = command.split("EXISTS", 1)[1].strip(" '\"")
                    return {"rc": 0, "stdout": "1" if key in self.keys else "0"}
                if "CONFIG_DB HGET" in command and "cable_type" in command:
                    return {"rc": 0, "stdout": "active-active"}
                if "CONFIG_DB DEL" in command:
                    key = command.split("DEL", 1)[1].strip(" '\"")
                    self.keys.discard(key)
                    return {"rc": 0, "stdout": "1"}
                if "ACL_TABLE|*" in command:
                    return {"rc": 0, "stdout": ""}
                if command.startswith("sudo config vlan member del 1000"):
                    self.keys.discard("VLAN_MEMBER|Vlan1000|Ethernet1")
                    return {"rc": 0, "stdout": ""}
                return {"rc": 0, "stdout": ""}

        host = StockPortHost()
        self.module._prepare_single_homed_interface(host, "Ethernet1", {
            "stock_vlan": 1000,
            "stock_mux_cable_type": "active-active",
        })
        self.assertFalse(host.keys)
        commands = [command for command, _ in host.commands]
        self.assertIn(
            "sudo sonic-db-cli CONFIG_DB DEL 'MUX_CABLE|Ethernet1'",
            commands)
        self.assertIn(
            "sudo config vlan member del 1000 Ethernet1", commands)
        delete_index = commands.index(
            "sudo sonic-db-cli CONFIG_DB DEL 'MUX_CABLE|Ethernet1'")
        restart_index = commands.index("sudo systemctl restart caclmgrd")
        active_index = commands.index(
            "sudo systemctl is-active --quiet caclmgrd")
        self.assertLess(delete_index, restart_index)
        self.assertLess(restart_index, active_index)

    def test_stock_port_mismatch_fails_before_mutation(self):
        class WrongMuxHost(FakeHost):
            hostname = "leaf0"

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if "CONFIG_DB EXISTS" in command:
                    return {"rc": 0, "stdout": "1"}
                if "CONFIG_DB HGET" in command:
                    return {"rc": 0, "stdout": "active-standby"}
                return {"rc": 0, "stdout": ""}

        host = WrongMuxHost()
        with self.assertRaisesRegex(RuntimeError, "cable_type"):
            self.module._prepare_single_homed_interface(
                host, "Ethernet1", {
                    "stock_vlan": 1000,
                    "stock_mux_cable_type": "active-active",
                })
        self.assertFalse(any(
            "CONFIG_DB DEL" in command or "config vlan member del" in command
            for command, _ in host.commands
        ))

    def test_checkpoint_rollback_refreshes_mux_acl_before_health_proof(self):
        source = CONFTEST_PATH.read_text(encoding="utf-8")
        finalizer = source[source.index(
            'rollback = dut.shell(\n            "sudo config rollback'):
            source.index(
                'deleted = dut.shell(\n            "sudo config delete-checkpoint')]
        self.assertLess(
            finalizer.index("restart_caclmgrd(dut)"),
            finalizer.index("_checkpoint_runtime_ready"),
        )
        self.assertIn("restored MUX ACL rendering failed", finalizer)

    def test_caclmgrd_restart_fails_closed_when_service_is_inactive(self):
        class InactiveCaclHost(FakeHost):
            hostname = "leaf0"

            def shell(self, command, **kwargs):
                self.commands.append((command, kwargs))
                if "systemctl is-active" in command:
                    return {"rc": 3, "stdout": "inactive"}
                return {"rc": 0, "stdout": ""}

        with self.assertRaisesRegex(RuntimeError, "did not return active"):
            self.module.restart_caclmgrd(InactiveCaclHost())

    def test_configuration_uses_one_generic_path_for_both_segments(self):
        duts = {
            "mh_leaf0": types.SimpleNamespace(hostname="leaf0"),
            "mh_leaf1": types.SimpleNamespace(hostname="leaf1"),
        }
        interfaces = {
            "h1_leg0": {"interface": "Ethernet0"},
            "h1_leg1": {"interface": "Ethernet27"},
            "h2_leg0": {"interface": "Ethernet25"},
            "h2_leg1": {"interface": "Ethernet26"},
            "sh1": {"interface": "Ethernet1"},
        }
        topology = {
            "vtep_ip": {
                "mh_leaf0": "10.0.0.1", "mh_leaf1": "10.0.0.2",
                "remote_leaf": "10.0.0.3",
            },
            "l3vni_vlan": 30, "l3vni": 5030, "vrf": "Vrf01",
            "anycast_gateway_mac": "00:11:22:33:44:11",
            "remote_overlay_asn": 64600,
            "endpoints": {
                name: {
                    "gateway_ipv4": "10.212.10.10", "ipv4_prefixlen": 24,
                    "gateway_ipv6": "2001:db8:10::10", "ipv6_prefixlen": 64,
                }
                for name in ("h1", "h2", "sh1")
            },
            "single_homed_endpoints": {"sh1": {
                "dut_role": "mh_leaf0", "vlan": 10, "l2vni": 5010,
                "stock_vlan": 1000,
                "stock_mux_cable_type": "active-active",
            }},
            "ethernet_segments": {
                "es_h1": {
                    "endpoint": "h1",
                    "leaf_roles": ("mh_leaf0", "mh_leaf1"),
                    "ptf_member_roles": ("h1_leg0", "h1_leg1"),
                    "portchannel": "PortChannel105", "system_mac": "00:01",
                    "esi": "03:00:44:33:22:11:01:00:00:69",
                    "vlan": 10, "l2vni": 5010,
                },
                "es_h2": {
                    "endpoint": "h2",
                    "leaf_roles": ("mh_leaf0", "mh_leaf1"),
                    "ptf_member_roles": ("h2_leg0", "h2_leg1"),
                    "portchannel": "PortChannel100", "system_mac": "00:02",
                    "esi": "03:00:44:33:22:11:00:00:00:64",
                    "vlan": 10, "l2vni": 5010,
                },
            },
        }
        issued = []

        def record(dut, commands, tolerate_existing=False):
            issued.extend((dut.hostname, command) for command in commands)

        with patch.object(self.module, "uses_frrcfgd", return_value=True), \
                patch.object(self.module, "_run", side_effect=record), \
                patch.object(self.module, "portchannel_members", return_value=[]), \
                patch.object(self.module, "_unbind_port_from_acl_tables"), \
                patch.object(self.module, "_prepare_single_homed_interface") as prepare, \
                patch.object(self.module, "_reconcile_vlan_addresses"), \
                patch.object(self.module, "_configure_overlay_bgp"):
            self.module.configure_evpn_mh(duts, interfaces, topology)

        commands = [command for _, command in issued]
        self.assertIn("sudo config portchannel add PortChannel105", commands)
        self.assertIn("sudo config portchannel add PortChannel100", commands)
        self.assertIn(
            "sudo config portchannel member add PortChannel105 Ethernet0",
            commands)
        self.assertIn(
            "sudo config portchannel member add PortChannel105 Ethernet27",
            commands)
        self.assertIn(
            "sudo config portchannel member add PortChannel100 Ethernet25",
            commands)
        self.assertIn(
            "sudo config portchannel member add PortChannel100 Ethernet26",
            commands)
        self.assertIn(
            "sudo config interface evpn-esi add PortChannel105 auto-system-mac",
            commands)
        self.assertIn(
            "sudo config interface evpn-esi add PortChannel100 auto-system-mac",
            commands)
        prepare.assert_called_once_with(
            duts["mh_leaf0"], "Ethernet1",
            topology["single_homed_endpoints"]["sh1"])

    def test_segment_replay_uses_auto_system_mac_esi(self):
        dut = types.SimpleNamespace(
            hostname="leaf0", shell=lambda *args, **kwargs: {"rc": 0})
        issued = []

        def record(_dut, commands, tolerate_existing=False):
            issued.extend(commands)

        segment = {
            "portchannel": "PortChannel105",
            "system_mac": "00:44:33:22:11:01",
            "esi": "03:00:44:33:22:11:01:00:00:69",
        }
        with patch.object(self.module, "_run", side_effect=record):
            self.module._replay_segment(dut, segment)
        self.assertIn(
            "sudo config interface evpn-esi add PortChannel105 auto-system-mac",
            issued)


if __name__ == "__main__":
    unittest.main()

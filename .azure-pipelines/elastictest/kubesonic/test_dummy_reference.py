#!/usr/bin/env python3
"""Focused contract tests for the KubeSonic dummy container reference."""

import importlib
import importlib.util
import json
import sys
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(REPOSITORY_ROOT))

shared_minikube_spec = importlib.util.spec_from_file_location(
    "_kubesonic_shared_minikube",
    REPOSITORY_ROOT / "tests/common/minikube.py",
)
shared_minikube = importlib.util.module_from_spec(
    shared_minikube_spec
)
sys.modules[shared_minikube_spec.name] = shared_minikube
shared_minikube_spec.loader.exec_module(shared_minikube)

load_container_spec = importlib.import_module(
    "tests.k8s_container.container_spec"
).load_container_spec


def _unexpected_registry_load(*_args, **_kwargs):
    raise AssertionError("registry loading is not expected in these tests")


docker_helpers = types.ModuleType("tests.common.system_utils.docker")
docker_helpers.load_docker_registry_info = _unexpected_registry_load
sys.modules.setdefault(
    "tests.common.system_utils.docker",
    docker_helpers,
)
image_staging = importlib.import_module(
    "tests.k8s_container.image_staging"
)

common_package = types.ModuleType("tests.common")
common_package.__path__ = []
helpers_package = types.ModuleType("tests.common.helpers")
helpers_package.__path__ = []
dut_utils = types.ModuleType("tests.common.helpers.dut_utils")
dut_utils.creds_on_dut = lambda _duthost: {}
minikube = types.ModuleType("tests.common.minikube")
minikube.DEFAULT_PROFILE = "minikube"
minikube.MinikubeLockHeldError = RuntimeError


class _MinikubeError(RuntimeError):
    pass


def _select_minikube_duthost(duthosts, explicit_name=None):
    hosts = tuple(duthosts or ())
    if explicit_name:
        matches = tuple(
            host
            for host in hosts
            if host.hostname == explicit_name
        )
        if len(matches) != 1:
            raise _MinikubeError(
                "--minikube-dut must name exactly one selected DUT"
            )
        return matches[0]
    if len(hosts) != 1:
        raise _MinikubeError(
            "Minikube requires one selected DUT or --minikube-dut"
        )
    return hosts[0]


minikube.MinikubeError = _MinikubeError
minikube.select_minikube_duthost = _select_minikube_duthost
lifecycle = types.ModuleType("tests.k8s_container.lifecycle")


class _MinikubeCommandBoundary:
    @staticmethod
    def from_joined_dut(joined_dut):
        return joined_dut


lifecycle.MinikubeCommandBoundary = _MinikubeCommandBoundary
lifecycle.deploy_workload = None
sys.modules.setdefault("tests.common", common_package)
sys.modules.setdefault("tests.common.helpers", helpers_package)
sys.modules.setdefault("tests.common.helpers.dut_utils", dut_utils)
sys.modules.setdefault("tests.common.minikube", minikube)
sys.modules.setdefault("tests.k8s_container.lifecycle", lifecycle)
select_kubesonic_duthost = importlib.import_module(
    "tests.k8s_container.dut_selection"
).select_kubesonic_duthost
dummy_provider = importlib.import_module(
    "tests.k8s_container.dummy_provider"
)


SPEC_PATH = (
    REPOSITORY_ROOT
    / "tests/k8s_container/container_specs/dummy.yaml"
)
PROFILE_PATH = (
    REPOSITORY_ROOT
    / "tests/k8s_container/kubesonic_profiles/dummy-golden.json"
)
MANUAL_PIPELINE_PATH = (
    REPOSITORY_ROOT
    / ".azure-pipelines/elastictest/kubesonic/manual.yml"
)


class FakeDockerHost:
    def __init__(self, credential_cleanup_failures=()):
        self.facts = {"asic_type": "vs"}
        self.credential_cleanup_failures = set(
            credential_cleanup_failures
        )
        self.command_calls = []
        self.credential_cleanup_calls = 0

    def command(self, argv, **_kwargs):
        self.command_calls.append(tuple(argv))
        if argv[1:3] == ["image", "inspect"]:
            return {
                "rc": 0,
                "stdout": json.dumps([{"Id": "sha256:staged"}]),
            }
        if argv[1] == "ps":
            return {"rc": 0, "stdout": "runtime-container\n"}
        if argv[1] == "inspect":
            return {
                "rc": 0,
                "stdout": json.dumps(
                    [{"Image": "sha256:runtime-config"}]
                ),
            }
        raise AssertionError("unexpected docker command: {}".format(argv))

    def shell(self, command, **_kwargs):
        if command.startswith("install -d "):
            return {"rc": 0}
        if command.startswith("rm -rf -- "):
            self.credential_cleanup_calls += 1
            if (
                self.credential_cleanup_calls
                in self.credential_cleanup_failures
            ):
                return {"rc": 1}
            return {"rc": 0}
        raise AssertionError("unexpected shell command: {}".format(command))


class FakePhysicalDockerHost:
    def __init__(
        self,
        initial_images,
        credential_cleanup_failures=(),
    ):
        self.facts = {"asic_type": "mellanox"}
        self.images = dict(initial_images)
        self.credential_cleanup_failures = set(
            credential_cleanup_failures
        )
        self.command_calls = []
        self.login_calls = []
        self.credential_cleanup_calls = 0

    def command(self, argv, **_kwargs):
        self.command_calls.append(tuple(argv))
        if argv[:3] == ["docker", "image", "inspect"]:
            image = argv[3]
            image_id = self.images.get(image)
            if image_id is None:
                return {
                    "rc": 1,
                    "stderr": "Error response from daemon: "
                    "No such image: {}".format(image),
                }
            return {
                "rc": 0,
                "stdout": json.dumps([{"Id": image_id}]),
            }
        if argv[:3] == ["docker", "image", "rm"]:
            self.images.pop(argv[3], None)
            return {"rc": 0}
        if argv[:2] == ["docker", "tag"]:
            source, target = argv[2:4]
            source_id = self.images.get(source, source)
            self.images[target] = source_id
            return {"rc": 0}
        if (
            len(argv) >= 5
            and argv[0] == "env"
            and argv[1].startswith("DOCKER_CONFIG=")
            and argv[2:4] == ["docker", "pull"]
        ):
            image = argv[4]
            suffix = "pause" if "pause" in image else "private"
            self.images[image] = "sha256:staged-{}".format(suffix)
            return {"rc": 0}
        raise AssertionError("unexpected docker command: {}".format(argv))

    def shell(self, command, **_kwargs):
        if command.startswith("install -d "):
            return {"rc": 0}
        if command.startswith("rm -rf -- "):
            self.credential_cleanup_calls += 1
            if (
                self.credential_cleanup_calls
                in self.credential_cleanup_failures
            ):
                return {"rc": 1}
            return {"rc": 0}
        raise AssertionError("unexpected shell command: {}".format(command))

    def _run(self, module, **kwargs):
        self.login_calls.append((module, kwargs))
        return {"failed": False}


class FakeDummyHost:
    facts = {"platform": "x86_64-kvm"}

    def shell(self, command, **_kwargs):
        if command == "uname -m":
            return {"rc": 0, "stdout": "x86_64\n"}
        raise AssertionError("unexpected shell command: {}".format(command))

    def command(self, argv, **_kwargs):
        if argv[:3] == ["docker", "image", "inspect"]:
            return {
                "rc": 0,
                "stdout": json.dumps([{"Id": "sha256:expected"}]),
            }
        raise AssertionError("unexpected docker command: {}".format(argv))


class DummyReferenceTests(unittest.TestCase):
    def test_kubelet_node_ip_override_follows_live_configuration(self):
        duthost = SimpleNamespace(
            facts={"hwsku": "Arista-720DT-G48S4"},
        )
        for rc, expected in ((0, True), (1, False)):
            with self.subTest(rc=rc):
                runner = shared_minikube.AnsibleDutJoinRunner(duthost)
                runner.run = mock.Mock(
                    return_value=shared_minikube.HostResult(
                        rc,
                        "",
                        "",
                    )
                )

                self.assertIs(
                    runner.needs_node_ip_override(),
                    expected,
                )
                runner.run.assert_called_once_with(
                    "grep -q -- '--node-ip=::' "
                    "/etc/default/kubelet",
                    private=True,
                )

    def test_kubelet_node_ip_override_rejects_unreadable_config(self):
        runner = shared_minikube.AnsibleDutJoinRunner(
            SimpleNamespace(facts={})
        )
        runner.run = mock.Mock(
            return_value=shared_minikube.HostResult(
                2,
                "",
                "permission denied",
            )
        )

        with self.assertRaisesRegex(
            shared_minikube.MinikubeError,
            "configuration is unreadable",
        ):
            runner.needs_node_ip_override()

    def test_dummy_spec_matches_reviewed_container_contract(self):
        spec = load_container_spec(SPEC_PATH)

        self.assertEqual(spec.container_names, ("dummyk8s",))
        expected_images = {
            "x86_64": (
                "soniccr1.azurecr.io/docker-dummyk8s:"
                "kube-20260202-amd64"
            ),
            "armv7l": (
                "soniccr1.azurecr.io/docker-dummyk8s:"
                "kube-20260202-armhf"
            ),
            "aarch64": (
                "soniccr1.azurecr.io/docker-dummyk8s:"
                "kube-20260202-arm64"
            ),
        }
        for architecture, expected_image in expected_images.items():
            with self.subTest(architecture=architecture):
                self.assertEqual(
                    spec.golden_image("dummyk8s", architecture),
                    expected_image,
                )
        bundle = spec.build_bundle(
            name="dummy-golden",
            images={
                "dummyk8s": spec.golden_image("dummyk8s", "x86_64"),
            },
            runtime_values={"PLATFORM": "test-platform"},
        )
        container = bundle.containers[0]
        environment = {
            item.name: item.value for item in container.environment
        }

        self.assertEqual(environment["RUNTIME_OWNER"], "kube")
        self.assertEqual(environment["IMAGE_VERSION"], "20260202a.kube")
        self.assertEqual(
            container.readiness_probe.command,
            ("/bin/bash", "/usr/bin/readiness-probe.sh"),
        )
        self.assertEqual(
            {mount.mount_path for mount in container.mounts},
            {
                "/etc/sonic",
                "/var/run/dbus",
                "/var/run/redis",
                "/var/run/redis-chassis",
            },
        )

    def test_profiles_are_selector_only(self):
        expected_selectors = {
            "dummy-golden.json": ["k8s_container/test_dummy.py"],
            "gnmi-golden.json": ["k8s_container/test_gnmi.py"],
            "ndra-golden.json": ["k8s_container/test_ndra.py"],
            "nightly-default.json": ["k8s_container/test_gnmi.py"],
        }
        for name, selectors in expected_selectors.items():
            with self.subTest(name=name):
                profile = json.loads(
                    PROFILE_PATH.with_name(name).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    set(profile),
                    {"version", "description", "selectors"},
                )
                self.assertEqual(profile["version"], 2)
                self.assertEqual(profile["selectors"], selectors)

    def test_dummy_profile_is_manual_only(self):
        profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        nightly = json.loads(
            (
                PROFILE_PATH.with_name("nightly-default.json")
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(
            profile["selectors"],
            ["k8s_container/test_dummy.py"],
        )
        self.assertNotIn(
            "k8s_container/test_dummy.py",
            nightly["selectors"],
        )

    def test_manual_queue_accepts_only_pr_and_exact_testbed(self):
        pipeline = yaml.safe_load(
            MANUAL_PIPELINE_PATH.read_text(encoding="utf-8")
        )

        self.assertEqual(
            [parameter["name"] for parameter in pipeline["parameters"]],
            ["PR_ID", "TESTBED"],
        )
        resolver_step = next(
            step
            for step in pipeline["stages"][0]["jobs"][0]["steps"]
            if "resolve_manual_inputs.py" in step.get("script", "")
        )
        self.assertEqual(
            resolver_step["env"]["PR_ID"],
            "${{ parameters.PR_ID }}",
        )
        self.assertEqual(
            resolver_step["env"]["TESTBED"],
            "${{ parameters.TESTBED }}",
        )
        self.assertNotIn(
            "TEST_CONFIG",
            MANUAL_PIPELINE_PATH.read_text(encoding="utf-8"),
        )

    def test_kubesonic_dut_selection_fails_closed(self):
        hosts = (
            SimpleNamespace(hostname="dut-1"),
            SimpleNamespace(hostname="dut-2"),
        )
        implicit = SimpleNamespace(
            config=SimpleNamespace(
                getoption=lambda _name: None
            )
        )
        explicit = SimpleNamespace(
            config=SimpleNamespace(
                getoption=lambda _name: "dut-2"
            )
        )

        with self.assertRaisesRegex(
            pytest.fail.Exception,
            "requires one selected DUT",
        ):
            select_kubesonic_duthost(implicit, hosts)
        self.assertIs(
            select_kubesonic_duthost(explicit, hosts),
            hosts[1],
        )

    def test_runtime_image_identity_uses_docker_config_digest(self):
        host = FakeDockerHost()

        self.assertEqual(
            image_staging.runtime_image_id(
                host,
                "pod-uid",
                "dummyk8s",
            ),
            "sha256:runtime-config",
        )
        self.assertEqual(
            host.command_calls[0],
            (
                "docker",
                "ps",
                "-q",
                "--filter",
                "label=io.kubernetes.pod.uid=pod-uid",
                "--filter",
                "label=io.kubernetes.container.name=dummyk8s",
            ),
        )

    def test_dummy_provider_rejects_runtime_image_mismatch(self):
        @contextmanager
        def deployed_workload(*_args, **_kwargs):
            yield SimpleNamespace(pod_uid="pod-uid")

        joined = SimpleNamespace(node_name="dut-node")
        with mock.patch.object(
            dummy_provider,
            "deploy_workload",
            deployed_workload,
        ), mock.patch.object(
            dummy_provider,
            "runtime_image_id",
            return_value="sha256:unexpected",
        ), mock.patch.object(
            dummy_provider.MinikubeCommandBoundary,
            "from_joined_dut",
            return_value=joined,
        ):
            with self.assertRaisesRegex(
                pytest.fail.Exception,
                "different dummy image ID",
            ):
                with dummy_provider._deployed_dummy_workload(
                    FakeDummyHost(),
                    joined,
                ):
                    pass

    def test_docker_inspect_distinguishes_absence_from_failure(self):
        absent = mock.Mock()
        absent.command.return_value = {
            "rc": 1,
            "stderr": "Error response from daemon: No such image: missing",
        }
        unavailable = mock.Mock()
        unavailable.command.return_value = {
            "rc": 1,
            "stderr": "Cannot connect to the Docker daemon",
        }

        self.assertIsNone(
            image_staging._image_id(absent, "missing")
        )
        with self.assertRaisesRegex(
            pytest.fail.Exception,
            "Unable to inspect Docker image",
        ):
            image_staging._image_id(unavailable, "unknown")

    def test_physical_staging_pulls_tags_and_restores_images(self):
        private_image = (
            "soniccr1.azurecr.io/sonic/docker-dummyk8s:"
            "kube-20260202-amd64"
        )
        host = FakePhysicalDockerHost(
            {private_image: "sha256:before-private"}
        )
        registry = SimpleNamespace(
            host="soniccr1.azurecr.io",
            username="registry-user",
            password="registry-password",
        )

        with mock.patch.object(
            image_staging,
            "load_docker_registry_info",
            return_value=registry,
        ):
            with image_staging.stage_images(
                host,
                (private_image, image_staging.PAUSE_IMAGE),
            ):
                self.assertEqual(
                    host.images[private_image],
                    "sha256:staged-private",
                )
                self.assertEqual(
                    host.images[image_staging.PAUSE_IMAGE],
                    "sha256:staged-pause",
                )

        self.assertEqual(
            host.images,
            {private_image: "sha256:before-private"},
        )
        self.assertEqual(len(host.login_calls), 1)
        self.assertEqual(host.credential_cleanup_calls, 2)

    def test_credential_cleanup_error_does_not_preserve_dut(self):
        host = FakeDockerHost(
            credential_cleanup_failures=(2,)
        )

        with self.assertRaises(
            image_staging.ProviderCleanupError
        ) as caught:
            with image_staging.stage_images(
                host,
                ("example.invalid/dummy:1",),
            ):
                pass

        self.assertFalse(caught.exception.preserve_environment)

    def test_credential_cleanup_does_not_reclassify_primary_error(self):
        host = FakeDockerHost(
            credential_cleanup_failures=(2,)
        )
        primary_error = RuntimeError("test failed")

        with self.assertRaises(RuntimeError) as caught:
            with image_staging.stage_images(
                host,
                ("example.invalid/dummy:1",),
            ):
                raise primary_error

        self.assertIs(caught.exception, primary_error)
        self.assertFalse(
            getattr(caught.exception, "preserve_environment", False)
        )
        self.assertEqual(
            caught.exception.cleanup_errors,
            ("unable to remove temporary Docker credentials",),
        )

    def test_credential_cleanup_preserves_dut_only_after_two_failures(self):
        host = FakeDockerHost(
            credential_cleanup_failures=(1, 2)
        )

        with self.assertRaises(
            pytest.fail.Exception
        ) as caught:
            with image_staging.stage_images(
                host,
                ("example.invalid/dummy:1",),
            ):
                self.fail("test body must not run")

        self.assertTrue(caught.exception.preserve_environment)
        self.assertEqual(
            caught.exception.cleanup_errors,
            ("unable to remove temporary Docker credentials",),
        )

    def test_early_staging_failure_gets_two_cleanup_attempts(self):
        image = "soniccr1.azurecr.io/sonic/docker-dummyk8s:test"
        host = FakePhysicalDockerHost(
            {},
            credential_cleanup_failures=(1, 2),
        )
        registry = SimpleNamespace(
            host="soniccr1.azurecr.io",
            username="registry-user",
            password="registry-password",
        )
        primary_error = RuntimeError("pull failed")

        with mock.patch.object(
            image_staging,
            "load_docker_registry_info",
            return_value=registry,
        ), mock.patch.object(
            image_staging,
            "_pull_private_image",
            side_effect=primary_error,
        ):
            with self.assertRaises(RuntimeError) as caught:
                with image_staging.stage_images(
                    host,
                    (image,),
                ):
                    self.fail("test body must not run")

        self.assertIs(caught.exception, primary_error)
        self.assertTrue(caught.exception.preserve_environment)
        self.assertEqual(host.credential_cleanup_calls, 2)
        self.assertEqual(
            caught.exception.cleanup_errors,
            ("unable to remove temporary Docker credentials",),
        )

    def test_registry_loader_clears_credentials_before_error_escapes(self):
        credentials = {
            "sonicadmin_password": "admin-secret",
            "lab_admin_pass": "lab-secret",
            "docker_registry_password": "registry-secret",
            "fanout_admin_password": "fanout-secret",
        }

        def fail_loading(_duthost, raw_credentials):
            self.assertIs(raw_credentials, credentials)
            raise RuntimeError("registry load failed")

        with mock.patch.object(
            dut_utils,
            "creds_on_dut",
            return_value=credentials,
        ), mock.patch.object(
            image_staging,
            "load_docker_registry_info",
            side_effect=fail_loading,
        ):
            try:
                image_staging._load_staging_registry(object())
            except RuntimeError as error:
                traceback_locals = {}
                traceback = error.__traceback__
                while traceback is not None:
                    frame = traceback.tb_frame
                    if frame.f_code.co_name in (
                        "_load_staging_registry",
                        "fail_loading",
                    ):
                        traceback_locals[frame.f_code.co_name] = dict(
                            frame.f_locals
                        )
                    traceback = traceback.tb_next
            else:
                self.fail("registry loading must fail")

        self.assertEqual(credentials, {})
        self.assertNotIn(
            "credentials",
            traceback_locals["_load_staging_registry"],
        )
        rendered_locals = repr(traceback_locals)
        for secret in (
            "admin-secret",
            "lab-secret",
            "registry-secret",
            "fanout-secret",
        ):
            self.assertNotIn(secret, rendered_locals)


if __name__ == "__main__":
    unittest.main()

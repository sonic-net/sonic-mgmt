"""Minimal KubeSonic provider for the docker-dummyk8s reference test."""

import json
import shlex
import uuid
from contextlib import contextmanager

import pytest

from tests.common.minikube import DEFAULT_PROFILE
from tests.common.minikube import MinikubeLockHeldError
from tests.k8s_container.container_spec import SPEC_DIRECTORY
from tests.k8s_container.container_spec import load_container_spec
from tests.k8s_container.image_staging import normalized_image_id
from tests.k8s_container.image_staging import PAUSE_IMAGE
from tests.k8s_container.image_staging import runtime_image_id
from tests.k8s_container.image_staging import stage_images
from tests.k8s_container.lifecycle import deploy_workload
from tests.k8s_container.lifecycle import MinikubeCommandBoundary
from tests.k8s_container.workload import WorkloadBundle


pytest_plugins = ("tests.common.fixtures.minikube",)

SPEC_PATH = SPEC_DIRECTORY / "dummy.yaml"
CONTAINER_NAME = "dummyk8s"


def _option(request, name, default):
    try:
        return request.config.getoption(name)
    except ValueError:
        return default


def _selected_image(duthost, spec):
    machine = duthost.shell("uname -m", module_ignore_errors=True)
    architecture = machine.get("stdout", "").strip()
    if machine.get("rc", 1) != 0 or not architecture:
        pytest.fail(
            "unable to determine DUT architecture for the dummy image"
        )
    try:
        return spec.golden_image(CONTAINER_NAME, architecture)
    except ValueError as error:
        pytest.fail(str(error))


def _docker_image_id(duthost, image):
    result = duthost.command(
        argv=["docker", "image", "inspect", image],
        module_ignore_errors=True,
        verbose=False,
    )
    try:
        return json.loads(result.get("stdout", ""))[0]["Id"]
    except (ValueError, IndexError, KeyError, TypeError):
        pytest.fail(
            "Selected dummy image is not present or invalid: {}".format(
                shlex.quote(image)
            )
        )


@contextmanager
def _deployed_dummy_workload(duthost, joined_dut):
    spec = load_container_spec(SPEC_PATH)
    image = _selected_image(duthost, spec)
    platform = str(duthost.facts.get("platform", ""))
    if not platform:
        pytest.fail(
            "DUT platform is required for the dummy container family"
        )
    bundle = spec.build_bundle(
        name="dummy-golden",
        images={CONTAINER_NAME: image},
        runtime_values={"PLATFORM": platform},
    )
    bundle = WorkloadBundle(
        name=bundle.name,
        containers=bundle.containers,
        host_network=True,
        hostname="sonic",
    )
    expected_image_id = _docker_image_id(duthost, image)
    with deploy_workload(
        MinikubeCommandBoundary.from_joined_dut(joined_dut),
        bundle,
        "default",
        joined_dut.node_name,
        str(uuid.uuid4()),
    ) as workload:
        actual_image_id = runtime_image_id(
            duthost,
            workload.pod_uid,
            CONTAINER_NAME,
        )
        if normalized_image_id(
            actual_image_id
        ) != normalized_image_id(expected_image_id):
            pytest.fail(
                "Kubernetes started a different dummy image ID"
            )
        yield workload


@pytest.fixture(scope="module")
def kubernetes_dummy_workload(request, minikube_duthost):
    if _option(
        request,
        "--minikube-profile",
        DEFAULT_PROFILE,
    ) != DEFAULT_PROFILE:
        pytest.fail(
            "Kubernetes dummy image staging requires the default "
            "serialized Minikube profile"
        )
    vmhosts = tuple(request.getfixturevalue("vmhosts") or ())
    if len(vmhosts) != 1:
        pytest.fail(
            "Kubernetes dummy qualification requires exactly one "
            "associated test server"
        )
    try:
        minikube_cluster = request.getfixturevalue("minikube_cluster")
    except MinikubeLockHeldError as error:
        pytest.fail(
            "Minikube setup cannot use the associated test server: "
            "{}".format(error)
        )

    spec = load_container_spec(SPEC_PATH)
    image = _selected_image(minikube_duthost, spec)
    with minikube_cluster.joined_dut(minikube_duthost) as joined:
        try:
            with stage_images(
                minikube_duthost,
                (image, PAUSE_IMAGE),
            ):
                with _deployed_dummy_workload(
                    minikube_duthost,
                    joined,
                ) as workload:
                    yield workload
        except BaseException as error:
            cleanup_errors = tuple(getattr(error, "cleanup_errors", ()))
            preserve_environment = (
                getattr(error, "preserve_workload_dependencies", False)
                or getattr(error, "preserve_environment", False)
            )
            if cleanup_errors and preserve_environment:
                joined.mark_workload_unclean(
                    "provider cleanup failed: {}".format(
                        "; ".join(cleanup_errors)
                    )
                )
            raise

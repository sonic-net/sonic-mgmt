"""Reversible Docker image staging for KubeSonic workloads."""

import json
import logging
import shlex
import uuid
from contextlib import contextmanager

import pytest

from tests.common.system_utils.docker import load_docker_registry_info


logger = logging.getLogger(__name__)
PAUSE_IMAGE = "k8s.gcr.io/pause:3.5"
PAUSE_SOURCE_IMAGE = "publicmirror.azurecr.io/pause:3.5"


def _load_staging_registry(duthost):
    from tests.common.helpers.dut_utils import creds_on_dut

    credentials = creds_on_dut(duthost)
    try:
        return load_docker_registry_info(duthost, credentials)
    finally:
        credentials.clear()
        del credentials


class ProviderCleanupError(RuntimeError):
    def __init__(self, message, preserve_environment=True):
        super().__init__(message)
        self.cleanup_errors = (message,)
        self.preserve_environment = preserve_environment


def normalized_image_id(image_id):
    return image_id.rsplit("sha256:", 1)[-1]


def _image_id(host, image):
    result = host.command(
        argv=["docker", "image", "inspect", image],
        module_ignore_errors=True,
        verbose=False,
    )
    if result.get("rc", 1) != 0:
        detail = " ".join(
            str(result.get(field, "")).strip()
            for field in ("stderr", "stdout")
            if result.get(field)
        )
        if any(
            marker in detail.lower()
            for marker in ("no such image", "no such object")
        ):
            return None
        pytest.fail(
            "Unable to inspect Docker image {}: {}".format(
                image,
                detail or "docker exited with rc {}".format(
                    result.get("rc", 1)
                ),
            )
        )
    try:
        return json.loads(result.get("stdout", ""))[0]["Id"]
    except (ValueError, IndexError, KeyError, TypeError):
        pytest.fail(
            "Image inspection returned invalid JSON for {}".format(image)
        )


def runtime_image_id(host, pod_uid, container_name):
    result = host.command(
        argv=[
            "docker",
            "ps",
            "-q",
            "--filter",
            "label=io.kubernetes.pod.uid={}".format(pod_uid),
            "--filter",
            "label=io.kubernetes.container.name={}".format(container_name),
        ],
        module_ignore_errors=True,
        verbose=False,
    )
    container_ids = result.get("stdout", "").split()
    if result.get("rc", 1) != 0 or len(container_ids) != 1:
        pytest.fail(
            "Unable to resolve one Kubernetes {} runtime container".format(
                container_name
            )
        )
    inspection = host.command(
        argv=["docker", "inspect", container_ids[0]],
        module_ignore_errors=True,
        verbose=False,
    )
    try:
        return json.loads(inspection.get("stdout", ""))[0]["Image"]
    except (ValueError, IndexError, KeyError, TypeError):
        pytest.fail(
            "Kubernetes {} runtime inspection is invalid".format(
                container_name
            )
        )


def _registry_host(value):
    host = value.rstrip("/")
    return host[:-4] if host.endswith(":443") else host


def _tagged_image(image):
    last_slash = image.rfind("/")
    separator = image.rfind(":")
    if separator <= last_slash or "@" in image:
        pytest.fail(
            "KubeSonic image staging requires a version-pinned tag: "
            "{}".format(image)
        )
    registry_and_repository = image[:separator]
    registry, found, repository = registry_and_repository.partition("/")
    if not found:
        pytest.fail(
            "KubeSonic image staging requires an explicit registry: "
            "{}".format(image)
        )
    return registry, repository, image[separator + 1:]


def _dut_docker(duthost, docker_config, arguments):
    return duthost.command(
        argv=[
            "env",
            "DOCKER_CONFIG={}".format(docker_config),
            "docker",
        ]
        + list(arguments),
        module_ignore_errors=True,
        verbose=False,
    )


def _remove_docker_config(duthost, docker_config):
    try:
        result = duthost.shell(
            "rm -rf -- {0} && test ! -e {0}".format(
                shlex.quote(docker_config)
            ),
            module_ignore_errors=True,
            verbose=False,
        )
    except BaseException as error:
        return (
            "unable to remove temporary Docker credentials: "
            "{}".format(error)
        )
    if result.get("rc", 1) != 0:
        return "unable to remove temporary Docker credentials"
    return None


def _pull_private_image(
    duthost,
    docker_config,
    registry,
    image,
    logged_in,
):
    registry_name, repository, tag = _tagged_image(image)
    if _registry_host(registry.host) != _registry_host(registry_name):
        pytest.fail(
            "Registry credentials do not match {}".format(registry_name)
        )
    if registry_name not in logged_in:
        if not registry.username or not registry.password:
            pytest.fail(
                "Registry credentials are required for {}".format(
                    registry_name
                )
            )
        result = duthost._run(
            "community.docker.docker_login",
            registry_url=registry_name,
            username=registry.username,
            password=registry.password,
            config_path="{}/config.json".format(docker_config),
            reauthorize=True,
            module_ignore_errors=True,
            verbose=False,
        )
        if result.get("failed", True):
            pytest.fail(
                "Unable to authenticate to {}".format(registry_name)
            )
        logged_in.add(registry_name)
    result = _dut_docker(
        duthost,
        docker_config,
        ["pull", "{}/{}:{}".format(registry_name, repository, tag)],
    )
    if result.get("rc", 1) != 0:
        pytest.fail("Unable to pull {} on the DUT".format(image))


def _restore_image_reference(duthost, image, before_id, staged_id):
    current_id = _image_id(duthost, image)
    if current_id is None:
        if before_id is None:
            return None
        result = duthost.command(
            argv=["docker", "tag", before_id, image],
            module_ignore_errors=True,
            verbose=False,
        )
        restored_id = _image_id(duthost, image)
        if (
            result.get("rc", 1) != 0
            or restored_id is None
            or normalized_image_id(restored_id)
            != normalized_image_id(before_id)
        ):
            return "unable to restore missing image reference {}".format(
                image
            )
        return None
    if normalized_image_id(current_id) != normalized_image_id(staged_id):
        return "{} changed after staging; preserving it".format(image)
    if before_id is None:
        result = duthost.command(
            argv=["docker", "image", "rm", image],
            module_ignore_errors=True,
            verbose=False,
        )
        if (
            result.get("rc", 1) != 0
            or _image_id(duthost, image) is not None
        ):
            return "unable to remove added image reference {}".format(image)
        return None
    result = duthost.command(
        argv=["docker", "tag", before_id, image],
        module_ignore_errors=True,
        verbose=False,
    )
    restored_id = _image_id(duthost, image)
    if (
        result.get("rc", 1) != 0
        or restored_id is None
        or normalized_image_id(restored_id)
        != normalized_image_id(before_id)
    ):
        return "unable to restore image reference {}".format(image)
    return None


@contextmanager
def stage_images(duthost, images):
    docker_config = "/tmp/sonic-mgmt-k8s-docker-{}".format(uuid.uuid4())
    references = {}
    logged_in = set()
    registry = None
    primary_error = None
    credential_cleanup_attempts = 0
    credential_cleanup_failures = 0
    preloaded_only = duthost.facts.get("asic_type") == "vs"

    def remove_credentials():
        nonlocal credential_cleanup_attempts
        nonlocal credential_cleanup_failures
        credential_cleanup_attempts += 1
        cleanup_error = _remove_docker_config(
            duthost,
            docker_config,
        )
        if cleanup_error:
            credential_cleanup_failures += 1
        return cleanup_error

    try:
        duthost.shell(
            "install -d -m 0700 {}".format(
                shlex.quote(docker_config)
            ),
            module_ignore_errors=False,
            verbose=False,
        )
        for target in sorted(set(images)):
            if preloaded_only:
                target_id = _image_id(duthost, target)
                if target_id is None:
                    pytest.fail(
                        "KVM image must be preloaded: {}".format(target)
                    )
                references[target] = {
                    "before": target_id,
                    "staged": target_id,
                }
                continue
            source = (
                PAUSE_SOURCE_IMAGE if target == PAUSE_IMAGE else target
            )
            if target not in references:
                references[target] = {
                    "before": _image_id(duthost, target),
                    "staged": None,
                }
            if (
                target == PAUSE_IMAGE
                and references[target]["before"] is not None
            ):
                references[target]["staged"] = references[target]["before"]
                continue
            if source not in references:
                references[source] = {
                    "before": _image_id(duthost, source),
                    "staged": None,
                }
            if source == PAUSE_SOURCE_IMAGE:
                result = _dut_docker(
                    duthost,
                    docker_config,
                    ["pull", source],
                )
                if result.get("rc", 1) != 0:
                    pytest.fail(
                        "Unable to pull {} on the DUT".format(source)
                    )
            else:
                if registry is None:
                    registry = _load_staging_registry(duthost)
                _pull_private_image(
                    duthost,
                    docker_config,
                    registry,
                    source,
                    logged_in,
                )
            references[source]["staged"] = _image_id(duthost, source)
            if not references[source]["staged"]:
                pytest.fail("Pulled image is absent: {}".format(source))
            if target == source:
                continue
            result = duthost.command(
                argv=["docker", "tag", source, target],
                module_ignore_errors=True,
                verbose=False,
            )
            if result.get("rc", 1) != 0:
                pytest.fail(
                    "Unable to tag {} as {}".format(source, target)
                )
            references[target]["staged"] = _image_id(duthost, target)
            if (
                not references[target]["staged"]
                or normalized_image_id(references[target]["staged"])
                != normalized_image_id(references[source]["staged"])
            ):
                pytest.fail(
                    "Staged image identity differs for {}".format(target)
                )
        if remove_credentials():
            pytest.fail(
                "Unable to remove temporary Docker credentials "
                "before test execution"
            )
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors = []
        preserve_environment = False
        preserve = primary_error is not None and getattr(
            primary_error,
            "preserve_workload_dependencies",
            False,
        )
        if preserve:
            logger.error(
                "Staged image references retained because workload "
                "cleanup failed"
            )
        else:
            for image, identity in reversed(tuple(references.items())):
                try:
                    if identity["staged"] is None:
                        identity["staged"] = _image_id(duthost, image)
                    if (
                        identity["staged"] is None
                        or identity["staged"] == identity["before"]
                    ):
                        continue
                    cleanup_error = _restore_image_reference(
                        duthost,
                        image,
                        identity["before"],
                        identity["staged"],
                    )
                    if cleanup_error:
                        cleanup_errors.append(cleanup_error)
                        preserve_environment = True
                except BaseException as error:
                    cleanup_errors.append(
                        "unable to restore {}: {}".format(image, error)
                    )
                    preserve_environment = True
        while credential_cleanup_attempts < 2:
            cleanup_error = remove_credentials()
            if (
                cleanup_error
                and cleanup_error not in cleanup_errors
            ):
                cleanup_errors.append(cleanup_error)
        if credential_cleanup_failures == 2:
            preserve_environment = True
        if cleanup_errors:
            if primary_error is not None:
                logger.error(
                    "Image staging cleanup failed: %s",
                    "; ".join(cleanup_errors),
                )
                existing = tuple(
                    getattr(primary_error, "cleanup_errors", ())
                )
                setattr(
                    primary_error,
                    "cleanup_errors",
                    existing + tuple(cleanup_errors),
                )
                if preserve_environment:
                    setattr(
                        primary_error,
                        "preserve_environment",
                        True,
                    )
            else:
                raise ProviderCleanupError(
                    "Image staging cleanup failed: {}".format(
                        "; ".join(cleanup_errors)
                    ),
                    preserve_environment=preserve_environment,
                )

import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.system_utils.docker import load_docker_registry_info
from tests.common.system_utils.docker import download_image
from tests.upgrade_path.utilities import cleanup_prev_images
from tests.common.helpers.upgrade_helpers import install_sonic
from tests.common import reboot


logger = logging.getLogger(__name__)
SYSTEM_STABILIZE_MAX_TIME = 300
container_name_mapping = {
    "docker-sonic-telemetry": "telemetry",
    "docker-sonic-gnmi": "gnmi"
}


def parse_containers(container_string):
    containers = []
    container_versions = []
    container_names = []

    full_docker_images = container_string.split("|")
    if len(full_docker_images) == 0:
        pytest.fail("Missing or incorrect container string format")

    for docker_image in full_docker_images:
        name_version_pair = docker_image.split(":")
        if len(name_version_pair) != 2:
            pytest.fail("Incorrect container name + tags")
        name, version = name_version_pair
        if name == "" or version == "":
            pytest.fail("Empty container name + tags")
        containers.append(name)
        container_versions.append(version)

    for container in containers:
        container_name = container_name_mapping.get(container)
        if container_name is None:
            pytest.fail("No matching container name to docker image name")
        container_names.append(container_name)

    return containers, container_versions, container_names


def parse_os_versions(os_versions_string):
    os_versions = os_versions_string.split("|")

    if len(os_versions) == 0:
        pytest.fail("Missing or incorrect os version string format")

    return os_versions


def createImageList(os_versions, image_url_template_string):
    image_list = []

    if "<osversion>" not in image_url_template_string:
        pytest.fail("Invalid image_url_template_string")

    for os_version in os_versions:
        image_list.append(image_url_template_string.replace("<osversion>", os_version))

    return image_list


# TODO
def createTestcaseList(testcase_file):
    logger.info(f"Testcase file is {testcase_file}")
    return []


# TODO
def createParametersMapping(containers, parameters_file):
    logger.info(f"Containers are {containers}, parameters_file is {parameters_file}")
    return []


def os_upgrade(duthost, localhost, tbinfo, image_url):
    cleanup_prev_images(duthost)
    install_sonic(duthost, image_url, tbinfo)
    reboot(duthost, localhost)
    networking_uptime = duthost.get_networking_uptime().seconds
    timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 1)
    py_assert(wait_until(timeout, 5, 0, check_reboot_cause, duthost, upgrade_type),
              "Reboot cause {} did not match the trigger - {}".format(get_reboot_cause(duthost),
                                                                      upgrade_type))


def pull_run_dockers(duthost, creds, env):
    # TODO: ADD PARAMETERS TO THIS ZIP
    registry = load_docker_registry_info(duthost, creds)
    for container, version, name in zip(env.containers, env.containerVersions, env.containerNames):
        docker_image = f"{registry.host}/{container}:{version}"
        download_image(duthost, registry, container, version)
        if duthost.shell(f"docker run -d --name {name} {docker_image}", module_ignore_errors=True)['rc'] != 0:
            pytest.fail("Not able to run container using pulled image")

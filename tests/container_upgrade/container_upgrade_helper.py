import pytest
import logging
import json

from tests.common.utilities import wait_until, file_exists_on_dut
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.system_utils.docker import load_docker_registry_info
from tests.common.system_utils.docker import download_image
from tests.upgrade_path.utilities import cleanup_prev_images
from tests.common.helpers.upgrade_helpers import install_sonic
from tests.common.reboot import reboot


logger = logging.getLogger(__name__)

DOCKER_CONF_FILE = "/etc/systemd/system/docker.service.d/http-proxy.conf"
BACKUP_DOCKER_CONF_FILE = "/host/http-proxy.conf"

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


def createTestcaseList(testcase_file):
    with open(testcase_file, 'r') as file:
        data = json.load(file)
    testcases = data.get('testcases', [])
    return testcases


def createParametersMapping(containers, parameters_file):
    with open(parameters_file, 'r') as file:
        data = json.load(file)
    container_parameters = {container: details['parameters'] for container, details in data.items()}
    return container_parameters


def backup_docker_conf(duthost):
    py_assert(file_exists_on_dut(duthost, DOCKER_CONF_FILE), "No existing docker conf")
    logger.info("Backing up docker configuration file")
    duthost.shell("cp {} {}".format(DOCKER_CONF_FILE, BACKUP_DOCKER_CONF_FILE))


def fetch_docker_conf(duthost):
    py_assert(file_exists_on_dut(duthost, BACKUP_DOCKER_CONF_FILE), "No docker conf backup")
    logger.info("Getting docker configuration file")
    duthost.shell("cp {} {}".format(BACKUP_DOCKER_CONF_FILE, DOCKER_CONF_FILE))
    duthost.shell("systemctl daemon-reload")
    duthost.shell("systemctl restart docker.service")


def os_upgrade(duthost, localhost, tbinfo, image_url):
    cleanup_prev_images(duthost)
    backup_docker_conf(duthost)
    logger.info(f"ABOUT TO INSTALL IMAGE {image_url}")
    install_sonic(duthost, image_url, tbinfo)
    logger.info(f"About to reboot device")
    reboot(duthost, localhost)
    logger.info("After reboot")
    fetch_docker_conf(duthost)
    assert wait_until(300, 20, 20, duthost.critical_services_fully_started), \
                      "All critical services should be fully started!"


def pull_run_dockers(duthost, creds, env):
    logger.info("About to pull dockers")
    duthost.shell("docker images")
    registry = load_docker_registry_info(duthost, creds)
    for container, version, name in zip(env.containers, env.containerVersions, env.containerNames):
        logger.info(f"{container} {version} {name} {env.parameters[container]}")
        docker_image = f"{registry.host}/{container}:{version}"
        download_image(duthost, registry, container, version)
        duthost.shell("docker images")
        #if duthost.shell(f"docker run -d {parameters} --name {name} {docker_image}", module_ignore_errors=True)['rc'] != 0:
        #    pytest.fail("Not able to run container using pulled image")

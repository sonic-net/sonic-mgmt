"""docker contains utilities for interacting with Docker on the duthost."""

import collections
import logging

from tests.common import config_reload
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.broadcom_data import is_broadcom_device
from tests.common.mellanox_data import is_mellanox_device
from tests.common.errors import RunAnsibleModuleFail
from tests.common.cisco_data import is_cisco_device
from tests.common.innovium_data import is_innovium_device
from tests.common.helpers.constants import DEFAULT_NAMESPACE
logger = logging.getLogger(__name__)

_DockerRegistryInfo = collections.namedtuple("DockerRegistryInfo", "host username password")


class DockerRegistryInfo(_DockerRegistryInfo):
    """DockerRegistryInfo holds all the data needed to access a remote Docker registry.

    `host` is a required attribute, `username` and `password` can be added if the target registry
    requires authentication.

    Attributes:
        host (str): The remote host where the Docker registry is located.
        username (str): The username used to access the registry.
        password (str): The password used to access the registry.
    """
    pass


def load_docker_registry_info(duthost, creds):
    """Attempts to load Docker registry information.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.

    Raises:
        ValueError: If the registry information is missing from both the
            Ansible inventory and the registry file.

    Returns:
        DockerRegistryInfo: The registry information that was loaded.
    """
    host = creds.get("docker_registry_host")
    username = creds.get("docker_registry_username")
    password = creds.get("docker_registry_password")

    if not host:
        error_message = ("Could not find hostname for docker registry; "
                         "please check that the `docker_registry_host` ansible variable is defined.")
        logger.error(error_message)
        raise ValueError(error_message)

    return DockerRegistryInfo(host, username, password)


def download_image(duthost, registry, image_name, image_version="latest"):
    """Attempts to download the specified image from the registry.

    Args:
        duthost (SonicHost): The target device.
        registry (DockerRegistryInfo): The registry from which to pull the image.
        image_name (str): The name of the image to download.
        image_version (str): The version of the image to download.
    """
    try:
        if registry.username and registry.password:
            duthost.command("docker login {} -u {} -p {}".format(registry.host, registry.username, registry.password))
    except RunAnsibleModuleFail as e:
        error_message = ("Could not login to Docker registry. Please verify that your DNS server is reachable, "
                         "the specified registry is reachable, and your credentials are correct.")
        logger.error(error_message)
        logger.error("Error detail:\n{}".format(repr(e)))
        raise RuntimeError(error_message)

    try:
        duthost.command("docker pull {}/{}:{}".format(registry.host, image_name, image_version))
    except RunAnsibleModuleFail as e:
        error_message = ('Image "{}:{}" not found. Please verify that this image has been uploaded to the '
                         "specified registry.".format(image_name, image_version))
        logger.error(error_message)
        logger.error("Error detail:\n{}".format(repr(e)))
        raise RuntimeError(error_message)

def download_image_local(duthost):
    """Attempts to download the specified file from location.

        Args:
            duthost (SonicHost): The target device.
            image_name (str): The name of the image to download.
            image_version (str): The version of the image to download.
        """

    version_out = duthost.shell("cat /etc/sonic/sonic_version.yml | grep build_version")['stdout']
    ver = version_out.split(".")[1].split('-')
    pipeline = ver[0]
    branch_name = "-".join(ver[1:-1])
    swapfile = "docker-syncd-brcm-dnx-rpc.gz"
    local_file_path = '/' + swapfile
    url = "http://152.148.153.62/files/sonic/build/{}/{}/{}".format(branch_name, pipeline, swapfile)

    try:
        output = duthost.shell('curl --silent -O {} --output {}'.format(url, local_file_path))['rc']
        if output == 0:
            duthost.command('docker load -i ./{}'.format(swapfile))
    except RunAnsibleModuleFail as e:
        error_message = ("Unable to load the image.Please verify that your DNS server is reachable.")
        logger.error(error_message)
        logger.error("Error detail:\n{}".format(repr(e)))
        raise RuntimeError(error_message)


def tag_image(duthost, tag, image_name, image_version="latest"):
    """Applies the specified tag to a Docker image on the duthost.

    Args:
        duthost (SonicHost): The target device.
        tag (str): The tag to apply to the target image.
        image_name (str): The name of the image to tag.
        image_version (str): The version of the image to tag.
    """
    vendor_id = _get_vendor_id(duthost)
    if vendor_id in ['invm']:
        image_name = "docker-syncd-{}-rpc".format(vendor_id)

    duthost.command("docker tag {}:{} {}".format(image_name, image_version, tag))


def swap_syncd(duthost, creds, namespace=DEFAULT_NAMESPACE):
    """Replaces the running syncd container with the RPC version of it.

    This will download a new Docker image to the duthost and restart the swss 
    service.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """

    if namespace == DEFAULT_NAMESPACE and duthost.is_multi_asic:
        asics_list = duthost.asics
    else:
        asics_list = [duthost.asic_instance_from_namespace(namespace)]

    vendor_id = _get_vendor_id(duthost)

    docker_syncd_name = "docker-syncd-{}".format(vendor_id)

    if duthost.facts.get("platform_asic") == 'broadcom-dnx':
        docker_syncd_name = docker_syncd_name + "-dnx"

    docker_rpc_image = docker_syncd_name + "-rpc"

    # Force image download to go through mgmt network
    duthost.command("config bgp shutdown all")  

    for asic in asics_list:
        asic.stop_service("swss")
        asic.delete_container("syncd")

    # Set sysctl RCVBUF parameter for tests
    duthost.command("sysctl -w net.core.rmem_max=609430500")

    # Set sysctl SENDBUF parameter for tests
    duthost.command("sysctl -w net.core.wmem_max=609430500")

    for asic in asics_list:
        _perform_swap_syncd_shutdown_check(asic)

    is_syncdrpc_present_locally = duthost.command('docker image inspect '+docker_rpc_image, module_ignore_errors=True)['rc'] == 0

    if is_syncdrpc_present_locally:
        tag_image(
            duthost,
            "{}:latest".format(docker_syncd_name),
            docker_rpc_image,
            'latest'
        )
    elif "Nokia" in duthost.facts.get("hwsku"):
        download_image_local(duthost)
        tag_image(duthost, docker_syncd_name, docker_rpc_image, 'latest')
    else:
        registry = load_docker_registry_info(duthost, creds)
        download_image(duthost, registry, docker_rpc_image, duthost.os_version)

        tag_image(
            duthost,
            "{}:latest".format(docker_syncd_name),
            "{}/{}".format(registry.host, docker_rpc_image),
            duthost.os_version
        )

    logger.info("Reloading config and restarting swss...")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    for asic in asics_list:
        _perform_syncd_liveness_check(asic)


def restore_default_syncd(duthost, creds, namespace=DEFAULT_NAMESPACE):
    """Replaces the running syncd with the default syncd that comes with the image.

    This will restart the swss service.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """
    if namespace == DEFAULT_NAMESPACE and duthost.is_multi_asic:
        asics_list = duthost.asics
    else:
        asics_list = [duthost.asic_instance_from_namespace(namespace)]
    vendor_id = _get_vendor_id(duthost)

    docker_syncd_name = "docker-syncd-{}".format(vendor_id)

    if duthost.facts.get("platform_asic") == 'broadcom-dnx':
        docker_syncd_name = docker_syncd_name + "-dnx"

    for asic in asics_list:
        asic.stop_service("swss")
        asic.delete_container("syncd")

    tag_image(
        duthost,
        "{}:latest".format(docker_syncd_name),
        docker_syncd_name,
        duthost.os_version
    )

    logger.info("Reloading config and restarting swss...")
    config_reload(duthost)

    # Remove the RPC image from the duthost
    docker_rpc_image = docker_syncd_name + "-rpc"
    registry = load_docker_registry_info(duthost, creds)

    if "Nokia" in duthost.facts.get("hwsku"):
        duthost.command("docker rmi {}:latest".format(docker_rpc_image), module_ignore_errors=True)
    else:
        duthost.command("docker rmi {}/{}:{}".format(registry.host, docker_rpc_image, duthost.os_version),
                            module_ignore_errors=True)



def _perform_swap_syncd_shutdown_check(asic):
    def ready_for_swap():
        if any([
            asic.is_container_running("syncd"),
            asic.is_container_running("swss"),
        ]):
            return False

        return True

    shutdown_check = wait_until(30, 3, 0, ready_for_swap)
    pytest_assert(shutdown_check, "Docker and/or BGP failed to shut down in 30s")


def _perform_syncd_liveness_check(asic):
    def check_liveness():
        return asic.is_service_running("syncd", "syncd")

    liveness_check = wait_until(30, 1, 0, check_liveness)
    pytest_assert(liveness_check, "syncd crashed after swap_syncd")


def _get_vendor_id(duthost):
    if is_broadcom_device(duthost):
        vendor_id = "brcm"
    elif is_mellanox_device(duthost):
        vendor_id = "mlnx"
    elif is_cisco_device(duthost):
        vendor_id = "cisco"
    elif is_innovium_device(duthost):
        vendor_id = "invm"
    else:
        error_message = '"{}" does not currently support swap_syncd'.format(duthost.facts["asic_type"])
        logger.error(error_message)
        raise ValueError(error_message)

    return vendor_id

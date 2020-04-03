"""
    docker contains utilities for interacting with Docker on the DUT.
"""

import collections
import logging
import os
import time
import yaml

from common.broadcom_data import is_broadcom_device
from common.mellanox_data import is_mellanox_device

_LOGGER = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
SONIC_DOCKER_REGISTRY = os.path.join(_BASE_DIR, "../../../ansible/vars/docker_registry.yml")

_DockerRegistryInfo = collections.namedtuple('DockerRegistryInfo', 'host username password')
class DockerRegistryInfo(_DockerRegistryInfo):
    """
        DockerRegistryInfo holds all the data needed to access a remote Docker registry.

        Attributes:
            host (str): The remote host where the Docker registry is located.
            username (str): The username used to access the registry.
            password (str): The password used to access the registry.
    """
    pass

def parse_registry_file(registry_file):
    """
        parse_registry_file parses the provided file to produce a DockerRegistryInfo.

        See `SONIC_DOCKER_REGISTRY` for the expected format of this file.

        Args:
            registry_file (str): The name of the file holding the registry information.

        Raises:
            IOError: If the file cannot be opened for any reason.
            ValueError: If the provided file is missing any required fields.

        Returns:
            DockerRegistryInfo: The registry info from the registry file.
    """

    try:
        with open(registry_file) as contents:
            registry_vars = yaml.safe_load(contents)
    except IOError as err:
        _LOGGER.error("Failed to parse registry file \"%s\" (%s)", registry_file, err)
        raise

    host = registry_vars.get("docker_registry_host")
    username = registry_vars.get("docker_registry_username")
    password = registry_vars.get("docker_registry_password")

    if not host or not username or not password:
        error_message = "Registry file \"{}\" is missing login or hostname".format(registry_file)
        _LOGGER.error(error_message)
        raise ValueError(error_message)

    return DockerRegistryInfo(host, username, password)

def delete_container(dut, container_name):
    """
        delete_container attempts to delete the specified container from the DUT.

        Args:
            dut (SonicHost): The target device.
            container_name (str): The name of the container to delete.
    """

    dut.docker_container(name=container_name, state="absent")

def download_image(dut, registry, image_name, image_version="latest"):
    """
        download_image attempts to download the specified image from the registry.

        Args:
            dut (SonicHost): The target device.
            registry (DockerRegistryInfo): The registry from which to pull the image.
            image_name (str): The name of the image to download.
            image_version (str): The version of the image to download.
    """

    dut.docker_login(registry_url=registry.host,
                     username=registry.username,
                     password=registry.password)
    dut.docker_image(source="pull",
                     name="{}/{}:{}".format(registry.host, image_name, image_version))

def tag_image(dut, tag, image_name, image_version="latest"):
    """
        tag_image applies the specified tag to a Docker image on the DUT.

        Args:
            dut (SonicHost): The target device.
            tag (str): The tag to apply to the target image.
            image_name (str): The name of the image to tag.
            image_version (str): The version of the image to tag.
    """

    dut.docker_image(source="local",
                     name="{}:{}".format(image_name, image_version),
                     tag=tag)

def swap_syncd(dut, registry_file=SONIC_DOCKER_REGISTRY):
    """
        swap_syncd replaces the default syncd container on the DUT with an RPC version of it.

        This command will download a new Docker image to the DUT and restart the swss service.

        Args:
            dut (SonicHost): The target device.
            registry_file (str): The registry file describing where to download the RPC image.
    """

    if is_broadcom_device(dut):
        vendor_id = "brcm"
    elif is_mellanox_device(dut):
        vendor_id = "mlnx"
    else:
        error_message = "\"{}\" is not currently supported".format(dut.get_asic_type())
        _LOGGER.error(error_message)
        raise ValueError(error_message)

    docker_syncd_name = "docker-syncd-{}".format(vendor_id)
    docker_rpc_image = docker_syncd_name + "-rpc"

    dut.command("systemctl stop swss")
    delete_container(dut, "syncd")

    # Set sysctl RCVBUF parameter for tests
    dut.command("sysctl -w net.core.rmem_max=509430500")

    # TODO: Getting the base image version should be a common utility
    output = dut.command("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version")
    sonic_version = output["stdout_lines"][0].strip()

    registry = parse_registry_file(registry_file)
    download_image(dut, registry, docker_rpc_image, sonic_version)

    tag_image(dut,
              "{}/{}".format(registry.host, docker_syncd_name),
              docker_rpc_image,
              sonic_version)

    dut.command("systemctl start swss")
    _LOGGER.info("swss has been restarted, waiting 60 seconds to initialize...")
    time.sleep(60)

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

def load_docker_registry_info(dut):
    """
        Attempts to load Docker registry information.

        This method will first search for the registry in the `secret_vars` section
        of the Ansible inventory. If it's not found, then it will load the registry from
        the `SONIC_DOCKER_REGISTRY` file.

        Args:
            dut (SonicHost): The target device.

        Raises:
            IOError: If the registry file cannot be read.
            ValueError: If the registry information is missing from both the
                Ansible inventory and the registry file.

        Returns:
            DockerRegistryInfo: The registry information that was loaded.
    """

    # FIXME: In Ansible we're able to load the facts regardless of where they're
    # stored. We should figure out how to do this in pytest so the registry
    # location isn't hard-coded.
    registry_vars = dut.host.options['variable_manager'] \
                            ._hostvars.get(dut.hostname, {}) \
                            .get("secret_vars", {}) \
                            .get("docker_registry")

    if not registry_vars:
        _LOGGER.warning("Registry info not found in inventory, falling back to registry file")

        try:
            with open(SONIC_DOCKER_REGISTRY) as contents:
                registry_vars = yaml.safe_load(contents)
        except IOError as err:
            _LOGGER.error("Failed to parse registry file (%s)", err)
            raise

    host = registry_vars.get("docker_registry_host")
    username = registry_vars.get("docker_registry_username")
    password = registry_vars.get("docker_registry_password")

    if not host or not username or not password:
        error_message = "Missing registry hostname or login"
        _LOGGER.error(error_message)
        raise ValueError(error_message)

    return DockerRegistryInfo(host, username, password)

def delete_container(dut, container_name):
    """
        Attempts to delete the specified container from the DUT.

        Args:
            dut (SonicHost): The target device.
            container_name (str): The name of the container to delete.
    """

    dut.command("docker rm {}".format(container_name))

def download_image(dut, registry, image_name, image_version="latest"):
    """
        Attempts to download the specified image from the registry.

        Args:
            dut (SonicHost): The target device.
            registry (DockerRegistryInfo): The registry from which to pull the image.
            image_name (str): The name of the image to download.
            image_version (str): The version of the image to download.
    """

    dut.command("docker login {} -u {} -p {}".format(registry.host, registry.username, registry.password))
    dut.command("docker pull {}/{}:{}".format(registry.host, image_name, image_version))

def tag_image(dut, tag, image_name, image_version="latest"):
    """
        Applies the specified tag to a Docker image on the DUT.

        Args:
            dut (SonicHost): The target device.
            tag (str): The tag to apply to the target image.
            image_name (str): The name of the image to tag.
            image_version (str): The version of the image to tag.
    """

    dut.command("docker tag {}:{} {}".format(image_name, image_version, tag))

def swap_syncd(dut):
    """
        Replaces the running syncd container with the RPC version of it.

        This will download a new Docker image to the DUT and restart the swss service.

        Args:
            dut (SonicHost): The target device.
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

    registry = load_docker_registry_info(dut)
    download_image(dut, registry, docker_rpc_image, sonic_version)

    tag_image(dut,
              "{}:latest".format(docker_syncd_name),
              "{}/{}".format(registry.host, docker_rpc_image),
              sonic_version)

    dut.command("systemctl reset-failed swss")
    dut.command("systemctl start swss")

    _LOGGER.info("swss has been restarted, waiting 60 seconds to initialize...")
    time.sleep(60)

def restore_default_syncd(dut):
    """
        Replaces the running syncd with the default syncd that comes with the image.

        This will restart the swss service.

        Args:
            dut (SonicHost): The target device.
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

    dut.command("systemctl stop swss")
    delete_container(dut, "syncd")

    # TODO: Getting the base image version should be a common utility
    output = dut.command("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version")
    sonic_version = output["stdout_lines"][0].strip()

    tag_image(dut,
              "{}:latest".format(docker_syncd_name),
              docker_syncd_name,
              sonic_version)

    dut.command("systemctl reset-failed swss")
    dut.command("systemctl start swss")

    _LOGGER.info("swss has been restarted, waiting 60 seconds to initialize...")
    time.sleep(60)

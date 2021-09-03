import logging

import pytest

from thrift.transport import TSocket
from thrift.transport import TTransport

from tests.common import config_reload
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.broadcom_data import is_broadcom_device
from tests.common.mellanox_data import is_mellanox_device
from tests.common.system_utils.docker import load_docker_registry_info
from tests.common.system_utils.docker import download_image
from tests.common.system_utils.docker import tag_image
from natsort import natsorted

logger = logging.getLogger(__name__)

OPT_DIR = "/opt"
SAISERVER_SCRIPT = "saiserver.sh"
SCRIPTS_SRC_DIR = "scripts/"
SERVICES_LIST = ["swss", "syncd", "radv", "lldp", "dhcp_relay", "teamd", "bgp", "pmon"]
SAI_PRC_PORT = 9092
PTF_TEST_ROOT_DIR = "/tmp/sai_qualify"
DUT_WORKING_DIR = "/home/admin"
PORT_MAP_FILE_PATH = "/tmp/default_interface_to_front_map.ini"
SAI_TEST_CASE_DIR_ON_PTF = "tests"
SAI_TEST_REPORT_DIR_ON_PTF = "test_results"


def pytest_addoption(parser):
    # sai test options
    parser.addoption("--sai_test_dir", action="store", default=None, type=str, help="SAI repo folder where the tests will be run.")
    parser.addoption("--sai_test_report_dir", action="store", default=None, type=str, help="SAI test report directory on mgmt node.")


@pytest.fixture(scope="module")
def start_saiserver(duthost, creds, deploy_saiserver):
    """
        Starts SAIServer docker on DUT.
    """
    _start_saiserver_with_retry(duthost)
    yield
    _stop_saiserver(duthost)


@pytest.fixture(scope="module")
def deploy_saiserver(duthost, creds, stop_other_services, prepare_saiserver_script):
    _deploy_saiserver(duthost, creds)
    yield
    _remove_saiserver_deploy(duthost, creds)


@pytest.fixture(scope="module")
def stop_other_services(duthost):
    _stop_dockers(duthost)
    yield
    _reload_dut_config(duthost)


@pytest.fixture(scope="module")
def prepare_saiserver_script(duthost):
    _copy_saiserver_script(duthost)
    yield
    _delete_saiserver_script(duthost)


@pytest.fixture(scope="module")
def prepare_ptf_server(ptfhost, duthost):
    _create_sai_port_map_file(ptfhost, duthost)
    yield
    _delete_sai_port_map_file(ptfhost)


def _start_saiserver_with_retry(duthost):
    """
    Attempts to start a saisever with retry.

    Args:
        duthost (SonicHost): The target device.
    """
    saiserver_check_waiting_time = 140
    saiserver_restart_interval = 35

    logger.info("Attempting to start saiserver.")

    sai_ready = wait_until(saiserver_check_waiting_time, saiserver_restart_interval, _is_saiserver_restarted, duthost)
    pt_assert(sai_ready, "SaiServer failed to start in {}s".format(saiserver_check_waiting_time))
    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    logger.info("Successful in starting SaiServer at : {}:{}".format(dut_ip, SAI_PRC_PORT))


def _is_saiserver_restarted(duthost):
    """
    Checks if the saiserver started.
    
    Args:
        duthost (SonicHost): The target device.
    """
    connection_checking_time = 32
    connection_checking_interval = 4

    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    if _is_container_exists(duthost, 'saiserver'):
        logger.info("saiserver already exists, stop and remove it for a clear restart.")
        _stop_saiserver(duthost)
        duthost.shell("docker rm saiserver")
    _start_saiserver(duthost)
    rpc_ready = wait_until(connection_checking_time, connection_checking_interval, _is_rpc_server_ready, dut_ip)
    if not rpc_ready:
        logger.info("Failed to start up saiserver, stop it for a restart")
    return rpc_ready


def _is_rpc_server_ready(dut_ip):
    """
    Checks if the saiserver rpc service is running.

    Args:
        dut_ip (SonicHost): The target device ip address.
    """
    try:
        transport = TSocket.TSocket(dut_ip, SAI_PRC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        logger.info("Attempting to open rpc connection : {}:{}".format(dut_ip, SAI_PRC_PORT))
        transport.open()
        logger.info("Successful in creating rpc connection : {}:{}".format(dut_ip, SAI_PRC_PORT))
        return True
    except Exception as e: 
        logger.info("Attempting to open rpc connection failed : {}".format(e))
        return False
    finally:
        transport.close()


def _start_saiserver(duthost):
    """
    Starts the saiserver by a script.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Starting SAIServer docker for testing")      
    duthost.shell(OPT_DIR + "/" + SAISERVER_SCRIPT + " start")


def _stop_saiserver(duthost):
    """
    Stops the saiserver by a script.

    Args:
        duthost (SonicHost): The target device.
    """

    logger.info("Stopping the container 'saiserver'...")
    duthost.shell(OPT_DIR + "/" + SAISERVER_SCRIPT + " stop")


def _deploy_saiserver(duthost, creds):
    """Deploy a saiserver docker for SAI testing.

    This will stop the swss and syncd, then download a new Docker image to the duthost.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """
    vendor_id = _get_sai_running_vendor_id(duthost)

    docker_saiserver_name = "docker-saiserver-{}".format(vendor_id)
    docker_saiserver_image = docker_saiserver_name

    logger.info("Loading docker image: {} ...".format(docker_saiserver_image))
    registry = load_docker_registry_info(duthost, creds)
    download_image(duthost, registry, docker_saiserver_image, duthost.os_version)

    tag_image(
    duthost,
    "{}:latest".format(docker_saiserver_name),
    "{}/{}".format(registry.host, docker_saiserver_image),
    duthost.os_version
    )


def _stop_dockers(duthost):
    """
    Stops all the services in SONiC dut.

    Args:
        duthost (SonicHost): The target device.
    """
    for service in SERVICES_LIST:
        logger.info("Stopping service '{}' ...".format(service))
        duthost.stop_service(service)    

    _saiserver_services_env_check(duthost)


def _reload_dut_config(duthost):   
    """
    Reloads the dut config.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Reloading config and restarting other services ...")
    config_reload(duthost)


def _remove_saiserver_deploy(duthost, creds):
    """Reverts the saiserver docker's deployment.

    This will stop and remove the saiserver docker, then restart the swss and syncd.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Delete saiserver docker from DUT host '{0}'".format(duthost.hostname))
    vendor_id = _get_sai_running_vendor_id(duthost)
    container_name = "saiserver"

    docker_saiserver_name = "docker-{}-{}".format(container_name, vendor_id)
    docker_saiserver_image = docker_saiserver_name

    logger.info("Cleaning the SAI Testing env ...")
    registry = load_docker_registry_info(duthost, creds)
    duthost.delete_container(container_name)    

    logger.info("Removing the image '{}'...".format(docker_saiserver_image))
    duthost.shell("docker image rm {}".format(docker_saiserver_image))
    duthost.command(
        "docker rmi {}/{}:{}".format(registry.host, docker_saiserver_image, duthost.os_version),
        module_ignore_errors=True
    )


def _copy_saiserver_script(duthost):
    """
        Copys script for controlling saiserver docker.

        Args:
            duthost (AnsibleHost): device under test

        Returns:
            None
    """
    logger.info("Copy saiserver script to DUT: '{0}'".format(duthost.hostname))
    duthost.copy(src=os.path.join(SCRIPTS_SRC_DIR, SAISERVER_SCRIPT), dest=OPT_DIR)
    duthost.shell("sudo chmod +x " + OPT_DIR + "/" + SAISERVER_SCRIPT)


def _delete_saiserver_script(duthost):
    """
    Deletes the saiserver script from dut.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Delete saiserver script from DUT host '{0}'".format(duthost.hostname))
    duthost.file(path=os.path.join(OPT_DIR, SAISERVER_SCRIPT), state="absent")


def _saiserver_services_env_check(duthost):
    """
    Checks if services that impact saiserver have been stopped.

    Args:
        duthost (SonicHost): The target device.
    """
    running_services = []
    def ready_for_saiserver():
        for service in SERVICES_LIST:
            if _is_container_running(duthost, service):
                running_services.append(service)
        if running_services:
            return False
        return True

    shutdown_check = wait_until(20, 4, ready_for_saiserver)
    if running_services:
        format_list = ['{:>1}' for item in running_services] 
        servers = ','.join(format_list)
        pt_assert(shutdown_check, "Docker {} failed to shut down in 20s".format(servers.format(*running_services)))


def _is_container_running(duthost, container_name):
    """
    Checks if the required container is running in DUT.

    Args:
        duthost (SonicHost): The target device.
        container_name: the required container's name.
    """
    try:
        result = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
        return result["stdout_lines"][0].strip() == "true"
    except Exception as e:
        logger.info("Cannot get container '{0}' running state".format(duthost.hostname))
    return False


def _is_container_exists(duthost, container_name):
    """
    Checks if the required container is running in DUT.

    Args:
        duthost (SonicHost): The target device.
        container_name: the required container's name.
    """
    try:
        result = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
        return bool(result["stdout_lines"][0].strip())
    except Exception as e:
        logger.info("Cannot get container '{0}' running state".format(duthost.hostname))
    return False


def _get_sai_running_vendor_id(duthost):
    """
    Get the vendor id.

    Args:
        duthost (SonicHost): The target device.
    """
    if is_broadcom_device(duthost):
        vendor_id = "brcm"
    elif is_mellanox_device(duthost):
        vendor_id = "mlnx"
    else:
        error_message = '"{}" does not currently support saitest'.format(duthost.facts["asic_type"])
        logger.error(error_message)
        raise ValueError(error_message)

    return vendor_id


def _create_sai_port_map_file(ptfhost, duthost):
    """
    Create port mapping file on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
        duthost (SonicHost): The target device.
    """

    logger.info("Creating {0} for SAI test on PTF server.".format(PORT_MAP_FILE_PATH))
    intfInfo = duthost.show_interface(command = "status")['ansible_facts']['int_status']
    portList = natsorted([port for port in intfInfo if port.startswith('Ethernet')])

    with open(PORT_MAP_FILE_PATH, 'w') as file:
        file.write("# ptf host interface @ switch front port name\n")
        file.writelines(
            map(
                    lambda (index, port): "{0}@{1}\n".format(index, port),
                    enumerate(portList)
                )
            )

    ptfhost.copy(src=PORT_MAP_FILE_PATH, dest="/tmp")


def _delete_sai_port_map_file(ptfhost):
    """
    Delete port mapping file on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Deleting {0} file.".format(PORT_MAP_FILE_PATH))
    ptfhost.file(path=PORT_MAP_FILE_PATH, state="absent")


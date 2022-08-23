import logging

import pytest
import time

from thrift.transport import TSocket
from thrift.transport import TTransport

from tests.common import config_reload
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.broadcom_data import is_broadcom_device
from tests.common.mellanox_data import is_mellanox_device
from tests.common.barefoot_data import is_barefoot_device
from tests.common.system_utils.docker import load_docker_registry_info
from tests.common.system_utils.docker import download_image
from tests.common.system_utils.docker import tag_image
from tests.common.reboot import REBOOT_TYPE_SAI_WARM
from tests.common.reboot import reboot
from natsort import natsorted

logger = logging.getLogger(__name__)

OPT_DIR = "/opt"
USR_BIN_DIR = "/usr/bin"
SAISERVER_SCRIPT = "prepare_saiserver_service.sh"
SERVICES_SCRIPT = "all_service.sh"
WARMBOOT_SCRIPT = "sai_warmboot.sh"
WARMBOOT_PROFILE_SCRIPT = "sai_warm_profile.sh"
SAI_SCRIPTS = [SAISERVER_SCRIPT, SERVICES_SCRIPT, WARMBOOT_SCRIPT, WARMBOOT_PROFILE_SCRIPT]
SCRIPTS_SRC_DIR = "scripts/sai_qualify/"
SERVICES_LIST = ["swss", "syncd", "radv", "lldp", "dhcp_relay", "teamd", "bgp", "pmon", "telemetry", "acms"]
SAI_PRC_PORT = 9092
SAI_TEST_CONTAINER_WARM_UP_IN_SEC = 5
IS_TEST_ENV_FAILED = False
WARM_TEST_DIR = "warm_boot"
WARM_TEST_ARGS = ";test_reboot_mode='warm'"
WARM_TEST_SETUP = ";test_reboot_stage='setup'"
WARM_TEST_STARTING = ";test_reboot_stage='starting'"
WARM_TEST_POST = ";test_reboot_stage='post'"
WARM_TEST_STAGES = [WARM_TEST_SETUP, WARM_TEST_STARTING, WARM_TEST_POST]
SONIC_SSH_PORT  = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'


#PTF_TEST_ROOT_DIR is the root folder for SAI testing
#DUT_WORKING_DIR is the working folder of DUT
PTF_TEST_ROOT_DIR = "/tmp/sai_qualify"
DUT_WORKING_DIR = "/home/admin"


#These paths are for the SAI cases/results
SAI_TEST_CONMUN_CASE_DIR_ON_PTF = "/tmp/sai_qualify/tests"
SAI_TEST_PTF_SAI_CASE_DIR_ON_PTF = "/tmp/sai_qualify/ptf"
SAI_TEST_SAI_CASE_DIR_ON_PTF = "/tmp/sai_qualify/sai_test"
SAI_TEST_REPORT_DIR_ON_PTF = "/tmp/sai_qualify/test_results"
SAI_TEST_REPORT_TMP_DIR_ON_PTF = "/tmp/sai_qualify/test_results_tmp"
SAISERVER_CONTAINER = "saiserver"
SYNCD_CONATINER = "syncd"

PORT_MAP_FILE_PATH = "/tmp/default_interface_to_front_map.ini"
DX010_PORT_MAP = "--interface '0-0@eth20' --interface '0-1@eth21' --interface '0-2@eth22' --interface '0-3@eth23' --interface '0-4@eth24' --interface '0-5@eth25' --interface '0-6@eth26' --interface '0-7@eth27' --interface '0-8@eth4' --interface '0-9@eth5' --interface '0-10@eth6' --interface '0-11@eth7' --interface '0-12@eth8' --interface '0-13@eth9' --interface '0-14@eth10' --interface '0-15@eth11' --interface '0-16@eth0' --interface '0-17@eth1' --interface '0-18@eth2' --interface '0-19@eth3' --interface '0-20@eth12' --interface '0-21@eth13' --interface '0-22@eth14' --interface '0-23@eth15' --interface '0-24@eth16' --interface '0-25@eth17' --interface '0-26@eth18' --interface '0-27@eth19' --interface '0-28@eth28' --interface '0-29@eth29' --interface '0-30@eth30' --interface '0-31@eth31'"


SAI_TEST_CTNR_CHECK_TIMEOUT_IN_SEC = 140
SAI_TEST_CTNR_RESTART_INTERVAL_IN_SEC = 35
RPC_RESTART_INTERVAL_IN_SEC = 32
RPC_CHECK_INTERVAL_IN_SEC = 4


def pytest_addoption(parser):
    """
    Parse the pytest input parameters

    Args:
        parser: pytest parameter paser.
    """

    # sai test options
    parser.addoption("--sai_test_dir", action="store", default=None, type=str, help="SAI repo folder where the tests will be run.")
    parser.addoption("--sai_test_report_dir", action="store", default=None, type=str, help="SAI test report directory on mgmt node.")
    parser.addoption("--sai_test_container", action="store", default="saiserver", type=str, help="SAI test container, saiserver or syncd.")
    parser.addoption("--sai_test_keep_test_env", action="store_true", default=False, help="SAI test debug options. If keep the test environment in DUT and PTF.")
    parser.addoption("--enable_ptf_sai_test", action="store_true", help="Trigger PTF-SAI test. If enable PTF-SAI testing or not, true or false.")
    parser.addoption("--enable_warmboot_test", action="store_true", default=False, help="Trigger WARMBOOT test. If enable WARMBOOT testing or not, true or false.")
    parser.addoption("--enable_sai_test", action="store_true", help="Trigger SAI test. If enable SAI T0 testing or not, true or false.")
    parser.addoption("--sai_port_config_file", action="store", default=None, type=str, help="SAI test port config file to map the relationship between lanes and interface.")
    parser.addoption("--always_stop_sai_test_container", action="store_true", help="If always stop the container after one test or not, true or false.")


@pytest.fixture(scope="module")
def start_sai_test_container(duthost, creds, deploy_sai_test_container, request):
    """
    Starts sai test container docker on DUT.

    Args:
        duthost (SonicHost): The target device.        
        creds (dict): Credentials used to access the docker registry.
        deploy_sai_test_container: The container name for sai testing on DUT.
        request: Pytest request. 
    """
    logger.info("sai_test_keep_test_env {}".format(request.config.option.sai_test_keep_test_env))
    logger.info("Starting sai test container {}".format(get_sai_test_container_name(request)))
    start_sai_test_conatiner_with_retry(duthost, get_sai_test_container_name(request))
    yield
    logger.info("Stopping and removing sai test container {}".format(get_sai_test_container_name(request)))
    if not request.config.option.sai_test_keep_test_env:
        stop_and_rm_sai_test_container(duthost, get_sai_test_container_name(request))


#TODO add a fixture after this fixture to remove other service script
@pytest.fixture(scope="module")
def deploy_sai_test_container(duthost, creds, stop_other_services, request):
    """
    Deploys a sai test container.
    
    Args:
        duthost (SonicHost): The target device.        
        creds (dict): Credentials used to access the docker registry.
        stop_other_services: Service list which will be stopped.
        request: Pytest request.
    """
    container_name = request.config.option.sai_test_container
    prepare_sai_test_container(duthost, creds, container_name, request)
    yield
    if not request.config.option.sai_test_keep_test_env:
        revert_sai_test_container(duthost, creds, container_name, request)


@pytest.fixture(scope="module")
def stop_other_services(duthost, prepare_saiserver_script, request):
    """
    Stop services which are not needed in sai test.

    Args:
        duthost (SonicHost): The target device.
        prepare_saiserver_script: Script uses to prepare the saiserver.
        request: Pytest request.
    """
    stop_dockers(duthost)
    yield
    if not request.config.option.sai_test_keep_test_env:
        reload_dut_config(duthost)


@pytest.fixture(scope="module")
def prepare_saiserver_script(duthost, request):
    """
    Prepare the saiserver script.

    Args:
        duthost (SonicHost): The target device.
        request: Pytest request.
    """
    __copy_sai_qualify_script(duthost)
    #TODO prepare the saiserver service script here
    yield
    if not request.config.option.sai_test_keep_test_env:
        #TODO remove the prepared saiserver service script here
        __delete_sai_qualify_script(duthost)


@pytest.fixture(scope="module")
def prepare_ptf_server(ptfhost, duthost, request):
    """
    Prepare the PTF Server.

    Args:
        ptfhost: ptf oject
        duthost (SonicHost): The target device.
        request: Pytest request.
    """
    update_saithrift_ptf(request, ptfhost)
    __create_sai_port_map_file(ptfhost, duthost)
    yield
    if not request.config.option.sai_test_keep_test_env:
        __delete_sai_port_map_file(ptfhost)


@pytest.fixture(scope="module")
def create_sai_test_interface_param(duthost):
    """
    Create port interface list.

    Args:
        duthost (SonicHost): The target device.
    """
    port_numbers = len(__create_sai_test_interface_info(duthost))
    logger.info("Creating {} port interface list".format(port_numbers))
    interfaces_list = []
    
    for port_number in range(port_numbers):
        interface_tmp = "\'0-{0}@eth{0}\'".format(port_number)
        interfaces_list.append(interface_tmp)
    interfaces_para = " --interface ".join(interfaces_list)
    interfaces_para = "--interface " + interfaces_para
    return interfaces_para


def prepare_sai_test_container(duthost, creds, container_name, request):
    """
    Prepare the sai test container.
    
    Args:
        duthost (SonicHost): The target device.        
        creds (dict): Credentials used to access the docker registry.
        container_name: The container name for sai testing on DUT.
        request: Pytest request.
    """
    logger.info("Preparing {} docker as a sai test container.".format(container_name))
    if container_name == SYNCD_CONATINER:
        __deploy_syncd_rpc_as_syncd(duthost, creds)
    else:
        __deploy_saiserver(duthost, creds, request)
        logger.info("Prepare saiserver.sh")
        cmd = "{}/{} -v {}".format(USR_BIN_DIR, SAISERVER_SCRIPT, get_sai_thrift_version(request))
        logger.info("Prepare saiserver with command: {}".format(cmd))
        duthost.shell(cmd)
        #Prepare warmboot
        if request.config.option.enable_warmboot_test:
            saiserver_warmboot_config(duthost, "init")
            duthost.shell(USR_BIN_DIR + "/" + container_name + ".sh" + " stop")
            duthost.shell(USR_BIN_DIR + "/" + container_name + ".sh" + " start")


def revert_sai_test_container(duthost, creds, container_name, request):
    """
    Reverts the sai test container.

    Args:
        duthost (SonicHost): The target device.        
        creds (dict): Credentials used to access the docker registry.
        container_name: The container name for sai testing on DUT.
        request: Pytest request.
    """
    logger.info("Reverting sai test container: [{}].".format(container_name))
    if container_name == SYNCD_CONATINER:
        __restore_default_syncd(duthost, creds)
    else:
        #Prepare warmboot
        if request.config.option.enable_warmboot_test:
            saiserver_warmboot_config(duthost, "restore")
        __remove_saiserver_deploy(duthost, creds, request)


def get_sai_test_container_name(request):
    """
    Get the SAI Test container name base on the pytest parameter 'sai_test_container'

    Args:
        request: Pytest request.
    """

    container_name = request.config.option.sai_test_container
    if container_name == SAISERVER_CONTAINER:
        return SAISERVER_CONTAINER
    else:
        return SYNCD_CONATINER


def get_sai_thrift_version(request):
    """
    Get the SAI thrift version base on the pytest test mode.

    In current implementation, it will use v2 saithrift when:
        enable_ptf_sai_test
        enable_warmboot_test
        enable_sai_test

    Args:
        request: Pytest request.
    """
    if request.config.option.enable_ptf_sai_test \
        or request.config.option.enable_warmboot_test \
        or request.config.option.enable_sai_test:
        return "v2"
    else:
        return ""

def start_sai_test_conatiner_with_retry(duthost, container_name):
    """
    Attempts to start a sai test container with retry.

    Args:
        duthost (SonicHost): The target device.
        container_name: The container name for sai testing on DUT.
    """

    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    logger.info("Checking the PRC connection before starting the {}.".format(container_name))
    rpc_ready = wait_until(1, 1, 0, __is_rpc_server_ready, dut_ip)
    
    if not rpc_ready:
        logger.info("Attempting to start {}.".format(container_name))
        sai_ready = wait_until(SAI_TEST_CTNR_CHECK_TIMEOUT_IN_SEC, SAI_TEST_CTNR_RESTART_INTERVAL_IN_SEC, 0, __is_sai_test_container_restarted, duthost, container_name)
        pt_assert(sai_ready, "[{}] sai test container failed to start in {}s".format(container_name, SAI_TEST_CTNR_CHECK_TIMEOUT_IN_SEC))
        logger.info("Waiting for another {} second for sai test container warm up.".format(SAI_TEST_CONTAINER_WARM_UP_IN_SEC))
        time.sleep(SAI_TEST_CONTAINER_WARM_UP_IN_SEC)
        logger.info("Successful in starting {} at : {}:{}".format(container_name, dut_ip, SAI_PRC_PORT))
    else:
        logger.info("PRC connection already set up before starting the {}.".format(container_name))


def stop_and_rm_sai_test_container(duthost, container_name):
    """
    Stops the sai test container by a script.

    Args:
        duthost (SonicHost): The target device.
        container_name: The container name for sai testing on DUT.
    """
    logger.info("Stopping the container '{}'...".format(container_name))
    duthost.shell(USR_BIN_DIR + "/" + container_name + ".sh" + " stop")
    duthost.delete_container(container_name)


def __is_sai_test_container_restarted(duthost, container_name):
    """
    Checks if the sai test container started.
    
    Args:
        duthost (SonicHost): The target device.
        container_name: The container name for sai testing on DUT.
    """

    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    if __is_container_exists(duthost, container_name):
        logger.info("{} already exists, stop and remove it for a clear restart.".format(container_name))
        stop_and_rm_sai_test_container(duthost, container_name)
    __start_sai_test_container(duthost, container_name)
    rpc_ready = wait_until(RPC_RESTART_INTERVAL_IN_SEC, RPC_CHECK_INTERVAL_IN_SEC, 0, __is_rpc_server_ready, dut_ip)
    if not rpc_ready:
        logger.info("Failed to start up {} for sai testing on DUT, stop it for a restart".format(container_name))
    return rpc_ready


def __is_rpc_server_ready(dut_ip):
    """
    Checks if the sai test container rpc service is running.

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
    except Exception: 
        logger.info("Failed to open rpc connection.")
        return False
    finally:
        transport.close()


def __start_sai_test_container(duthost, container_name):
    """
    Starts the sai test container by a script.

    Args:
        duthost (SonicHost): The target device.
        container_name: The container name for sai testing on DUT.
    """
    logger.info("Starting {} docker for testing".format(container_name))      
    duthost.shell(USR_BIN_DIR + "/" + container_name + ".sh" + " start")


def __deploy_saiserver(duthost, creds, request):
    """
    Deploy a saiserver docker for SAI testing.

    This will stop the swss and syncd, then download a new Docker image to the duthost.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """
    vendor_id = get_sai_running_vendor_id(duthost)
    
    docker_saiserver_name = "docker-saiserver{}-{}".format(get_sai_thrift_version(request), vendor_id)
    docker_saiserver_image = docker_saiserver_name
    # Skip download step if image has existed
    if __is_image_exists(duthost, docker_saiserver_image):
        logger.info("The image {} has existed".format(docker_saiserver_image))   
        return

    # Force image download to go through mgmt network
    duthost.command("config bgp shutdown all")  

    # Set sysctl RCVBUF parameter for tests
    duthost.command("sysctl -w net.core.rmem_max=609430500")

    # Set sysctl SENDBUF parameter for tests
    duthost.command("sysctl -w net.core.wmem_max=609430500")

    logger.info("Loading docker image: {} ...".format(docker_saiserver_image))
    registry = load_docker_registry_info(duthost, creds)
    download_image(duthost, registry, docker_saiserver_image, duthost.os_version)

    tag_image(
    duthost,
    "{}:latest".format(docker_saiserver_name),
    "{}/{}".format(registry.host, docker_saiserver_image),
    duthost.os_version
    )


def __deploy_syncd_rpc_as_syncd(duthost, creds):
    """
    Replaces the running syncd container with the RPC version of it.

    This will download a new Docker image to the duthost. 
    service.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """
    vendor_id = get_sai_running_vendor_id(duthost)

    docker_syncd_name = "docker-{}-{}".format(SYNCD_CONATINER, vendor_id)
    docker_rpc_image = docker_syncd_name + "-rpc"

    # Force image download to go through mgmt network
    duthost.command("config bgp shutdown all")  
    duthost.stop_service("swss")
    duthost.delete_container(SYNCD_CONATINER)

    # Set sysctl RCVBUF parameter for tests
    duthost.command("sysctl -w net.core.rmem_max=609430500")

    # Set sysctl SENDBUF parameter for tests
    duthost.command("sysctl -w net.core.wmem_max=609430500")

    logger.info("Loading docker image: {} ...".format(docker_rpc_image))
    registry = load_docker_registry_info(duthost, creds)
    download_image(duthost, registry, docker_rpc_image, duthost.os_version)

    logger.info("Swapping docker container from image: [{}] to [{}] ...".format(docker_rpc_image, docker_syncd_name))
    tag_image(
        duthost,
        "{}:latest".format(docker_syncd_name),
        "{}/{}".format(registry.host, docker_rpc_image),
        duthost.os_version
    )


def stop_dockers(duthost):
    """
    Stops all the services in SONiC dut.

    Args:
        duthost (SonicHost): The target device.
    """
    #TODO sample for skip duthost.shell("sudo " + USR_BIN_DIR + "/" + SERVICES_SCRIPT + " -s syncd -o stop")
    duthost.command(
    "sudo " + USR_BIN_DIR + "/" + SERVICES_SCRIPT + " -o stop",
    module_ignore_errors=True
    )
    __services_env_stop_check(duthost)


def reload_dut_config(duthost):   
    """
    Reloads the dut config.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Reloading config and restarting other services ...")
    config_reload(duthost)


def __remove_saiserver_deploy(duthost, creds, request):
    """
    Reverts the saiserver docker's deployment.

    This will stop and remove the saiserver docker.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Delete saiserver docker from DUT host '{0}'".format(duthost.hostname))
    vendor_id = get_sai_running_vendor_id(duthost)

    docker_saiserver_name = "docker-{}{}-{}".format(SAISERVER_CONTAINER, get_sai_thrift_version(request) , vendor_id)
    docker_saiserver_image = docker_saiserver_name

    logger.info("Cleaning the SAI Testing env ...")
    registry = load_docker_registry_info(duthost, creds)
    duthost.delete_container(SAISERVER_CONTAINER)    

    logger.info("Removing the image '{}'...".format(docker_saiserver_image))
    duthost.shell("docker image rm {}".format(docker_saiserver_image))
    duthost.command(
        "docker rmi {}/{}:{}".format(registry.host, docker_saiserver_image, duthost.os_version),
        module_ignore_errors=True
    )

def __restore_default_syncd(duthost, creds):
    """
    Replaces the running syncd with the default syncd that comes with the image.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """
    vendor_id = get_sai_running_vendor_id(duthost)

    docker_syncd_name = "docker-{}-{}".format(SYNCD_CONATINER, vendor_id)

    duthost.stop_service("swss")
    duthost.delete_container(SYNCD_CONATINER)

    tag_image(
        duthost,
        "{}:latest".format(docker_syncd_name),
        docker_syncd_name,
        duthost.os_version
    )

    # Remove the RPC image from the duthost
    docker_rpc_image = docker_syncd_name + "-rpc"
    registry = load_docker_registry_info(duthost, creds)
    duthost.command(
        "docker rmi {}/{}:{}".format(registry.host, docker_rpc_image, duthost.os_version),
        module_ignore_errors=True
    )

def warm_reboot(duthost, localhost):
    """
    Reboot the dut in warm reboot mode.

    Args:
        duthost (SonicHost): The target device.
        localhost: local host object which create by ansible script.
    """
    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_SAI_WARM)


def saiserver_warmboot_config(duthost, operation):
    """
    Saiserver warmboot mode.

        Args:
        duthost (AnsibleHost): device under test
        operation: init|start|restore
    """
    duthost.command(
        "docker exec {} {}/{} -o {}".format(SAISERVER_CONTAINER, USR_BIN_DIR, WARMBOOT_PROFILE_SCRIPT, operation),
        module_ignore_errors=True
    )


def __copy_sai_profile_into_saiserver_docker(duthost):
    """
    Copy the script for prepare the sai.profile into saiserver docker

        Args:
        duthost (AnsibleHost): device under test
    """
    duthost.command(
        "docker cp {}/{} {}:{}".format(USR_BIN_DIR, WARMBOOT_PROFILE_SCRIPT, SAISERVER_CONTAINER, USR_BIN_DIR),
        module_ignore_errors=True
    )

def __copy_sai_qualify_script(duthost):
    """
        Copys script for controlling saiserver docker, sonic services, warmboot...

        Args:
            duthost (AnsibleHost): device under test

        Returns:
            None
    """
    duthost.shell("sudo mkdir -p " + USR_BIN_DIR)
    for script in SAI_SCRIPTS:
        logger.info("Copy script {} to DUT: '{}:{}'".format(script, duthost.hostname, USR_BIN_DIR))
        duthost.copy(src=os.path.join(SCRIPTS_SRC_DIR, script), dest=USR_BIN_DIR)
        duthost.shell("sudo chmod +x " + USR_BIN_DIR + "/" + script)


def __delete_sai_qualify_script(duthost):
    """
    Deletes the saiserver script from dut.

    Args:
        duthost (SonicHost): The target device.
    """
    for script in SAI_SCRIPTS:
        logger.info("Delete script {} from DUT host '{}/{}'".format(script, duthost.hostname, USR_BIN_DIR))
        duthost.file(path=os.path.join(USR_BIN_DIR, script), state="absent")


def __services_env_stop_check(duthost):
    """
    Checks if services that impact sai-test have been stopped.

    Args:
        duthost (SonicHost): The target device.
    """
    running_services = []
    def ready_for_sai_test():
        running_services = []
        for service in SERVICES_LIST:
            if __is_container_running(duthost, service):
                running_services.append(service)
                logger.info("Docker {} is still running, try to stop it.".format(service))
                duthost.shell("docker stop {}".format(service))
        if running_services:
            return False
        return True

    shutdown_check = wait_until(20, 4, 0, ready_for_sai_test)
    if running_services:
        format_list = ['{:>1}' for item in running_services] 
        servers = ','.join(format_list)
        pt_assert(shutdown_check, "Docker {} failed to shut down in 20s".format(servers.format(*running_services)))


def __is_container_running(duthost, container_name):
    """
    Checks if the required container is running in DUT.

    Args:
        duthost (SonicHost): The target device.
        container_name: the required container's name.
    """
    try:
        result = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
        return result["stdout_lines"][0].strip() == "true"
    except Exception:
        logger.info("Cannot get container '{}' running state.".format(container_name))
    return False


def __is_container_exists(duthost, container_name):
    """
    Checks if the required container is running in DUT.

    Args:
        duthost (SonicHost): The target device.
        container_name: the required container's name.
    """
    try:
        result = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
        return bool(result["stdout_lines"][0].strip())
    except Exception:
        logger.info("Cannot get container '{}' running state.".format(container_name))
    return False


def __is_image_exists(duthost, docker_image_name):
    """
        Checks if required docker images exist

        Args:
            duthost (AnsibleHost): device under test
            service_name: the required service's name.
    """
    try:
        result = duthost.shell("docker images | grep {}".format(docker_image_name))
        return bool(docker_image_name in result["stdout_lines"][0].strip())
    except Exception:
        logger.info("Cannot find required docker images '{}'.".format(docker_image_name))
    return False


def get_sai_running_vendor_id(duthost):
    """
    Get the vendor id.

    Args:
        duthost (SonicHost): The target device.
    """
    if is_broadcom_device(duthost):
        vendor_id = "brcm"
    elif is_mellanox_device(duthost):
        vendor_id = "mlnx"
    elif is_barefoot_device(duthost):
        vendor_id = "bfn"
    else:
        error_message = '"{}" does not currently support saitest'.format(duthost.facts["asic_type"])
        logger.error(error_message)
        raise ValueError(error_message)

    return vendor_id


def __create_sai_port_map_file(ptfhost, duthost):
    """
    Create port mapping file on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
        duthost (SonicHost): The target device.
    """

    intfInfo = __create_sai_test_interface_info(duthost)
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


def __delete_sai_port_map_file(ptfhost):
    """
    Delete port mapping file on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Deleting {0} file.".format(PORT_MAP_FILE_PATH))
    ptfhost.file(path=PORT_MAP_FILE_PATH, state="absent")


def update_saithrift_ptf(request, ptfhost):
    '''
    Install the correct python saithrift package on the ptf
    '''
    py_saithrift_url = request.config.getoption("--py_saithrift_url")
    if not py_saithrift_url:
        pytest.fail("No URL specified for python saithrift package")
    pkg_name = py_saithrift_url.split("/")[-1]
    ptfhost.shell("rm -f {}".format(pkg_name))
    result = ptfhost.get_url(url=py_saithrift_url, dest="/root", module_ignore_errors=True)
    if result["failed"] != False or "OK" not in result["msg"]:
        pytest.fail("Download failed/error while installing python saithrift package")
    ptfhost.shell("dpkg -i {}".format(os.path.join("/root", pkg_name)))
    logging.info("Python saithrift package installed successfully")


def __create_sai_test_interface_info(duthost):
    """
        Create sai test interface info

        Args:
            duthost (SonicHost): The target device.
    """
    logger.info("Creating {0} for SAI test on PTF server.".format(PORT_MAP_FILE_PATH))
    intfInfo = duthost.show_interface(command = "status")['ansible_facts']['int_status']
    return intfInfo

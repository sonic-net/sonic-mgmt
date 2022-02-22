import logging

import pytest
import time

from thrift.transport import TSocket
from thrift.transport import TTransport

from tests.common import config_reload
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.broadcom_data import is_broadcom_device
from tests.common.mellanox_data import is_mellanox_device
from tests.common.barefoot_data import is_barefoot_device
from tests.common.system_utils.docker import load_docker_registry_info
from tests.common.system_utils.docker import download_image
from tests.common.system_utils.docker import tag_image
from natsort import natsorted

logger = logging.getLogger(__name__)

OPT_DIR = "/opt"
USR_BIN_DIR = "/usr/bin"
SAISERVER_SCRIPT = "prepare_saiserver_service.sh"
SCRIPTS_SRC_DIR = "scripts/"
SERVICES_DIR = "/lib/systemd/system"
SONIC_WANTS_DIR = "/etc/systemd/system/sonic.target.wants"
TMP_SERVICES_DIR = "/tmp_services"
TMP_SONIC_WANTS_DIR = "/tmp_sonic_wants"
SERVICES_LIST = ["swss", "syncd", "radv", "lldp", "dhcp_relay", "teamd", "bgp", "pmon", "telemetry", "acms"]
SAI_PRC_PORT = 9092
SAI_TEST_CONTAINER_WARM_UP_IN_SEC = 5
IS_TEST_ENV_FAILED = False


#PTF_TEST_ROOT_DIR is the root folder for SAI testing
#DUT_WORKING_DIR is the working folder of DUT
PTF_TEST_ROOT_DIR = "/tmp/sai_qualify"
DUT_WORKING_DIR = "/home/admin"


#These paths are for the SAI cases/results 
SAI_TEST_CASE_DIR_ON_PTF = "/tmp/sai_qualify/tests"
SAI_TEST_REPORT_DIR_ON_PTF = "/tmp/sai_qualify/test_results"
SAI_TEST_REPORT_TMP_DIR_ON_PTF = "/tmp/sai_qualify/test_results_tmp"
SAISERVER_CONTAINER = "saiserver"
SYNCD_CONATINER = "syncd"

PORT_MAP_FILE_PATH = "/tmp/default_interface_to_front_map.ini"


SAI_TEST_CTNR_CHECK_TIMEOUT_IN_SEC = 140
SAI_TEST_CTNR_RESTART_INTERVAL_IN_SEC = 35
RPC_RESTART_INTERVAL_IN_SEC = 32
RPC_CHECK_INTERVAL_IN_SEC = 4



def pytest_addoption(parser):
    # sai test options
    parser.addoption("--sai_test_dir", action="store", default=None, type=str, help="SAI repo folder where the tests will be run.")
    parser.addoption("--sai_test_report_dir", action="store", default=None, type=str, help="SAI test report directory on mgmt node.")
    parser.addoption("--sai_test_container", action="store", default=None, type=str, help="SAI test container, saiserver or syncd.")
    parser.addoption("--sai_test_keep_test_env", action="store_true", default=False, help="SAI test debug options. If keep the test environment in DUT and PTF.")
    parser.addoption("--enable_ptf_sai_test", action="store_true", help="SAI test debug options. If enable PTF-SAI testing, true or false.")
    parser.addoption("--use_dev_branch", action="store_true", help="SAI test debug options. If use dev branch, true or false.")
    parser.addoption("--remove_service_script", action="store_true", help="SAI test debug options. If remove the service script, true or false.")

@pytest.fixture(scope="module")
def start_sai_test_container(duthost, creds, deploy_sai_test_container, request, localhost):
    """
        Starts sai test container docker on DUT.
    """
    logger.info("sai_test_keep_test_env {}".format(request.config.option.sai_test_keep_test_env))
    logger.info("Starting sai test container {}".format(get_sai_test_container_name(request)))
    start_sai_test_conatiner_with_retry(duthost, get_sai_test_container_name(request))
    yield
    logger.info("Stopping and removing sai test container {}".format(get_sai_test_container_name(request)))
    if not request.config.option.sai_test_keep_test_env:
        stop_and_rm_sai_test_container(duthost, get_sai_test_container_name(request))


@pytest.fixture(scope="module")
def deploy_sai_test_container(duthost, creds, stop_other_services, prepare_saiserver_script, request, localhost):
    """
        Deploys a sai test container.
    """
    sai_thrift_version = ""
    if request.config.option.enable_ptf_sai_test:
        logger.info("Enable PTF-SAI Testing: {}".format(request.config.option.enable_ptf_sai_test))
        sai_thrift_version = "v2"
    container_name = request.config.option.sai_test_container
    prepare_sai_test_container(duthost, creds, container_name, sai_thrift_version, request)
    yield
    if not request.config.option.sai_test_keep_test_env:
        revert_sai_test_container(duthost, creds, container_name, sai_thrift_version, request)


@pytest.fixture(scope="module")
def stop_other_services(duthost, request, localhost):
    if request.config.option.remove_service_script:
        _remove_services_script(duthost)
        logger.info("Starting reboot DUT")
        reboot(duthost, localhost)
    else:
        stop_dockers(duthost)
    yield
    if not request.config.option.sai_test_keep_test_env:
        reload_dut_config(duthost)   
        if request.config.option.remove_service_script:
            _reload_services_script(duthost)  


@pytest.fixture(scope="module")
def prepare_saiserver_script(duthost, request):
    _copy_saiserver_script(duthost)
    yield
    if not request.config.option.sai_test_keep_test_env:
        _delete_saiserver_script(duthost)


@pytest.fixture(scope="module")
def prepare_ptf_server(ptfhost, duthost, request):
    update_saithrift_ptf(request, ptfhost)
    _create_sai_port_map_file(ptfhost, duthost)
    yield
    if not request.config.option.sai_test_keep_test_env:
        _delete_sai_port_map_file(ptfhost)


def prepare_sai_test_container(duthost, creds, container_name, sai_thrift_version, request):
    """
        Prepare the sai test container.
    Args:
        duthost (SonicHost): The target device.        
        creds (dict): Credentials used to access the docker registry.
        container_name: The container name for sai testing on DUT.
    """
    logger.info("Preparing {} docker as a sai test container.".format(container_name))
    if container_name == SYNCD_CONATINER:
        _deploy_syncd_rpc_as_syncd(duthost, creds)
    else:
        _deploy_saiserver(duthost, creds, sai_thrift_version, request)
        logger.info("Prepare saiserver.sh")
        duthost.shell(USR_BIN_DIR + "/" + SAISERVER_SCRIPT + " -v " + sai_thrift_version)


def revert_sai_test_container(duthost, creds, container_name, sai_thrift_version, request):
    """
        Reverts the sai test container.
    Args:
        duthost (SonicHost): The target device.        
        creds (dict): Credentials used to access the docker registry.
        container_name: The container name for sai testing on DUT.
    """
    logger.info("Reverting sai test container: [{}].".format(container_name))
    if container_name == SYNCD_CONATINER:
        _restore_default_syncd(duthost, creds)
    else:
        _remove_saiserver_deploy(duthost, creds, sai_thrift_version, request)


def get_sai_test_container_name(request):
    container_name = request.config.option.sai_test_container
    if container_name == SAISERVER_CONTAINER:
        return SAISERVER_CONTAINER
    else:
        return SYNCD_CONATINER


def start_sai_test_conatiner_with_retry(duthost, container_name):
    """
    Attempts to start a sai test container with retry.

    Args:
        duthost (SonicHost): The target device.
        container_name: The container name for sai testing on DUT.
    """

    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    logger.info("Checking the PRC connection before starting the {}.".format(container_name))
    rpc_ready = wait_until(1, 1, 0, _is_rpc_server_ready, dut_ip)
    
    if not rpc_ready:
        logger.info("Attempting to start {}.".format(container_name))
        sai_ready = wait_until(SAI_TEST_CTNR_CHECK_TIMEOUT_IN_SEC, SAI_TEST_CTNR_RESTART_INTERVAL_IN_SEC, 0, _is_sai_test_container_restarted, duthost, container_name)
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


def _is_sai_test_container_restarted(duthost, container_name):
    """
    Checks if the sai test container started.
    
    Args:
        duthost (SonicHost): The target device.
        container_name: The container name for sai testing on DUT.
    """

    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    if _is_container_exists(duthost, container_name):
        logger.info("{} already exists, stop and remove it for a clear restart.".format(container_name))
        stop_and_rm_sai_test_container(duthost, container_name)
    _start_sai_test_container(duthost, container_name)
    rpc_ready = wait_until(RPC_RESTART_INTERVAL_IN_SEC, RPC_CHECK_INTERVAL_IN_SEC, 0, _is_rpc_server_ready, dut_ip)
    if not rpc_ready:
        logger.info("Failed to start up {} for sai testing on DUT, stop it for a restart".format(container_name))
    return rpc_ready


def _is_rpc_server_ready(dut_ip):
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


def _start_sai_test_container(duthost, container_name):
    """
    Starts the sai test container by a script.

    Args:
        duthost (SonicHost): The target device.
        container_name: The container name for sai testing on DUT.
    """
    logger.info("Starting {} docker for testing".format(container_name))      
    duthost.shell(USR_BIN_DIR + "/" + container_name + ".sh" + " start")


def _deploy_saiserver(duthost, creds, sai_thrift_version, request):
    """Deploy a saiserver docker for SAI testing.

    This will stop the swss and syncd, then download a new Docker image to the duthost.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """
    vendor_id = _get_sai_running_vendor_id(duthost)
    docker_saiserver_name = "docker-saiserver{}-{}".format(sai_thrift_version, vendor_id)
    docker_saiserver_image = docker_saiserver_name

    # Force image download to go through mgmt network
    duthost.command("config bgp shutdown all")  

    # Set sysctl RCVBUF parameter for tests
    duthost.command("sysctl -w net.core.rmem_max=609430500")

    # Set sysctl SENDBUF parameter for tests
    duthost.command("sysctl -w net.core.wmem_max=609430500")

    logger.info("Loading docker image: {} ...".format(docker_saiserver_image))
    registry = load_docker_registry_info(duthost, creds)
    if request.config.option.use_dev_branch:
        os_version = _transform_dev_branch_version(duthost)
    else:
        os_version = duthost.os_version
    download_image(duthost, registry, docker_saiserver_image, os_version)
    tag_image(
    duthost,
    "{}:latest".format(docker_saiserver_name),
    "{}/{}".format(registry.host, docker_saiserver_image),
    os_version
    )


def _deploy_syncd_rpc_as_syncd(duthost, creds):
    """Replaces the running syncd container with the RPC version of it.

    This will download a new Docker image to the duthost. 
    service.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """
    vendor_id = _get_sai_running_vendor_id(duthost)

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
    for service in SERVICES_LIST:
        logger.info("Stopping service '{}' ...".format(service))
        duthost.stop_service(service)    

    _services_env_stop_check(duthost)


def reload_dut_config(duthost):   
    """
    Reloads the dut config.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Reloading config and restarting other services ...")
    config_reload(duthost)


def _remove_saiserver_deploy(duthost, creds, sai_thrift_version, request):
    """Reverts the saiserver docker's deployment.

    This will stop and remove the saiserver docker.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Delete saiserver docker from DUT host '{0}'".format(duthost.hostname))
    vendor_id = _get_sai_running_vendor_id(duthost)
    docker_saiserver_name = "docker-{}{}-{}".format(SAISERVER_CONTAINER, sai_thrift_version, vendor_id)
    docker_saiserver_image = docker_saiserver_name

    logger.info("Cleaning the SAI Testing env ...")
    registry = load_docker_registry_info(duthost, creds)
    duthost.delete_container(SAISERVER_CONTAINER)    

    if request.config.option.use_dev_branch:
        os_version = _transform_dev_branch_version(duthost)
    else:
        os_version = duthost.os_version

    logger.info("Removing the image '{}'...".format(docker_saiserver_image))
    duthost.shell("docker image rm {}".format(docker_saiserver_image))
    duthost.command(
        "docker rmi {}/{}:{}".format(registry.host, docker_saiserver_image, os_version),
        module_ignore_errors=True
    )

def _restore_default_syncd(duthost, creds):
    """Replaces the running syncd with the default syncd that comes with the image.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
    """
    vendor_id = _get_sai_running_vendor_id(duthost)

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


def _copy_saiserver_script(duthost):
    """
        Copys script for controlling saiserver docker.

        Args:
            duthost (AnsibleHost): device under test

        Returns:
            None
    """
    logger.info("Copy saiserver script to DUT: '{}'".format(duthost.hostname))
    duthost.copy(src=os.path.join(SCRIPTS_SRC_DIR, SAISERVER_SCRIPT), dest=USR_BIN_DIR)
    duthost.shell("sudo chmod +x " + USR_BIN_DIR + "/" + SAISERVER_SCRIPT)


def _delete_saiserver_script(duthost):
    """
    Deletes the saiserver script from dut.

    Args:
        duthost (SonicHost): The target device.
    """
    logger.info("Delete saiserver script from DUT host '{}'".format(duthost.hostname))
    duthost.file(path=os.path.join(USR_BIN_DIR, SAISERVER_SCRIPT), state="absent")


def _services_env_stop_check(duthost):
    """
    Checks if services that impact sai-test have been stopped.

    Args:
        duthost (SonicHost): The target device.
    """
    running_services = []
    def ready_for_sai_test():
        running_services = []
        for service in SERVICES_LIST:
            if _is_container_running(duthost, service):
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
    except Exception:
        logger.info("Cannot get container '{}' running state.".format(container_name))
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
    except Exception:
        logger.info("Cannot get container '{}' running state.".format(duthost.hostname))
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
    elif is_barefoot_device(duthost):
        vendor_id = "bfn"
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

    intfInfo = _create_sai_test_interface_info(duthost)
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

def _remove_services_script(duthost):
    """
        Removes scripts to shutup services.

        Args:
            duthost (AnsibleHost): device under test

        Returns:
            None
    """
    duthost.command("sudo rm -rf {}{}".format(OPT_DIR, TMP_SERVICES_DIR))
    duthost.command("sudo rm -rf {}{}".format(OPT_DIR, TMP_SONIC_WANTS_DIR))
    duthost.command("sudo mkdir {}{}".format(OPT_DIR, TMP_SERVICES_DIR))
    duthost.command("sudo mkdir {}{}".format(OPT_DIR, TMP_SONIC_WANTS_DIR))
    for service in SERVICES_LIST:
        if(_is_service_script_exist(duthost, SERVICES_DIR, service)):
            logger.info("Removing service script from{}/{}.service to {}{} ...".format(SERVICES_DIR, service, OPT_DIR, TMP_SERVICES_DIR))
            duthost.command("sudo mv -f {}/{}.service {}{}".format(SERVICES_DIR, service, OPT_DIR, TMP_SERVICES_DIR))
           
        if(_is_service_script_exist(duthost, SONIC_WANTS_DIR, service)):
            logger.info("Removing service script from{}/{}.service to {}{} ...".format(SONIC_WANTS_DIR, service, OPT_DIR, TMP_SONIC_WANTS_DIR))
            duthost.command("sudo mv -f {}/{}.service {}{}".format(SONIC_WANTS_DIR, service, OPT_DIR, TMP_SONIC_WANTS_DIR))

def _reload_services_script(duthost):
    """
        Reloads scripts to recover services.

        Args:
            duthost (AnsibleHost): device under test

        Returns:
            None
    """
    for service in SERVICES_LIST:
        script_path = "{}{}".format(OPT_DIR, TMP_SERVICES_DIR)
        if(_is_service_script_exist(duthost, script_path, service)):
            logger.info("Reloading service script from{}{}/{}.service to {} ...".format(OPT_DIR, TMP_SERVICES_DIR, service, SERVICES_DIR))
            duthost.command("sudo mv -f {}{}/{}.service {}".format(OPT_DIR, TMP_SERVICES_DIR, service, SERVICES_DIR))
        script_path = "{}{}".format(OPT_DIR, TMP_SONIC_WANTS_DIR)
        if(_is_service_script_exist(duthost, script_path, service)):
            logger.info("Reloading service script from{}{}/{}.service to {} ...".format(OPT_DIR, TMP_SONIC_WANTS_DIR, service, SONIC_WANTS_DIR))
            duthost.command("sudo mv -f {}{}/{}.service {}".format(OPT_DIR, TMP_SONIC_WANTS_DIR, service, SONIC_WANTS_DIR))
    duthost.command("sudo rm -rf {}{}".format(OPT_DIR, TMP_SERVICES_DIR))
    duthost.command("sudo rm -rf {}{}".format(OPT_DIR, TMP_SONIC_WANTS_DIR))

def _is_service_script_exist(duthost, script_path ,service_name):
    """
        Checks if service script exist

        Args:
            duthost (AnsibleHost): device under test
            script_path: the required script path
            service_name: the required service's name.
    """
    try:
        script_name = "{}.service".format(service_name)
        result = duthost.shell("ls {} | grep {}".format(script_path, script_name))
        return bool(result["stdout_lines"][0].strip() == script_name)
    except Exception:
        logger.info("Cannot find required service '{}'.".format(service_name))
    return False

def _transform_dev_branch_version(duthost):
    """
        Transforms dev branch version

        Args:
            duthost (AnsibleHost): device under test
        
        Returns:
            os_version: transformed os version
    """
    logger.info("Transforming dev branch verson: {}".format(duthost.os_version))
    os_version = "{}.bld-{}".format(duthost.os_version.split(".")[1].split("-")[2], duthost.os_version.split(".")[1].split("-")[0])
    return os_version

def _create_sai_test_interface_info(duthost):
    """
        Create sai test interface info

        Args:
            duthost (SonicHost): The target device.
    """
    logger.info("Creating {0} for SAI test on PTF server.".format(PORT_MAP_FILE_PATH))
    intfInfo = duthost.show_interface(command = "status")['ansible_facts']['int_status']
    return intfInfo

def _create_sai_test_interface(port_numbers):
    """
    Create port interface list.

    Args:
        port_numbers: The port number of DUT.
    """
    logger.info("Creating {} port interface list".format(port_numbers))
    interfaces_str = ""
    for port_number in range(port_numbers):
        interface_tmp = "\'0-{0}@eth{0}\'".format(port_number)
        interfaces_str += "--interface {} ".format(interface_tmp)
    return interfaces_str
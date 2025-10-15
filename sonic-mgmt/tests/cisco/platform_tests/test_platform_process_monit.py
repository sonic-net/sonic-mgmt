import pytest
import time
import random
import logging
import yaml

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

logger = logging.getLogger(__name__)

PLATFORM_PROCESS_SCRIPT_PATH = "/usr/bin/platform_monit_process.py"
PLATFORM_PROCESS_LIST = "/etc/monit/platform_process_monit_list.yaml"


@pytest.fixture(autouse=True, scope="module")
def skip_if_platform_process_list_missing(duthosts, rand_one_dut_hostname):
    """
    Skip all tests in this module if the platform process script or list is missing on the DUT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    
    # Check if platform process script exists
    if duthost.shell(f"test -f {PLATFORM_PROCESS_SCRIPT_PATH}", module_ignore_errors=True)['rc'] != 0:
        pytest.skip(f"{PLATFORM_PROCESS_SCRIPT_PATH} not present on {duthost.hostname}, skipping tests.")
    
    # Check if platform process list exists
    if duthost.shell(f"test -f {PLATFORM_PROCESS_LIST}", module_ignore_errors=True)['rc'] != 0:
        pytest.skip(f"{PLATFORM_PROCESS_LIST} not present on {duthost.hostname}, skipping tests.")


@pytest.fixture(autouse=True, scope="module")
def disable_monit_platform_process(duthosts, rand_one_dut_hostname):
    """
    Disable monit platform_process_monit before tests and re-enable after tests.
    """
    duthost = duthosts[rand_one_dut_hostname]
    
    # Disable monit monitoring before tests
    duthost.shell("monit unmonitor platform_process_monit", module_ignore_errors=True)
    
    yield
    
    # Re-enable monit monitoring after tests
    duthost.shell("monit monitor platform_process_monit", module_ignore_errors=True)

def run_platform_process_check(duthost):
    """
    Run the platform process check script on the DUT and return (rc, stdout).
    """
    cmd = f"{PLATFORM_PROCESS_SCRIPT_PATH}"
    result = duthost.shell(cmd, module_ignore_errors=True)
    return result['rc'], result['stdout']

def wait_for_process_in_container(duthost, container, proc, expected=True, timeout=30):
    """
    Wait until the specified process is (or is not) running in the given container.
    """
    def _check():
        ps_cmd = f"docker exec {container} pgrep -f {proc}"
        res = duthost.shell(ps_cmd, module_ignore_errors=True)
        found = res["rc"] == 0
        return found if expected else not found
    pytest_assert(wait_until(timeout, 2, 0, _check), f"Process {proc} in {container} did not reach expected state: {expected}")

def restart_process_in_container(duthost, container, proc):
    """
    Restart a process inside a container by killing it and waiting for it to respawn.
    """
    duthost.shell(f"docker exec {container} pkill -9 {proc}", module_ignore_errors=True)
    time.sleep(3)
    wait_for_process_in_container(duthost, container, proc, expected=True)

def stop_process_in_container(duthost, container, proc):
    """
    Stop a process inside a container by killing it and waiting until it is not running.
    """
    duthost.shell(f"docker exec {container} supervisorctl stop {proc}", module_ignore_errors=True)
    wait_for_process_in_container(duthost, container, proc, expected=False)

def start_process_in_container(duthost, container, proc):
    """
    Start a process inside a container using supervisorctl.
    """
    duthost.shell(f"docker exec {container} supervisorctl start {proc}", module_ignore_errors=True)
    wait_for_process_in_container(duthost, container, proc, expected=True)

def restart_container_service(duthost, process):
    logger.info(f"Restarting service: {process}")
    duthost.shell(f"systemctl restart {process}")
    time.sleep(10)

def get_random_container_and_process(duthost):
    """
    Calls the platform process script with --process_list, parses the YAML output,
    and returns a random (feature, process) tuple.
    """
    cmd = f"{PLATFORM_PROCESS_SCRIPT_PATH} --process-list"
    result = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(result['rc'] == 0, f"Failed to get process list: {result['stdout']}")
    try:
        yaml_data = yaml.safe_load(result['stdout'])
        
        process_dict = {}
        if yaml_data and 'containers' in yaml_data:
            for container_info in yaml_data['containers']:
                container_name = container_info['name']
                processes = container_info.get('processes', [])
                if processes:
                    process_dict[container_name] = processes
    except Exception as e:
        pytest_assert(False, f"Could not parse process list output as YAML: {result['stdout']}\nError: {e}")

    pytest_assert(process_dict, "Process list is empty")
    container = random.choice(list(process_dict.keys()))
    process_list = process_dict[container]
    pytest_assert(process_list, f"No processes found for feature {container}")
    proc = random.choice(process_list)
    return container, proc


class TestPlatformMonitProcess:
    def test_platform_monit_success_no_warning(self, duthosts, rand_one_dut_hostname):
        duthost = duthosts[rand_one_dut_hostname]
        # clear previous states
        rc, out = run_platform_process_check(duthost)

        rc, out = run_platform_process_check(duthost)
        pytest_assert(rc == 0, f"Script did not return success: {out}")
        pytest_assert("WARNING:" not in out, f"Unexpected warning in output: {out}")

    @pytest.mark.disable_loganalyzer
    def test_platform_monit_multiple_process_restarts(self, duthosts, rand_one_dut_hostname, enum_rand_one_asic_index):
        """Test multiple process restarts and verify correct restart count."""
        duthost = duthosts[rand_one_dut_hostname]
        asic = duthost.asic_instance(enum_rand_one_asic_index)
        container, proc = get_random_container_and_process(duthost)
        container_name = asic.get_docker_name(container) if hasattr(asic, 'get_docker_name') else container
        
        # Restart process 3 times
        for i in range(3):
            restart_process_in_container(duthost, container_name, proc)
            time.sleep(5)
        
        rc, out = run_platform_process_check(duthost)
        pytest_assert("restarted 3 times since last check" in out, f"Expected restart count 3 not found for {proc}: {out}")
        
        # Second check should show SUCCESS
        rc2, out2 = run_platform_process_check(duthost)
        pytest_assert("WARNING:" not in out2, f"Unexpected warning on second check: {out2}")

    @pytest.mark.disable_loganalyzer
    def test_platform_monit_process_restart_after_docker_restart(self, duthosts, rand_one_dut_hostname, enum_rand_one_asic_index):
        """Test process restart detection after docker service restart."""
        duthost = duthosts[rand_one_dut_hostname]
        asic = duthost.asic_instance(enum_rand_one_asic_index)
        
        # Restart swss service
        duthost.shell("sudo systemctl reset-failed")
        process_name = 'swss'
        if duthost.is_multi_asic:
            process_name = asic.get_service_name(process_name)
        restart_container_service(duthost, process_name)
        assert wait_until(600, 5, 120, duthost.critical_services_fully_started), \
            "Not all critical services are fully started"
        time.sleep(10)
        
        try:
            # Get a process to restart
            container, proc = get_random_container_and_process(duthost)
            container_name = asic.get_docker_name(container) if hasattr(asic, 'get_docker_name') else container
            
            # Restart the process once
            restart_process_in_container(duthost, container_name, proc)
            
            rc, out = run_platform_process_check(duthost)
            pytest_assert("restarted 1 times since docker start" in out, f"Expected restart count 1 not found for {proc}: {out}")
            
            # Second check should show SUCCESS
            rc2, out2 = run_platform_process_check(duthost)
            pytest_assert("WARNING:" not in out2, f"Unexpected warning on second check: {out2}")
        finally:
            # Always wait for all admin up interfaces to be up, even if test fails
            status = wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost)
            pytest_assert(status, "Not all ports that are admin up are operationally up")

    def test_platform_monit_restart_process(self, duthosts, rand_one_dut_hostname, enum_rand_one_asic_index):
        """Test single process restart detection."""
        duthost = duthosts[rand_one_dut_hostname]
        asic = duthost.asic_instance(enum_rand_one_asic_index)
        container, proc = get_random_container_and_process(duthost)
        container_name = asic.get_docker_name(container) if hasattr(asic, 'get_docker_name') else container
        
        restart_process_in_container(duthost, container_name, proc)
        rc, out = run_platform_process_check(duthost)
        pytest_assert("restarted 1 times since last check" in out, f"Expected restart count 1 not found for {proc}: {out}")

        rc2, out2 = run_platform_process_check(duthost)
        pytest_assert("WARNING:" not in out2, f"Unexpected warning after {proc} restart recovery: {out2}")

    def test_platform_monit_stop_and_start_process(self, duthosts, rand_one_dut_hostname, enum_rand_one_asic_index):
        """Test process Not RUNNING detection."""
        duthost = duthosts[rand_one_dut_hostname]
        asic = duthost.asic_instance(enum_rand_one_asic_index)
        container, proc = get_random_container_and_process(duthost)
        container_name = asic.get_docker_name(container) if hasattr(asic, 'get_docker_name') else container

        # Clear current state
        _, _ = run_platform_process_check(duthost)
        try:
            stop_process_in_container(duthost, container_name, proc)
            rc, out = run_platform_process_check(duthost)
            pytest_assert(f"WARNING: {proc} not running in {container_name}" in out, f"Expected not running warning not found for {proc}: {out}")
        except Exception as e:
            logger.warning(f"Failed to stop process {proc} in container {container_name}: {e}")
        finally:
            try:
                start_process_in_container(duthost, container_name, proc)
                rc, out = run_platform_process_check(duthost)
                pytest_assert("restarted 1 times since last check" in out, f"Expected restart warning not found for {proc}: {out}")
            except Exception as e:
                logger.warning(f"Failed to start process {proc} in container {container_name}: {e}")
            finally:
                rc2, out2 = run_platform_process_check(duthost)
                pytest_assert("not running in" not in out2, f"Unexpected warning after {proc} restart recovery: {out2}")

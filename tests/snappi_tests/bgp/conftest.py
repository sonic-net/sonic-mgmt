import pytest
import logging
import os
import time
import paramiko
from tests.snappi_tests.variables import t2_uplink_fanout_info, t1_dut_info, fanout_presence    # noqa: F401
from tests.snappi_tests.bgp.files.bgp_outbound_helper import get_hw_platform    # noqa: F401
from tests.common.utilities import wait_until
from _pytest.runner import TestReport

logger = logging.getLogger(__name__)
# Get the directory of the current script
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
CRITICAL_CONTAINERS = {"bgp", "swss", "syncd"}


def pytest_runtest_logreport(report: TestReport):
    """Log test results for better visibility."""
    if report.when == "call":
        # extract convergence results
        convergence_result = dict(report.user_properties).get(
            "convergence_result", None)
        logger.info(
            f"Test {report.nodeid} finished with result: {report.outcome}")
        if convergence_result:
            print(convergence_result)


def ssh_connect(device_ip, username, password):
    """Establish an SSH connection to the DUT."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(device_ip, username=username, password=password)
        return ssh
    except Exception as e:
        logger.error(f"SSH connection to {device_ip} failed: {e}")
        pytest.fail(f"Failed to connect to {device_ip}")


def scp_to_dut(device_ip, creds, local_path, remote_tmp_path="/tmp/config_db.json.tmp"):
    """Copy the config file to the DUT's /tmp directory using SCP."""
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')

    ssh = ssh_connect(device_ip, username, password)

    try:
        logger.info(f"Transferring config file to {device_ip}...")
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_tmp_path)
        sftp.close()
        logger.info(
            f"Successfully copied {local_path} to {device_ip}:{remote_tmp_path}")
    except Exception as e:
        logger.error(f"Failed to copy file to {device_ip}: {e}")
        pytest.fail(f"Failed SCP transfer to {device_ip}")
    finally:
        ssh.close()


def execute_command(ssh, command, password=None):
    """Execute a command over SSH and check for failures."""
    stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)

    if password:
        stdin.write(f"{password}\n")  # Provide sudo password
        stdin.flush()

    output, error = stdout.read().decode(), stderr.read().decode()

    if error:
        logger.error(f"Command failed: {command}\nError: {error}")
        pytest.fail(f"Command execution failed on DUT: {command}")

    return output


def are_critical_containers_running(ssh):
    """Check if all critical containers (bgp, swss, syncd) are running."""
    running_containers_output = execute_command(
        ssh, "docker ps -f 'status=running' --format '{{.Names}}'")
    running_containers = set(running_containers_output.split())

    return CRITICAL_CONTAINERS.issubset(running_containers)


def validate_critical_containers(ssh):
    """Ensure critical containers are running, waiting up to 120s with 10s intervals."""
    logger.info("Validating critical containers are running...")

    assert wait_until(120, 10, 0, lambda: are_critical_containers_running(
        ssh)), "Critical containers did not start within 120 seconds!"

    logger.info("All critical containers are running.")


def apply_t1_config_on_dut(device_ip, creds,
                           remote_tmp_path="/tmp/config_db.json.tmp",
                           final_path="/etc/sonic/config_db.json"):
    """Move the file to /etc/sonic, rename it, reload config, and validate containers."""
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')

    ssh = ssh_connect(device_ip, username, password)

    try:
        logger.info(f"Applying configuration on T1 DUT: {device_ip}...")
        execute_command(
            ssh, f"sudo mv {remote_tmp_path} {final_path}", password)
        logger.info(f"Moved {remote_tmp_path} to {final_path}")
        execute_command(ssh, "sudo config reload -y", password)
        logger.info("T1 DUT Config reload command executed")

        # Validate containers
        validate_critical_containers(ssh)

        logger.info(
            f"T1 DUT Configuration applied successfully on {device_ip}")
    finally:
        ssh.close()


def apply_fanout_config_on_dut(device_ip, creds,
                               remote_tmp_path="/tmp/config_db.json.tmp",
                               final_path="/etc/sonic/config_db.json"):
    """Apply fanout DUT specific configuration and validate containers."""
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')

    ssh = ssh_connect(device_ip, username, password)

    try:
        logger.info(f"Applying configuration on Fanout DUT: {device_ip}...")
        execute_command(
            ssh, f"sudo cp {remote_tmp_path} {final_path}", password)
        logger.info(f"Copied {remote_tmp_path} to {final_path}")
        execute_command(ssh, "sudo config reload -y", password)
        logger.info("Fanout DUT Config reload command executed")

        # Validate containers
        validate_critical_containers(ssh)
        time.sleep(60)  # Wait for containers to stabilize
        # Execute bcmcmd commands after validation
        execute_command(ssh, 'bcmcmd "fp detach"', password)
        logger.info("Executed bcmcmd 'fp detach'")
        execute_command(ssh, 'bcmcmd "fp init"', password)
        logger.info("Executed bcmcmd 'fp init'")

        logger.info(
            f"Fanout DUT Configuration applied successfully on {device_ip}")
    finally:
        ssh.close()


def configure_dut(hw_platform, creds, role):
    """Configure T1 or Fanout DUT based on the given role."""
    config_filename = f"config_db.json.{role}.{hw_platform}"  # Example: "config_db.json.t1.ARISTA"
    config_source_path = os.path.join(BASE_DIR, "configs", config_filename)

    if not os.path.exists(config_source_path):
        logger.error(f"Config file '{config_source_path}' not found.")
        pytest.fail(
            f"Missing config file: {config_source_path} for platform: {hw_platform}")

    if role == "t1":
        device_ip = t1_dut_info[hw_platform]["dut_ip"]
    elif role == "fanout":
        device_ip = t2_uplink_fanout_info[hw_platform]["fanout_ip"]

    # Copy to /tmp on DUT
    scp_to_dut(device_ip, creds, config_source_path)

    # Apply configuration based on role
    if role == "t1":
        apply_t1_config_on_dut(device_ip, creds)
    elif role == "fanout":
        apply_fanout_config_on_dut(device_ip, creds)


def apply_tsb(duthost):
    """Apply TSB on the DUT and ensure it is successfully applied."""
    logger.info(f"Applying TSB on {duthost.hostname}...")

    try:
        result = duthost.shell("sudo TSB", module_ignore_errors=True)
        if result["rc"] != 0:
            error_msg = f"Failed to apply TSB on {duthost.hostname}: {result['stderr']}"
            logger.error(error_msg)
            pytest.fail(error_msg)

        save_result = duthost.shell(
            "sudo config save -y", module_ignore_errors=True)
        if save_result["rc"] != 0:
            error_msg = f"Failed to save config on {duthost.hostname}: {save_result['stderr']}"
            logger.error(error_msg)
            pytest.fail(error_msg)

        logger.info(
            f"TSB applied and configuration saved successfully on {duthost.hostname}.")

    except Exception as e:
        error_msg = f"Error while applying TSB on {duthost.hostname}: {str(e)}"
        logger.exception(error_msg)
        pytest.fail(error_msg)


@pytest.fixture(scope="session", autouse=True)
def initial_setup(duthosts, creds):
    """Perform initial DUT configurations (T1, Fanout) for convergence tests (runs once per test session)."""
    logger.info("Starting initial DUT setup for T2 Convergence tests")

    # Get Hardware platform
    ansible_dut_hostnames = [duthost.hostname for duthost in duthosts]
    hw_platform = get_hw_platform(ansible_dut_hostnames)

    if hw_platform is None:
        pytest.fail("Unknown HW Platform")
    logger.info(f"HW Platform: {hw_platform}")

    # Configure T1 DUT
    configure_dut(hw_platform, creds, "t1")

    # Configure Fanout DUT (if applicable)
    if fanout_presence:
        configure_dut(hw_platform, creds, "fanout")

    # execute TSB on DUTs
    for duthost in duthosts:
        apply_tsb(duthost)

    logger.info("T2 Convergence test setup complete")

import csv
import shutil
from unittest.mock import Mock
import pytest
import logging
import os
import time
import paramiko
from tests.conftest import add_custom_msg
from tests.snappi_tests.variables import (
    COMMUNITY_LOWER_TIER_DROP,
    TOPOLOGY_T2_PIZZABOX,
    FANOUT_PRESENCE,
    detect_topology_and_vendor,
    get_lower_tier_info,
    get_uplink_fanout_info
)
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


def apply_lower_tier_config_on_dut(device_ip, creds, topology_type,
                                   remote_tmp_path="/tmp/config_db.json.tmp",
                                   final_path="/etc/sonic/config_db.json", **kwargs):
    """Move the file to /etc/sonic, rename it, reload config, and validate containers for lower tier DUT."""
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')

    ssh = ssh_connect(device_ip, username, password)
    exist_prefix_deny = False

    # Route-map prefix is same for both topologies
    route_map_prefix = "FROM_TIER2"

    try:
        logger.info(f"Applying configuration on Lower Tier DUT: {device_ip}...")
        execute_command(
            ssh, f"sudo mv {remote_tmp_path} {final_path}", password)
        logger.info(f"Moved {remote_tmp_path} to {final_path}")

        execute_command(ssh, "sudo config reload -y", password)
        logger.info("Lower Tier DUT Config reload command executed")

        time.sleep(10)

        exist_prefix_deny = execute_command(
            ssh, "vtysh -c 'show run | include bgp' | grep UPSTREAM_PREFIX_DENY")

        kwargs.get("context")["exist-prefix-deny"] = exist_prefix_deny

        if not exist_prefix_deny:
            logger.info(
                f"Apply filter for lower tier community {COMMUNITY_LOWER_TIER_DROP[0]}")
            execute_command(ssh, "vtysh -c " + " -c ".join(
                [
                    "'config t'",
                    f"'bgp community-list standard UPSTREAM_PREFIX_DENY permit {COMMUNITY_LOWER_TIER_DROP[0]}'",
                    f"'route-map {route_map_prefix}_V4 deny 10'",
                    "'match community UPSTREAM_PREFIX_DENY'",
                    "'exit'",
                    f"'route-map {route_map_prefix}_V6 deny 10'",
                    "'match community UPSTREAM_PREFIX_DENY'"
                ])
            )

        # Validate containers
        validate_critical_containers(ssh)

        logger.info(
            f"Lower Tier DUT Configuration applied successfully on {device_ip}")
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


def configure_lower_tier_or_fanout(topology_type, vendor, creds, role, **kwargs):
    """
    Unified function to configure lower tier or Fanout DUT.

    Args:
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: Vendor identifier (e.g., 'ARISTA', 'NOKIA', 'CISCO')
        creds: Credentials dictionary
        role: 'lower_tier' or 'fanout'
        **kwargs: Additional arguments (e.g., context for lower tier config)
    """
    # Determine config file name based on topology and role
    if role == "lower_tier":
        if topology_type == TOPOLOGY_T2_PIZZABOX:
            config_role = "lower_tier.pizzabox"
        else:
            config_role = "lower_tier.chassis"
    elif role == "fanout":
        if topology_type == TOPOLOGY_T2_PIZZABOX:
            config_role = "fanout.pizzabox"
        else:
            config_role = "fanout.chassis"
    else:
        pytest.fail(f"Unknown role: {role}")

    config_filename = f"config_db.json.{config_role}.{vendor}"
    config_source_path = os.path.join(BASE_DIR, "configs", config_filename)

    if not os.path.exists(config_source_path):
        logger.error(f"Config file '{config_source_path}' not found.")
        pytest.fail(f"Missing config file: {config_source_path} for vendor: {vendor}")

    # Get device IP based on role
    if role == "lower_tier":
        device_ip = get_lower_tier_info(topology_type, vendor)["dut_ip"]
    elif role == "fanout":
        device_ip = get_uplink_fanout_info(topology_type, vendor)["fanout_ip"]

    # Copy config to /tmp on DUT
    scp_to_dut(device_ip, creds, config_source_path)

    # Apply configuration based on role
    if role == "lower_tier":
        apply_lower_tier_config_on_dut(device_ip, creds, topology_type, **kwargs)
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


def patch_conn_graph_facts(duthosts, tbinfo):
    """
    Perform patching _links.csv so that only included duts exisiting in the file.
    """
    base_path = os.path.dirname(os.path.realpath(__file__))
    lab_conn_graph_path = os.path.join(base_path, "../../../ansible/files/")
    link_file = os.path.join(lab_conn_graph_path, f"sonic_{tbinfo['inv_name']}_links.csv")

    def patch():
        shutil.copyfile(link_file, link_file + ".bak")
        with open(link_file, "w"):
            # Get all DUT hostnames
            dut_hostnames = set(duthost.hostname for duthost in duthosts)
            with open(link_file + ".bak", "r") as infile, open(link_file, "w", newline="") as outfile:
                reader = csv.reader(infile)
                writer = csv.writer(outfile)
                header = next(reader)
                writer.writerow(header)
                for row in reader:
                    if any(host in row for host in dut_hostnames):
                        writer.writerow(row)

    def undo():
        shutil.move(link_file + ".bak", link_file)

    return Mock(undo=undo, patch=patch)


@pytest.fixture(scope="session")
def record_property(request):
    from tabulate import tabulate

    def _print_table(arr_dict_value):
        logger.info(tabulate([
            d.values() for d in arr_dict_value
        ], headers=arr_dict_value[0].keys(), tablefmt="psql"))

    def _handler(key, arr_dict_value):
        add_custom_msg(request, key, arr_dict_value)
        _print_table(arr_dict_value)
    return _handler


@pytest.fixture(scope="session", autouse=True)
def initial_setup(duthosts, creds, tbinfo):
    if 'route_conv' not in tbinfo['topo']['name']:
        yield
        return

    """Perform initial DUT configurations for convergence tests (runs once per test session)."""
    patch_facts = patch_conn_graph_facts(duthosts, tbinfo)
    patch_facts.patch()

    context = {'exist-prefix-deny': False}

    logger.info("Starting initial DUT setup for Convergence tests")

    # Get Hardware platform and topology type using new unified function
    ansible_dut_hostnames = [duthost.hostname for duthost in duthosts]
    topology_type, vendor = detect_topology_and_vendor(ansible_dut_hostnames)

    if vendor is None:
        pytest.fail("Unknown Vendor/HW Platform")
    logger.info(f"Vendor: {vendor}")
    logger.info(f"Topology Type: {topology_type}")

    # Configure lower tier and fanout using unified function
    configure_lower_tier_or_fanout(topology_type, vendor, creds, "lower_tier", context=context)
    if FANOUT_PRESENCE:
        configure_lower_tier_or_fanout(topology_type, vendor, creds, "fanout")

    # Execute TSB on all DUTs
    for duthost in duthosts:
        apply_tsb(duthost)

    logger.info(f"{topology_type} Convergence test setup complete")

    yield

    # Cleanup
    if not context['exist-prefix-deny']:
        lower_tier_info = get_lower_tier_info(topology_type, vendor)
        device_ip = lower_tier_info["dut_ip"]
        route_map_prefix = "FROM_TIER2"

        ssh = ssh_connect(device_ip, creds.get('sonicadmin_user'),
                          creds.get('sonicadmin_password'))
        logger.info(f"Remove filter for community {COMMUNITY_LOWER_TIER_DROP[0]}")
        execute_command(ssh, "vtysh -c " + " -c ".join([
            "'config t'",
            f"'no bgp community-list standard UPSTREAM_PREFIX_DENY permit {COMMUNITY_LOWER_TIER_DROP[0]}'",
            f"'no route-map {route_map_prefix}_V4 deny 10'",
            f"'no route-map {route_map_prefix}_V6 deny 10'",
        ]))

    patch_facts.undo()

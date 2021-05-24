import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_host_visible_vars
from tests.common.utilities import wait_until

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_RESTART_THRESHOLD_SECS = 180

logger = logging.getLogger(__name__)

def is_supervisor_node(inv_files, hostname):
    """Check if the current node is a supervisor node in case of multi-DUT.
     @param inv_files: List of inventory file paths, In tests,
            you can be get it from get_inventory_files in tests.common.utilities
     @param hostname: hostname as defined in the inventory
    Returns:
          Currently, we are using 'card_type' in the inventory to make the decision. If 'card_type' for the node is defined in
          the inventory, and it is 'supervisor', then return True, else return False. In future, we can change this
          logic if possible to derive it from the DUT.
    """
    dut_vars = get_host_visible_vars(inv_files, hostname)
    if 'card_type' in dut_vars and dut_vars['card_type'] == 'supervisor':
        return True
    return False


def is_frontend_node(inv_files, hostname):
    """Check if the current node is a frontend node in case of multi-DUT.
     @param inv_files: List of inventory file paths, In tests,
            you can be get it from get_inventory_files in tests.common.utilities
     @param hostname: hostname as defined in the inventory
     Returns:
          True if it is not any other type of node. Currently, the only other type of node supported is 'supervisor'
          node. If we add more types of nodes, then we need to exclude them from this method as well.
    """
    return not is_supervisor_node(inv_files, hostname)


def is_container_running(duthost, container_name):
    """Decides whether the container is running or not
    @param duthost: Host DUT.
    @param container_name: Name of a container.
    Returns:
        Boolean value. True represents the container is running
    """
    result = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
    return result["stdout_lines"][0].strip() == "true"


def check_container_state(duthost, container_name, should_be_running):
    """Determines whether a container is in the expected state (running/not running)
    @param duthost: Host DUT.
    @param container_name: Name of container.
    @param should_be_running: Boolean value.
    Returns:
        This function will return True if the container was in the expected state.
        Otherwise, it will return False.
    """
    is_running = is_container_running(duthost, container_name)
    return is_running == should_be_running


def is_hitting_start_limit(duthost, container_name):
    """Checks whether the container can not be restarted is due to start-limit-hit.
    @param duthost: Host DUT.
    @param ontainer_name: name of a container.
    Returns:
        If start limitation was hit, then this function will return True. Otherwise
        it returns False.
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(container_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False


def clear_failed_flag_and_restart(duthost, container_name):
    """Clears the failed flag of a container and restart it.
    @param duthost: Host DUT.
    @param container_name: name of a container.
    Returns:
        None
    """
    logger.info("{} hits start limit and clear reset-failed flag".format(container_name))
    duthost.shell("sudo systemctl reset-failed {}.service".format(container_name))
    duthost.shell("sudo systemctl start {}.service".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart container '{}' after reset-failed was cleared".format(container_name))


def get_group_program_info(duthost, container_name, group_name):
    """Gets program names, running status and their pids by analyzing the command
       output of "docker exec <container_name> supervisorctl status". Program name
       at here represents a program which is part of group <group_name>

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.

    Returns:
        A dictionary where keys are the program names and values are their running
        status and pids.
    """
    group_program_info = defaultdict(list)
    program_name = None
    program_status = None
    program_pid = None

    program_list = duthost.shell("docker exec {} supervisorctl status".format(container_name), module_ignore_errors=True)
    for program_info in program_list["stdout_lines"]:
        if program_info.find(group_name) != -1:
            program_name = program_info.split()[0].split(':')[1].strip()
            program_status = program_info.split()[1].strip()
            if program_status in ["EXITED", "STOPPED", "STARTING"]:
                program_pid = -1
            else:
                program_pid = int(program_info.split()[3].strip(','))

            group_program_info[program_name].append(program_status)
            group_program_info[program_name].append(program_pid)

            if program_pid != -1:
                logger.info("Found program '{}' in the '{}' state with pid {}"
                            .format(program_name, program_status, program_pid))

    return group_program_info


def get_program_info(duthost, container_name, program_name):
    """Gets program running status and its pid by analyzing the command
       output of "docker exec <container_name> supervisorctl status"

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.

    Return:
        Program running status and its pid.
    """
    program_status = None
    program_pid = -1

    program_list = duthost.shell("docker exec {} supervisorctl status".format(container_name), module_ignore_errors=True)
    for program_info in program_list["stdout_lines"]:
        if program_info.find(program_name) != -1:
            program_status = program_info.split()[1].strip()
            if program_status == "RUNNING":
                program_pid = int(program_info.split()[3].strip(','))
            break

    if program_pid != -1:
        logger.info("Found program '{}' in the '{}' state with pid {}"
                    .format(program_name, program_status, program_pid))

    return program_status, program_pid


def get_disabled_container_list(duthost):
    """Gets the container/service names which are disabled.

    Args:
        duthost: Host DUT.

    Return:
        A list includes the names of disabled containers/services
    """
    disabled_containers = []

    container_status, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "Failed to get status ('enabled'|'disabled') of containers. Exiting...")

    for container_name, status in container_status.items():
        if "disabled" in status:
            disabled_containers.append(container_name)

    return disabled_containers

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_host_visible_vars
from tests.common.utilities import wait_until

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_RESTART_THRESHOLD_SECS = 180


def is_supervisor_node(inv_files, hostname):
    """Check if the current node is a supervisor node in case of multi-DUT.
     @param inv_files: List of inventory file paths, In tests,
            you can be get it from get_inventory_files in tests.common.utilities
     @param hostname: hostname as defined in the inventory
    Returns:
          Currently, we are using 'type' in the inventory to make the decision. If 'type' for the node is defined in
          the inventory, and it is 'supervisor', then return True, else return False. In future, we can change this
          logic if possible to derive it from the DUT.
    """
    node_type = get_host_visible_vars(inv_files, hostname, variable='type')
    if node_type and node_type == 'supervisor':
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

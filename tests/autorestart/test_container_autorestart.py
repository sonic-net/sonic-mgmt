"""
Test the auto-restart feature of containers
"""
import logging
import time
from collections import defaultdict

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_STOP_THRESHOLD_SECS = 30
CONTAINER_RESTART_THRESHOLD_SECS = 180


def get_group_program_info(duthost, container_name, group_name):
    """
    @summary: Get program names, running status and their pids by analyzing the command
              output of "docker exec <container_name> supervisorctl status". Program name
              at here represents a program which is part of group <group_name>
    @return: A dictionary where keys are the program names and values are their running
             status and pids
    """
    group_program_info = defaultdict(list)
    program_name = None
    program_status = None
    program_pid = -1

    program_list = duthost.shell("docker exec {} supervisorctl status".format(container_name))
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

    return group_program_info


def get_program_info(duthost, container_name, program_name):
    """
    @summary: Get program running status and its pid by analyzing the command
              output of "docker exec <container_name> supervisorctl status"
    @return:  Program running status and its pid
    """
    program_status = None
    program_pid = -1

    program_list = duthost.shell("docker exec {} supervisorctl status".format(container_name))
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
    """
    @summary: Get the container/service names which are disabled
    @return: A list includes the names of disabled containers/services
    """
    disabled_containers = []

    container_status, succeeded = duthost.get_feature_status()
    if not succeeded:
        pytest.fail("Failed to get status ('enabled'|'disabled') of containers. Exiting...")

    for container_name, status in container_status.items():
        if status == "disabled":
            disabled_containers.append(container_name)

    return disabled_containers


def is_container_running(duthost, container_name):
    """
    @summary: Decide whether the container is running or not
    @return:  Boolean value. True represents the container is running
    """
    result = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
    return result["stdout_lines"][0].strip() == "true"


def check_container_state(duthost, container_name, should_be_running):
    """
    @summary: Determine whether a container is in the expected state (running/not running)
    """
    is_running = is_container_running(duthost, container_name)
    return is_running == should_be_running


def kill_process_by_pid(duthost, container_name, program_name, program_pid):
    """
    @summary: Kill a process in the specified container by its pid
    """
    kill_cmd_result = duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, program_pid))

    # Get the exit code of 'kill' command
    exit_code = kill_cmd_result["rc"]
    if exit_code != 0:
        pytest.fail("Failed to stop program '{}' before test".format(program_name))

    logger.info("Program '{}' in container '{}' was stopped successfully"
                .format(program_name, container_name))


def is_hiting_start_limit(duthost, container_name):
    """
    @summary: Determine whether the container can not be restarted is due to
              start-limit-hit or not
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(container_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False


def verify_autorestart_with_critical_process(duthost, container_name, program_name,
                                             program_status, program_pid):
    """
    @summary: Kill a critical process in a container to verify whether the container
              is stopped and restarted correctly
    """
    if program_status == "RUNNING":
        kill_process_by_pid(duthost, container_name, program_name, program_pid)
    elif program_status in ["EXITED", "STOPPED", "STARTING"]:
        pytest.fail("Program '{}' in container '{}' is in the '{}' state, expected 'RUNNING'"
                    .format(program_name, container_name, program_status))
    else:
        pytest.fail("Failed to find program '{}' in container '{}'"
                    .format(program_name, container_name))

    logger.info("Waiting until container '{}' is stopped...".format(container_name))
    stopped = wait_until(CONTAINER_STOP_THRESHOLD_SECS,
                         CONTAINER_CHECK_INTERVAL_SECS,
                         check_container_state, duthost, container_name, False)
    pytest_assert(stopped, "Failed to stop container '{}'".format(container_name))
    logger.info("Container '{}' was stopped".format(container_name))

    logger.info("Waiting until container '{}' is restarted...".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           check_container_state, duthost, container_name, True)
    if not restarted:
        if is_hiting_start_limit(duthost, container_name):
            logger.info("{} hits start limit and clear reset-failed flag".format(container_name))
            duthost.shell("sudo systemctl reset-failed {}.service".format(container_name))
            duthost.shell("sudo systemctl start {}.service".format(container_name))
            restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                                   CONTAINER_CHECK_INTERVAL_SECS,
                                   check_container_state, duthost, container_name, True)
            pytest_assert(restarted, "Failed to restart container '{}' after reset-failed was cleared".format(container_name))
        else:
            pytest.fail("Failed to restart container '{}'".format(container_name))

    logger.info("Container '{}' was restarted".format(container_name))


def verify_no_autorestart_with_non_critical_process(duthost, container_name, program_name,
                                                    program_status, program_pid):
    """
    @summary: Kill a non-critical process in a container to verify whether the container
              remains in the running state
    """
    if program_status == "RUNNING":
        kill_process_by_pid(duthost, container_name, program_name, program_pid)
    elif program_status in ["EXITED", "STOPPED", "STARTING"]:
        pytest.fail("Program '{}' in container '{}' is in the '{}' state, expected 'RUNNING'"
                    .format(program_name, container_name, program_status))
    else:
        pytest.fail("Failed to find program '{}' in container '{}'"
                    .format(program_name, container_name))

    logger.info("Waiting to ensure container '{}' does not stop...".format(container_name))
    stopped = wait_until(CONTAINER_STOP_THRESHOLD_SECS,
                         CONTAINER_CHECK_INTERVAL_SECS,
                         check_container_state, duthost, container_name, False)
    pytest_assert(not stopped, "Container '{}' was stopped unexpectedly".format(container_name))
    logger.info("Container '{}' did not stop".format(container_name))
    logger.info("Restart the program '{}' in container '{}'".format(program_name, container_name))
    duthost.shell("docker exec {} supervisorctl start {}".format(container_name, program_name))


def test_containers_autorestart(duthost, tbinfo):
    """
    @summary: Test the auto-restart feature of each container against two scenarios: killing
              a non-critical process to verify the container is still running; killing each
              critical process to verify the container will be stopped and restarted
    """
    container_autorestart_states = duthost.get_container_autorestart_states()
    disabled_containers = get_disabled_container_list(duthost)

    for container_name in container_autorestart_states.keys():
        # Skip testing the database container, radv container on T1 devices and containers/services which are disabled
        if (container_name in disabled_containers or container_name == "database"
                or (container_name == "radv" and tbinfo["topo"]["type"] != "t0")):
            logger.warning("Skip testing the container '{}'".format(container_name))
            continue

        is_running = is_container_running(duthost, container_name)
        if not is_running:
            pytest.fail("Container '{}' is not running. Exiting...".format(container_name))

        logger.info("Start testing the container '{}'...".format(container_name))

        restore_disabled_state = False
        if container_autorestart_states[container_name] == "disabled":
            logger.info("Change auto-restart state of container '{}' to be 'enabled'".format(container_name))
            duthost.shell("sudo config feature autorestart {} enabled".format(container_name))
            restore_disabled_state = True

        # Currently we select 'rsyslogd' as non-critical processes for testing based on
        # the assumption that every container has an 'rsyslogd' process running and it is not
        # considered to be a critical process
        program_status, program_pid = get_program_info(duthost, container_name, "rsyslogd")
        verify_no_autorestart_with_non_critical_process(duthost, container_name, "rsyslogd",
                                                        program_status, program_pid)

        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name)
        if not succeeded:
            pytest.fail("Failed to get critical group and process lists of container '{}'".format(container_name))

        for critical_process in critical_process_list:
            program_status, program_pid = get_program_info(duthost, container_name, critical_process)
            verify_autorestart_with_critical_process(duthost, container_name, critical_process,
                                                     program_status, program_pid)
            # Sleep 20 seconds in order to let the processes come into live after container is restarted.
            # We will uncomment the following line once the "extended" mode is added
            # time.sleep(20)
            # We are currently only testing one critical process, that is why we use 'break'. Once
            # we add the "extended" mode, we will remove this statement
            break

        for critical_group in critical_group_list:
            group_program_info = get_group_program_info(duthost, container_name, critical_group)
            for program_name in group_program_info:
                verify_autorestart_with_critical_process(duthost, container_name, program_name,
                                                         group_program_info[program_name][0],
                                                         group_program_info[program_name][1])
                # We are currently only testing one critical program for each critical group, which is
                # why we use 'break' statement. Once we add the "extended" mode, we will remove this
                # statement
                break

        # After these two containers are restarted, we need wait to give their dependent containers
        # a chance to restart
        if container_name in ["syncd", "swss"]:
            logger.info("Sleep 20 seconds after testing the container '{}'...".format(container_name))
            time.sleep(20)

        if restore_disabled_state:
            logger.info("Restore auto-restart state of container '{}' to 'disabled'".format(container_name))
            duthost.shell("sudo config feature autorestart {} disabled".format(container_name))

        logger.info("End of testing the container '{}'".format(container_name))

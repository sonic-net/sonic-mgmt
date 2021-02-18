"""
Test the feature of monitoring critical processes by Supervisord.
"""
from collections import defaultdict
import logging

import pytest

from pkg_resources import parse_version
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_utils import get_program_info
from tests.common.helpers.dut_utils import get_group_program_info
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_RESTART_THRESHOLD_SECS = 180


@pytest.fixture(autouse=True, scope='module')
def config_reload_after_tests(duthost):
    yield
    config_reload(duthost)


@pytest.fixture(autouse=True, scope='module')
def disable_and_enable_autorestart(duthost):
    """Changes the autorestart of containers from `enabled` to `disabled` before testing.
       and Rolls them back after testing.

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    containers_autorestart_states = duthost.get_container_autorestart_states()
    disabled_autorestart_containers = []

    for container_name, state in containers_autorestart_states.items():
        if state != "disabled":
            logger.info("Disabling the autorestart of container '{}'.".format(container_name))
            command_disable_autorestart = "sudo config feature autorestart {} disabled".format(container_name)
            command_output = duthost.shell(command_disable_autorestart)
            exit_code = command_output["rc"]
            pytest_assert(exit_code == 0, "Failed to disable the autorestart of container '{}'".format(container_name))
            logger.info("The autorestart of container '{}' was disabled.".format(container_name))
            disabled_autorestart_containers.append(container_name)

    yield

    for container_name in disabled_autorestart_containers:
        logger.info("Enabling the autorestart of container '{}'...".format(container_name))
        command_output = duthost.shell("sudo config feature autorestart {} enabled".format(container_name))
        exit_code = command_output["rc"]
        pytest_assert(exit_code == 0, "Failed to enable the autorestart of container '{}'".format(container_name))
        logger.info("The autorestart of container '{}' is enabled.".format(container_name))


@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT was 201911 or old version.

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    pytest_require(parse_version(duthost.kernel_version) > parse_version("4.9.0"),
                   "Test was not supported for 201911 and older image versions!")


def check_all_critical_processes_status(duthost):
    """Post-checks the status of critical processes.

    Args:
        duthost: Hostname of DUT.

    Returns:
        This function will return True if all critical processes are running.
        Otherwise it will return False.
    """
    processes_status = duthost.all_critical_process_status()
    for container_name, processes in processes_status.items():
        if processes["status"] is False or len(processes["exited_critical_process"]) > 0:
            return False

    return True


def post_test_check(duthost, up_bgp_neighbors):
    """Post-checks the status of critical processes and state of BGP sessions.

    Args:
        duthost: Hostname of DUT.
        up_bgp_neighbors: An IP list contains the established BGP sessions with
        this DUT.

    Returns:
        This function will return True if all critical processes are running and
        all BGP sessions are established. Otherwise it will return False.
    """
    return check_all_critical_processes_status(duthost) and duthost.check_bgp_session_state(up_bgp_neighbors, "established")


def postcheck_critical_processes_status(duthost, up_bgp_neighbors):
    """Calls the sub-functions to post-check the status of critical processes and
       state of BGP sessions.

    Args:
        duthost: Hostname of DUT.
        up_bgp_neighbors: An IP list contains the established BGP sessions with
        this DUT.

    Returns:
        If all critical processes are running and all BGP sessions are established, it
        returns True. Otherwise it will call the function to do post-check every 30 seconds
        for 3 minutes. It will return False after timeout.
    """
    logger.info("Post-checking status of critical processes and BGP sessions...")
    return wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS,
                      post_test_check, duthost, up_bgp_neighbors)


def get_expected_alerting_messages(duthost, containers_in_namespaces):
    """Generates the expected alerting messages from the stopped critical processes in each namespace.

    Args:
        duthost: Hostname of DUT.
        containers_in_namespaces: A dictionary where keys are container names and
        values are lists which contains ids of namespaces this container should reside in.

    Returns:
        None.
    """
    expected_alerting_messages = []
    logger.info("Generating the alerting messages... ")

    for container_name in containers_in_namespaces.keys():
        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name)
        pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'".format(container_name))

        namespaces = containers_in_namespaces[container_name]
        for namespace_id in namespaces:
            namespace_name = "host"
            if namespace_id != "host":
                namespace_name = "asic" + namesapce_id

            for critical_process in critical_process_list:
                # Skip 'dsserve' process since it was not managed by supervisord
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if container_name == "syncd" and critical_process == "dsserve":
                    continue
                expected_alerting_messages.append(".*Process '{}' is not running in namespace '{}'.*".format(critical_process, namespace_name))

            for critical_group in critical_group_list:
                group_program_info = get_group_program_info(duthost, container_name, critical_group)
                for program_name in group_program_info:
                    expected_alerting_messages.append(".*Process '{}' is not running in namespace '{}'.*".format(program_name, namespace_name))

    logger.info("Generating the alerting message was done!")
    return expected_alerting_messages


def parse_config_entry(config_info):
    """Parse a single entry of `FEATURE` table.

    Args:
        config_info: A list which contains the detailed configuration of a
        container in `FEATURE` table.

    Returns:
        is_enabled: A string ("enabled|disabled") shows whether this container
        is enabled or not.
        has_global_scope: A string ("True|False") shows if a device has multi-ASIC,
        whether the container should be running in the host.
        has_per_asic_scope: A string ("True|False") shows if a device has multi-ASIC,
        whether the container should be running in each ASIC.
    """
    is_enabled = ""
    has_global_scope = ""
    has_per_asic_scope = ""

    for index, item in enumerate(config_info):
        if item == "state":
            is_enabled = config_info[index + 1]
        elif item == "has_global_scope":
            has_global_scope = config_info[index + 1]
        elif item == "has_per_asic_scope":
            has_per_asic_scope = config_info[index + 1]

    return is_enabled, has_global_scope, has_per_asic_scope


def parse_feature_table(duthost, num_asics, skip_containers):
    """Parses the `FEATURE` table in Config_DB.

    This function will parse the `FEATURE` table in Config_DB to get which containers
    were enabled and which namespaces these enabled containers reside in.

    Args:
        duthost: Hostname of DUT.
        num_asics: An integer shows number of ASICs on the DUT.
        skip_containers: A list shows which containers will be skipped.

    Returns:
        A dictionary where keys are container names and values are a list which contains
        ids of namespaces this container should reside in such as {lldp: ["host", "0", "1"]}
    """
    container_list = []
    containers_in_namespaces = defaultdict(list)

    container_list_command = "sonic-db-cli CONFIG_DB keys \"FEATURE|*\""
    command_output = duthost.shell(container_list_command)
    exit_code = command_output["rc"]
    pytest_assert(exit_code == 0, "Failed to get keys (container names) in `FEATURE` table")
    for line in command_output["stdout_lines"]:
        container_name = line.split("|")[1].strip()
        if container_name not in skip_containers:
            container_list.append(container_name)

    for container_name in container_list:
        command_config_entry = "sonic-db-cli CONFIG_DB hgetall \"FEATURE|{}\"".format(container_name)
        command_output = duthost.shell(command_config_entry)
        exit_code = command_output["rc"]
        pytest_assert(exit_code == 0, "Failed to get configuration of container '{}' in `FEATURE` table"
                      .format(container_name))

        is_enabled, has_global_scope, has_per_asic_scope = parse_config_entry(command_output["stdout_lines"])
        if is_enabled != "disabled":
            logger.info("Parsing the configuration of container '{}' in Config_DB.".format(container_name))
            if num_asics > 1:
                if has_global_scope == "True":
                    containers_in_namespaces[container_name].append("host")
                if has_per_asic_scope == "True":
                    for asic_id in range(num_asics):
                        containers_in_namespaces[container_name].append(str(asic_id))
            else:
                containers_in_namespaces[container_name].append("host")
            logger.info("The configuration of container '{}' in `FEATURE` table was retrieved.".format(container_name))

    return containers_in_namespaces


def kill_process_by_pid(duthost, container_name, program_name, program_pid):
    """Kills a process in the specified container by its pid.

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.
        program_pid: An integer represents the PID of a process.

    Returns:
        None.
    """
    kill_cmd_result = duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, program_pid))

    # Get the exit code of 'kill' command
    exit_code = kill_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to stop program '{}' before test".format(program_name))

    logger.info("Program '{}' in container '{}' was stopped successfully"
                .format(program_name, container_name))


def check_and_kill_process(duthost, container_name, program_name, program_status, program_pid):
    """Checks the running status of a critical process. If it is running, kill it. Otherwise,
       fail this test.

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.
        program_pid: An integer represents the PID of a process.

    Returns:
        None.
    """
    if program_status == "RUNNING":
        kill_process_by_pid(duthost, container_name, program_name, program_pid)
    elif program_status in ["EXITED", "STOPPED", "STARTING"]:
        pytest.fail("Program '{}' in container '{}' is in the '{}' state, expected 'RUNNING'"
                    .format(program_name, container_name, program_status))
    else:
        pytest.fail("Failed to find program '{}' in container '{}'"
                    .format(program_name, container_name))


def stop_critical_processes(duthost, containers_in_namespaces):
    """Gets all critical processes of each enabled container and stops them from running.

    Args:
        duthost: Hostname of DUT.
        containers_in_namespaces: A dictionary where keys are container names and
        values are lists which contains ids of namespaces this container should reside in.

    Returns:
        None.
    """
    for container_name in containers_in_namespaces.keys():
        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name)
        pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'".format(container_name))

        namespaces = containers_in_namespaces[container_name]
        for namespace_id in namespaces:
            container_name_in_namespace = container_name
            if namespace_id != "host":
                container_name_in_namespace += namesapce_id

            for critical_process in critical_process_list:
                # Skip 'dsserve' process since it was not managed by supervisord
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if container_name_in_namespace == "syncd" and critical_process == "dsserve":
                    continue

                program_status, program_pid = get_program_info(duthost, container_name_in_namespace, critical_process)
                check_and_kill_process(duthost, container_name_in_namespace, critical_process, program_status, program_pid)

            for critical_group in critical_group_list:
                group_program_info = get_group_program_info(duthost, container_name, critical_group)
                for program_name in group_program_info:
                    check_and_kill_process(duthost, container_name_in_namespace, program_name,
                                           group_program_info[program_name][0],
                                           group_program_info[program_name][1])


def check_and_restart_process(duthost, container_name, critical_process):
    """Checks the running status of a critical process and restarts it if it was not running.

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows name of a container.
        critical_process: A string shows name of a process.

    Returns:
        None.
    """
    logger.info("Checking whether process '{}' in container '{}' is running...".format(critical_process, container_name))
    program_status, program_pid = get_program_info(duthost, container_name, critical_process)
    if program_status == "RUNNING":
        logger.info("Process '{}' in container '{} is running.".format(critical_process, container_name))
    else:
        logger.info("Process '{}' in container '{}' is not running and restart it...".format(critical_process, container_name))
        command_output = duthost.shell("docker exec {} supervisorctl restart {}".format(container_name, critical_process))
        if command_output["rc"] == 0:
            logger.info("Process '{}' in container '{}' is restarted.".format(critical_process, container_name))
        else:
            pytest.fail("Failed to restart process '{}' in container '{}'.".format(critical_process, container_name))


def restart_critical_processes(duthost, containers_in_namespaces):
    """Restarts all critical process in enabled containers.

    Args:
        duthost: Hostname of DUT.
        containers_in_namespaces: A dictionary where keys are container names and
        values are lists which contains ids of namespaces this container should reside in.

    Returns:
        None.
    """
    for container_name in containers_in_namespaces.keys():
        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name)
        pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'".format(container_name))

        namespaces = containers_in_namespaces[container_name]
        for namespace_id in namespaces:
            container_name_in_namespace = container_name
            if namespace_id != "host":
                container_name_in_namespace += namesapce_id

            for critical_process in critical_process_list:
                # Skip 'dsserve' process since it was not managed by supervisord
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if container_name_in_namespace == "syncd" and critical_process == "dsserve":
                    continue

                check_and_restart_process(duthost, container_name_in_namespace, critical_process)

            for critical_group in critical_group_list:
                group_program_info = get_group_program_info(duthost, container_name_in_namespace, critical_group)
                for program_name in group_program_info:
                    check_and_restart_process(duthost, container_name_in_namespace, program_name)


def test_monitoring_critical_processes(duthosts, rand_one_dut_hostname, tbinfo):
    """Tests the feature of monitoring critical processes with Supervisord.

    This function will check whether names of critical processes will appear
    in the syslog if the autorestart were disabled and these critical processes were
    mnually stopped.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: hostname of DUT.
        tbinfo: Testbed information.

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="monitoring_critical_processes")
    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]

    skip_containers = []
    skip_containers.append("database")
    # Skip 'radv' container on devices whose role is not T0.
    if tbinfo["topo"]["type"] != "t0":
        skip_containers.append("radv")

    num_asics = duthost.num_asics()
    containers_in_namespaces = parse_feature_table(duthost, num_asics, skip_containers)

    expected_alerting_messages = get_expected_alerting_messages(duthost, containers_in_namespaces)
    loganalyzer.expect_regex.extend(expected_alerting_messages)
    marker = loganalyzer.init()

    stop_critical_processes(duthost, containers_in_namespaces)

    # Wait for 70 seconds such that Supervisord has a chance to write alerting message into syslog.
    logger.info("Sleep 70 seconds to wait for the alerting message...")
    time.sleep(70)

    logger.info("Checking the alerting messages from syslog...")
    loganalyzer.analyze(marker)
    logger.info("Found all the expected alerting messages from syslog!")

    logger.info("Executing the config reload...")
    config_reload(duthost)
    logger.info("Executing the config reload was done!")

    restart_critical_processes(duthost, containers_in_namespaces)

    if not postcheck_critical_processes_status(duthost, up_bgp_neighbors):
        pytest.fail("Post-check failed after testing the container checker!")
    logger.info("Post-checking status of critical processes and BGP sessions was done!")

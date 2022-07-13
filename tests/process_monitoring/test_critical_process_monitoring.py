"""
Test the feature of monitoring critical processes on 20191130 image (Monit),
202012 and newer images (Supervisor)
"""
from collections import defaultdict
import logging

import pytest

from pkg_resources import parse_version
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.constants import DEFAULT_ASIC_ID, NAMESPACE_PREFIX
from tests.common.helpers.dut_utils import get_program_info
from tests.common.helpers.dut_utils import get_group_program_info
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_RESTART_THRESHOLD_SECS = 180
POST_CHECK_INTERVAL_SECS = 1
POST_CHECK_THRESHOLD_SECS = 360


@pytest.fixture(autouse=True, scope='module')
def config_reload_after_tests(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    yield
    config_reload(duthost)


@pytest.fixture(autouse=True, scope='module')
def disable_and_enable_autorestart(duthosts, rand_one_dut_hostname):
    """Changes the autorestart of containers from `enabled` to `disabled` before testing.
       and Rolls them back after testing.

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    containers_autorestart_states = duthost.get_container_autorestart_states()
    disabled_autorestart_containers = []

    for container_name, state in containers_autorestart_states.items():
        if "enabled" in state:
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
def check_image_version(duthosts, rand_one_dut_hostname):
    """Skips this test if the SONiC image installed on DUT is 20191130.70 or older image version.

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    pytest_require(("20191130" in duthost.os_version and parse_version(duthost.os_version) > parse_version("20191130.72"))
                   or parse_version(duthost.kernel_version) > parse_version("4.9.0"),
                   "Test is not supported for 20191130.72 and older image versions!")


@pytest.fixture(autouse=True, scope="module")
def modify_monit_config_and_restart(duthosts, rand_one_dut_hostname):
    """Backup Monit configuration file, then customize and restart it before testing. Restore original
    Monit configuration file and restart it after testing.

    Args:
        duthost: Hostname of DuT.

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    logger.info("Back up Monit configuration file ...")
    duthost.shell("sudo cp -f /etc/monit/monitrc /tmp/")

    logger.info("Modifying Monit config to eliminate start delay and decrease interval ...")
    duthost.shell("sudo sed -i 's/set daemon 60/set daemon 10/' /etc/monit/monitrc")
    duthost.shell("sudo sed -i '/with start delay 300/s/^./#/' /etc/monit/monitrc")

    logger.info("Restart Monit service ...")
    duthost.shell("sudo systemctl restart monit")

    yield

    logger.info("Restore original Monit configuration ...")
    duthost.shell("sudo mv -f /tmp/monitrc /etc/monit/")

    logger.info("Restart Monit service ...")
    duthost.shell("sudo systemctl restart monit")


def check_all_critical_processes_running(duthost):
    """Determine whether all critical processes are running on the DUT or not.

    Args:
        duthost: Hostname of DUT.

    Returns:
        This function will return True if all critical processes are running.
        Otherwise return False.
    """
    processes_status = duthost.all_critical_process_status()
    for container_name, processes in processes_status.items():
        if processes["status"] is False or len(processes["exited_critical_process"]) > 0:
            logger.info("The status of checking process in container '{}' is: {}"
                        .format(container_name, processes["status"]))
            logger.info("The processes not running in container '{}' are: '{}'"
                        .format(container_name, processes["exited_critical_process"]))
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
    return check_all_critical_processes_running(duthost) and duthost.check_bgp_session_state(up_bgp_neighbors, "established")


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
    return wait_until(POST_CHECK_THRESHOLD_SECS, POST_CHECK_INTERVAL_SECS, 0,
                      post_test_check, duthost, up_bgp_neighbors)


def get_critical_process_from_monit(duthost, container_name):
    """Gets command lines of critical processes by parsing the Monit configration file
    of each container.

    Args:
        duthost: Hostname of DuT.
        container_name: Name of container.

    Returns:
        A list contains command lines of critical processes. Bool varaible indicates
        whether the operation in this funciton was done successfully or not.
    """
    critical_process_list = []
    succeeded = True

    monit_config_file_name = "monit_" + container_name
    file_content = duthost.shell("bash -c '[ -f /etc/monit/conf.d/{0} ] && cat /etc/monit/conf.d/{0}'"
                                 .format(monit_config_file_name))
    if file_content["rc"] != 0:
        succeeded = False
        return critical_process_list, succeeded

    for line in file_content["stdout_lines"]:
        if "process_checker" in line:
            command_line = line.split(" {} ".format(container_name))[1].strip(" \n\"")
            critical_process_list.append(command_line)

    return critical_process_list, succeeded


def get_expected_alerting_messages_monit(duthost, containers_in_namespaces):
    """Generates the regex of expected alerting messages for processes in each container.
    These alerting messages will be matched against those in syslog generated by Monit.

    Args:
        duthost: Hostname of DUT.
        containers_in_namespaces: A dictionary where keys are container names and
        values are lists which contains ids of namespaces this container should reside in.

    Returns:
        A list contains the regex of alerting messages.
    """
    expected_alerting_messages = []

    logger.info("Generating the regex of expected alerting messages ...")
    for container_name in containers_in_namespaces.keys():
        namespace_ids = containers_in_namespaces[container_name]

        critical_process_list, succeeded = get_critical_process_from_monit(duthost, container_name)
        pytest_assert(succeeded, "Failed to get critical processes of container '{}' from Monit config file"
                      .format(container_name))

        for namespace_id in namespace_ids:
            namespace_name = "host"
            container_name_in_namespace = container_name
            if namespace_id != DEFAULT_ASIC_ID:
                namespace_name = NAMESPACE_PREFIX + namespace_id
                container_name_in_namespace += namespace_id

            logger.info("Generating the regex of expected alerting messages for container '{}'..."
                        .format(container_name_in_namespace))
            for critical_process in critical_process_list:
                # Skip 'syncd' process on devices with Broadcom since it was not managed by Supervisord.
                # Although there is an entry in Supervisord config file showing 'syncd'
                # is managed by Supervisord, the process managed by Supervisord is actually
                # the process 'dsserve' not 'syncd'.
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if ("syncd" in container_name_in_namespace and "broadcom" in duthost.facts["asic_type"]
                        and "/usr/bin/dsserve" not in critical_process):
                    continue

                # Skip 'thermalctld' and 'syseepromd' processes in PMon container
                # since they are set to auto-restart if exited unexpectedly.
                # TODO: Should remove `sensord` from the following if statement once it is added
                # into the 'critical_processes' file.
                if "pmon" in container_name_in_namespace and ("thermalctld" in critical_process
                                                              or "syseepromd" in critical_process
                                                              or "sensord" in critical_process):
                    continue

                # Skip 'bgpmon' process in BGP container since it is set to auto-restart if exited unexpectedly.
                if "bgp" in container_name_in_namespace and "bgpmon" in critical_process:
                    continue

                logger.info("Generating the regex of expected alerting message for process '{}' in container '{}'"
                            .format(critical_process, container_name_in_namespace))

                if namespace_id != DEFAULT_ASIC_ID:
                    expected_alerting_messages.append(".*'{}' is not running.*in namespace.*{}"
                                                      .format(critical_process, namespace_name))
                else:
                    expected_alerting_messages.append(".*'{}' is not running.*in {}".format(critical_process, namespace_name))

            logger.info("Generating the regex of expected alerting messages for container '{}' was done!"
                        .format(container_name_in_namespace))

    return expected_alerting_messages


def get_expected_alerting_messages_supervisor(duthost, containers_in_namespaces):
    """Generates the regex of expected alerting messages for the critical processes in each container.
    These alerting messages will be matched against those in syslog generated by Supervisord.

    Args:
        duthost: Hostname of DUT.
        containers_in_namespaces: A dictionary where keys are container names and
        values are lists which contains ids of namespaces this container should reside in.

    Returns:
        A list contains the regex of alerting messages.
    """
    expected_alerting_messages = []

    logger.info("Generating the regex of expected alerting messages ...")
    for container_name in containers_in_namespaces.keys():
        namespace_ids = containers_in_namespaces[container_name]
        container_name_in_namespace = container_name
        # If a container is only running on host, then namespace_ids is [None]
        # If a container is running on multi-ASIC, then namespace_ids is [0, 1, ...]
        # If a container is running on host and multi-ASICs, then namespace_ids is [None, 0, 1, ...]
        if len(namespace_ids) > 2:
            container_name_in_namespace += namespace_ids[1]

        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name_in_namespace)
        pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'"
                      .format(container_name_in_namespace))

        for namespace_id in namespace_ids:
            namespace_name = "host"
            container_name_in_namespace = container_name
            if namespace_id != DEFAULT_ASIC_ID:
                namespace_name = NAMESPACE_PREFIX + namespace_id
                container_name_in_namespace += namespace_id

            logger.info("Generating the regex of expected alerting messages for container '{}'..."
                        .format(container_name_in_namespace))
            for critical_process in critical_process_list:
                # Skip 'dsserve' process since it was not managed by supervisord
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if "syncd" in container_name_in_namespace and critical_process == "dsserve":
                    continue
                logger.info("Generating the regex of expected alerting message for process '{}' in container '{}'"
                            .format(critical_process, container_name_in_namespace))
                expected_alerting_messages.append(".*Process '{}' is not running in namespace '{}'.*"
                                                  .format(critical_process, namespace_name))

            for critical_group in critical_group_list:
                group_program_info = get_group_program_info(duthost, container_name_in_namespace, critical_group)
                for program_name in group_program_info:
                    logger.info("Generating the regex of expected alerting message for process '{}' in container '{}'"
                                .format(program_name, container_name_in_namespace))
                    expected_alerting_messages.append(".*Process '{}' is not running in namespace '{}'.*"
                                                      .format(program_name, namespace_name))

            logger.info("Generating the regex of expected alerting messages for container '{}' was done!"
                        .format(container_name_in_namespace))

    return expected_alerting_messages


def get_containers_namespace_ids(duthost, skip_containers):
    """
    This function will get namespace ids where a container was running.

    Args:
        duthost: Hostname of DUT.
        skip_containers: A list shows which containers should be skipped for testing.

    Returns:
        A dictionary where keys are container names and values are a list which contains
        ids of namespaces this container should reside in such as {lldp: [DEFAULT_ASIC_ID, "0", "1"]}
    """
    containers_in_namespaces = defaultdict(list)

    logger.info("Getting the namespace ids for each container...")
    containers_states, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "Failed to get feature status of containers!")

    for container_name, state in containers_states.items():
        if container_name not in skip_containers and state not in ["disabled", "always_disabled"]:
            namespace_ids, succeeded = duthost.get_namespace_ids(container_name)
            pytest_assert(succeeded, "Failed to get namespace ids of container '{}'".format(container_name))
            containers_in_namespaces[container_name] = namespace_ids

    logger.info("Getting the namespace ids for each container was done!")

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
    if "20191130" in duthost.os_version:
        kill_cmd_result = duthost.shell("docker exec {} supervisorctl stop {}".format(container_name, program_name))
    else:
        # If we used the command `supervisorctl stop <proc_name>' to stop process,
        # Supervisord will treat the exit code of process as expected and it will not generate
        # alerting message.
        kill_cmd_result = duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, program_pid))

    # Get the exit code of 'kill' or 'supervisorctl stop' command
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
    """Gets critical processes of each running container and then stops them from running.

    Args:
        duthost: Hostname of DUT.
        containers_in_namespaces: A dictionary where keys are container names and
        values are lists which contains ids of namespaces this container should reside in.

    Returns:
        None.
    """
    for container_name in containers_in_namespaces.keys():
        namespace_ids = containers_in_namespaces[container_name]
        container_name_in_namespace = container_name
        # If a container is only running on host, then namespace_ids is [None]
        # If a container is running on multi-ASIC, then namespace_ids is [0, 1, ...]
        # If a container is running on host and multi-ASICs, then namespace_ids is [None, 0, 1, ...]
        if len(namespace_ids) >= 2:
            container_name_in_namespace += namespace_ids[1]

        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name_in_namespace)
        pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'"
                      .format(container_name_in_namespace))

        for namespace_id in namespace_ids:
            container_name_in_namespace = container_name
            if namespace_id != DEFAULT_ASIC_ID:
                container_name_in_namespace += namespace_id

            for critical_process in critical_process_list:
                # Skip 'dsserve' process since it was not managed by supervisord
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if "syncd" in container_name_in_namespace and critical_process == "dsserve":
                    continue

                program_status, program_pid = get_program_info(duthost, container_name_in_namespace, critical_process)
                check_and_kill_process(duthost, container_name_in_namespace, critical_process, program_status, program_pid)

            for critical_group in critical_group_list:
                group_program_info = get_group_program_info(duthost, container_name_in_namespace, critical_group)
                for program_name in group_program_info:
                    check_and_kill_process(duthost, container_name_in_namespace, critical_group + ":" + program_name,
                                           group_program_info[program_name][0],
                                           group_program_info[program_name][1])


def ensure_process_is_running(duthost, container_name, critical_process):
    """Checks the running status of a critical process and starts it if it was not running.

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
        logger.info("Process '{}' in container '{}' is not running and start it...".format(critical_process, container_name))
        command_output = duthost.shell("docker exec {} supervisorctl start {}".format(container_name, critical_process))
        if command_output["rc"] == 0:
            logger.info("Process '{}' in container '{}' is started.".format(critical_process, container_name))
        else:
            pytest.fail("Failed to start process '{}' in container '{}'.".format(critical_process, container_name))


def ensure_all_critical_processes_running(duthost, containers_in_namespaces):
    """Checks whether each critical process is running and starts it if it is not running.

    Args:
        duthost: Hostname of DUT.
        containers_in_namespaces: A dictionary where keys are container names and
        values are lists which contains ids of namespaces this container should reside in.

    Returns:
        None.
    """
    for container_name in containers_in_namespaces.keys():
        namespace_ids = containers_in_namespaces[container_name]
        container_name_in_namespace = container_name
        # If a container is only running on host, then namespace_ids is [None]
        # If a container is running on multi-ASIC, then namespace_ids is [0, 1, ...]
        # If a container is running on host and multi-ASICs, then namespace_ids is [None, 0, 1, ...]
        if len(namespace_ids) >= 2:
            container_name_in_namespace += namespace_ids[1]

        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name_in_namespace)
        pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'"
                      .format(container_name_in_namespace))

        for namespace_id in namespace_ids:
            container_name_in_namespace = container_name
            if namespace_id != DEFAULT_ASIC_ID:
                container_name_in_namespace += namespace_id

            for critical_process in critical_process_list:
                # Skip 'dsserve' process since it was not managed by supervisord
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if "syncd" in container_name_in_namespace and critical_process == "dsserve":
                    continue

                ensure_process_is_running(duthost, container_name_in_namespace, critical_process)

            for critical_group in critical_group_list:
                group_program_info = get_group_program_info(duthost, container_name_in_namespace, critical_group)
                for program_name in group_program_info:
                    ensure_process_is_running(duthost, container_name_in_namespace, program_name)


def test_monitoring_critical_processes(duthosts, rand_one_dut_hostname, tbinfo, skip_vendor_specific_container):
    """Tests the feature of monitoring critical processes by Monit and Supervisord.

    This function will check whether names of critical processes will appear
    in the syslog if the autorestart were disabled and these critical processes
    were stopped.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: hostname of DUT.
        tbinfo: Testbed information.

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="monitoring_critical_processes")
    loganalyzer.expect_regex = []
    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]

    skip_containers = []
    skip_containers.append("database")
    skip_containers.append("gbsyncd")
    # Skip 'restapi' container since 'restapi' service will be restarted immediately after exited, which will not trigger alarm message.
    skip_containers.append("restapi")
    # Skip 'acms' container since 'acms' process is not running on lab devices and
    # another process `cert_converter.py' is set to auto-restart if exited.
    skip_containers.append("acms")
    # Skip 'radv' container on devices whose role is not T0.
    if tbinfo["topo"]["type"] != "t0":
        skip_containers.append("radv")
    skip_containers = skip_containers + skip_vendor_specific_container

    containers_in_namespaces = get_containers_namespace_ids(duthost, skip_containers)

    if "20191130" in duthost.os_version:
        expected_alerting_messages = get_expected_alerting_messages_monit(duthost, containers_in_namespaces)
    else:
        expected_alerting_messages = get_expected_alerting_messages_supervisor(duthost, containers_in_namespaces)

    loganalyzer.expect_regex.extend(expected_alerting_messages)
    marker = loganalyzer.init()

    stop_critical_processes(duthost, containers_in_namespaces)

    # Wait for 70 seconds such that Supervisord/Monit has a chance to write alerting message into syslog.
    logger.info("Sleep 70 seconds to wait for the alerting messages in syslog...")
    time.sleep(70)

    logger.info("Checking the alerting messages from syslog...")
    loganalyzer.analyze(marker)
    logger.info("Found all the expected alerting messages from syslog!")

    logger.info("Executing the config reload...")
    config_reload(duthost)
    logger.info("Executing the config reload was done!")

    ensure_all_critical_processes_running(duthost, containers_in_namespaces)

    if not postcheck_critical_processes_status(duthost, up_bgp_neighbors):
        pytest.fail("Post-check failed after testing the process monitoring!")
    logger.info("Post-checking status of critical processes and BGP sessions was done!")

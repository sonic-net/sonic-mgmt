"""
Test the auto-restart feature of containers
"""
import logging
from collections import defaultdict

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_ports import decode_dut_port_name
from tests.common import config_reload
from tests.common.helpers.dut_utils import get_disabled_container_list

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_STOP_THRESHOLD_SECS = 30
CONTAINER_RESTART_THRESHOLD_SECS = 180

@pytest.fixture(autouse=True, scope='module')
def config_reload_after_tests(duthost):
    yield
    config_reload(duthost)

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(duthost, loganalyzer, enum_dut_feature):
    """
        Ignore expected failure/error messages during testing the autorestart feature.

        First, since we killed a critical process in a specific container to test the feature of
        autorestart, we expect to see error messages which were fired by Monit such as
        "ERR monit[563]: 'lldp|lldpd' status failed (1) -- 'lldpd' is not running."

        Second, if teammgrd process was killed for testing, orchagent process in
        swss container would write the error messages into syslog such as
        "ERR swss#orchagent: :- removeLag: Failed to remove ref count 1 LAG PortChannel10008."
        When teamd was restarted, there was an error message in the syslog: "ERR teamd#teamsyncd:
        :- readData: netlink reports an error=-33 on reading a netlink socket."

        Third, during pmon container was restarted due to ledd process was killed for testing,
        xcvrd process would write an error message into syslog such as "ERR pmon#xcvrd[29]: :-initialize
        GlobalConfig: Sonic database config global file doesn't exist at /var/run/redis/sonic-db/database_global.json."
        thermalctld process would write an error message into syslog such as "ERR pmon#thermalctld[33]:
        Caught exception while initializing thermal manager."

        Fourth, if orchagent process was killed and swss container was restarted, then syncd process
        would write error messages such as "ERR syncd#syncd: [none] driverEgressMemoryUpdate:1395
        Error getting cosq for port 1.". At the same time, syncd process also wrote two WARNING messages
        into syslog such as "WARNING syncd#syncd:- saiDiscover: skipping since it causes crash:
        SAI_STP_ATTR_BRIDGE_ID". Since there was a keyword "crash" in these warning message, logAnalyzer
        would fail.

        Fifth, systemd would fire an error message:"ERR systemd[1]: Failed to start SNMP/TEAMD container." since
        SNMP/TEAMD container hits the limitation of restart. route_check.py also wrote an error message into syslog.

    """
    swss_syncd_teamd_regex = [
            ".*ERR swss#orchagent.*removeLag.*",
            ".*ERR syncd#syncd.*driverEgressMemoryUpdate.*",
            ".*ERR syncd#syncd.*brcm_sai*",
            ".*ERR syncd#syncd.*SAI_API_UNSPECIFIED:sai_api_query.*",
            ".*ERR syncd#syncd.*SAI_API_SWITCH:sai_query_attribute_enum_values_capability.*",
            ".*ERR syncd#syncd.*SAI_API_SWITCH:sai_object_type_get_availability.*",
            ".*ERR syncd#syncd.*sendApiResponse: api SAI_COMMON_API_SET failed in syncd mode.*",
            ".*ERR syncd#syncd.*processQuadEvent.*",
            ".*WARNING syncd#syncd.*skipping since it causes crash.*",
            ".*ERR swss#portsyncd.*readData.*netlink reports an error=-33 on reading a netlink socket.*",
            ".*ERR teamd#teamsyncd.*readData.*netlink reports an error=-33 on reading a netlink socket.*",
            ".*ERR swss#orchagent.*set status: SAI_STATUS_ATTR_NOT_IMPLEMENTED_0.*",
            ".*ERR swss#orchagent.*setIntfVlanFloodType.*",
            ".*ERR snmp#snmpd.*",
        ]
    ignore_regex_dict = {
        'common' : [
            ".*ERR monit.*",
            ".*ERR systemd.*Failed to start .* container*",
            ".*ERR kernel.*PortChannel.*",
            ".*ERR route_check.*",
        ],
        'pmon' : [
            ".*ERR pmon#xcvrd.*initializeGlobalConfig.*",
            ".*ERR pmon#thermalctld.*Caught exception while initializing thermal manager.*",
            ".*ERR pmon#xcvrd.*Could not establish the active side.*",
        ],
        'swss' : swss_syncd_teamd_regex,
        'syncd' : swss_syncd_teamd_regex,
        'teamd' : swss_syncd_teamd_regex,
    }

    _, feature = decode_dut_port_name(enum_dut_feature)

    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(ignore_regex_dict['common'])
        if feature in ignore_regex_dict:
            loganalyzer[duthost.hostname].ignore_regex.extend(ignore_regex_dict[feature])


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

    return group_program_info


def get_program_info(duthost, container_name, program_name):
    """
    @summary: Get program running status and its pid by analyzing the command
              output of "docker exec <container_name> supervisorctl status"
    @return:  Program running status and its pid
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
    pytest_assert(exit_code == 0, "Failed to stop program '{}' before test".format(program_name))

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


def clear_failed_flag_and_restart(duthost, container_name):
    """
    @summary: If a container hits the restart limitation, then we clear the failed flag and
              restart it.
    """
    logger.info("{} hits start limit and clear reset-failed flag".format(container_name))
    duthost.shell("sudo systemctl reset-failed {}.service".format(container_name))
    duthost.shell("sudo systemctl start {}.service".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart container '{}' after reset-failed was cleared".format(container_name))


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
            clear_failed_flag_and_restart(duthost, container_name)
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


def check_all_critical_processes_status(duthost):
    processes_status = duthost.all_critical_process_status()
    for container_name, processes in processes_status.items():
        if processes["status"] is False or len(processes["exited_critical_process"]) > 0:
            return False

    return True

def post_test_check(duthost, up_bgp_neighbors):
    return check_all_critical_processes_status(duthost) and duthost.check_bgp_session_state(up_bgp_neighbors, "established")


def postcheck_critical_processes_status(duthost, container_autorestart_states, up_bgp_neighbors):
    """
    @summary: Do the post check to see whether all the critical processes are alive after testing
              the autorestart feature.
              First we restart the containers which hit the restart limitation and then do the post check
    """
    for container_name in container_autorestart_states.keys():
        if is_hiting_start_limit(duthost, container_name):
            clear_failed_flag_and_restart(duthost, container_name)

    return wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS,
                      post_test_check, duthost, up_bgp_neighbors)


def run_test_on_single_container(duthost, container_name, tbinfo):
    container_autorestart_states = duthost.get_container_autorestart_states()
    disabled_containers = get_disabled_container_list(duthost)

    skip_condition = disabled_containers[:]
    skip_condition.append("database")
    if tbinfo["topo"]["type"] != "t0":
        skip_condition.append("radv")

    # Skip testing the database container, radv container on T1 devices and containers/services which are disabled
    pytest_require(container_name not in skip_condition,
                   "Skipping test for container {}".format(container_name))

    is_running = is_container_running(duthost, container_name)
    pytest_assert(is_running, "Container '{}' is not running. Exiting...".format(container_name))

    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]

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
    pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'".format(container_name))

    for critical_process in critical_process_list:
        # Skip 'dsserve' process since it was not managed by supervisord
        # TODO: Should remove the following two lines once the issue was solved in the image.
        if container_name == "syncd" and critical_process == "dsserve":
            continue

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

    if restore_disabled_state:
        logger.info("Restore auto-restart state of container '{}' to 'disabled'".format(container_name))
        duthost.shell("sudo config feature autorestart {} disabled".format(container_name))

    if not postcheck_critical_processes_status(duthost, container_autorestart_states, up_bgp_neighbors):
        config_reload(duthost)
        pytest.fail("Some post check failed after testing feature {}".format(container_name))

    logger.info("End of testing the container '{}'".format(container_name))


def test_containers_autorestart(duthosts, enum_dut_feature, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    @summary: Test the auto-restart feature of each container against two scenarios: killing
              a non-critical process to verify the container is still running; killing each
              critical process to verify the container will be stopped and restarted
    """
    dut_name, feature = decode_dut_port_name(enum_dut_feature)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname and feature != "unknown",
                   "Skip test on dut host {} (chosen {}) feature {}"
                   .format(dut_name, enum_rand_one_per_hwsku_frontend_hostname, feature))

    duthost = duthosts[dut_name]
    run_test_on_single_container(duthost, feature, tbinfo)


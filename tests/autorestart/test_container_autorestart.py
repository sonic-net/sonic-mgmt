"""
Test the auto-restart feature of containers
"""
import logging
import re
from collections import defaultdict

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common import config_reload
from tests.common.helpers.dut_utils import get_disabled_container_list

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_STOP_THRESHOLD_SECS = 60
CONTAINER_RESTART_THRESHOLD_SECS = 300
CONTAINER_NAME_REGEX = r"([a-zA-Z_-]+)(\d*)([a-zA-Z_-]+)(\d*)$"
DHCP_RELAY = "dhcp_relay"
DHCP_SERVER = "dhcp_server"
POST_CHECK_INTERVAL_SECS = 1
POST_CHECK_THRESHOLD_SECS = 360
PROGRAM_STATUS = "RUNNING"


@pytest.fixture(autouse=True, scope='module')
def config_reload_after_tests(duthosts, selected_rand_one_per_hwsku_hostname, tbinfo):
    dhcp_server_hosts = []
    # Enable autorestart for all features before the test begins
    for hostname in selected_rand_one_per_hwsku_hostname:
        duthost = duthosts[hostname]
        feature_list, _ = duthost.get_feature_status()
        for feature, status in list(feature_list.items()):
            if status == 'enabled':
                duthost.shell("sudo config feature autorestart {} enabled".format(feature))
        # Enable dhcp_server feature for mx topo
        if tbinfo["topo"]["type"] == "mx" \
            and DHCP_SERVER in feature_list \
                and "enabled" not in feature_list.get(DHCP_SERVER, ""):
            dhcp_server_hosts.append(hostname)
            duthost.shell("config feature state %s enabled" % DHCP_SERVER)
            duthost.shell("sudo config feature autorestart %s enabled" % DHCP_SERVER)
            duthost.shell("sudo systemctl restart %s.service" % DHCP_RELAY)
            pytest_require(
                wait_until(120, 1, 1,
                           is_supervisor_program_running,
                           duthost,
                           DHCP_RELAY,
                           "dhcp-relay:dhcprelayd"),
                "dhcp-relay:dhcprelayd is not running"
            )
    yield
    # Config reload should set the auto restart back to state before test started
    for hostname in selected_rand_one_per_hwsku_hostname:
        duthost = duthosts[hostname]
        config_reload(duthost, config_source='config_db', safe_reload=True)
        if hostname in dhcp_server_hosts:
            duthost.shell("docker rm %s" % DHCP_SERVER, module_ignore_errors=True)


def is_supervisor_program_running(duthost, container_name, program_name):
    return "RUNNING" in duthost.shell(f"docker exec {container_name} supervisorctl status {program_name}")["stdout"]


def enable_autorestart(duthost):
    # Enable autorestart for all features
    feature_list, _ = duthost.get_feature_status()
    for feature, status in list(feature_list.items()):
        if status == 'enabled':
            duthost.shell("sudo config feature autorestart {} enabled".format(feature))


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index,
                                          enum_dut_feature, loganalyzer):
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

        Sixth, after a process is killed, its network resources are not immediately released. So it might take some time
        for the ports to be available again. The problem might be more pronounced with weak devices. So we expect some
        failures with listening or binding to a socket. When encountering this problem, the process will be repeated
        and it typically resolves by itself. So we skip "Unable to initialize team socket" in teamsyncd and "Failed to
        bind socket" in dhcprelay.

        Also invalid OID is more of a warning. So we skip messages with keyword "invalid OID".

    """
    swss_syncd_teamd_regex = [
            ".*ERR swss[0-9]*#orchagent.*removeLag.*",
            ".*ERR syncd[0-9]*#syncd.*driverEgressMemoryUpdate.*",
            ".*ERR syncd[0-9]*#syncd.*brcm_sai*",
            ".*ERR syncd[0-9]*#syncd.*SAI_API_UNSPECIFIED:sai_api_query.*",
            ".*ERR syncd[0-9]*#syncd.*SAI_API_SWITCH:sai_query_attribute_enum_values_capability.*",
            ".*ERR syncd[0-9]*#syncd.*SAI_API_SWITCH:sai_object_type_get_availability.*",
            ".*ERR syncd[0-9]*#syncd.*SAI_API_SWITCH:sai_query_attribute_capability.*",
            ".*ERR syncd[0-9]*#syncd.*sendApiResponse: api SAI_COMMON_API_SET failed in syncd mode.*",
            ".*ERR syncd[0-9]*#syncd.*processQuadEvent.*",
            ".*ERR syncd[0-9]*#syncd.*process_on_fdb_event: invalid OIDs in fdb notifications.*",
            ".*ERR syncd[0-9]*#syncd.*process_on_fdb_event: FDB notification was not sent since it contain invalid "
            "OIDs.*",
            ".*ERR syncd[0-9]*#syncd.*saiGetMacAddress: failed to get mac address: SAI_STATUS_ITEM_NOT_FOUND.*",
            ".*ERR syncd[0-9]*#syncd.*getSupportedBufferPoolCounters.*",
            ".*ERR syncd[0-9]*#SDK.*mlnx_bridge_1d_oid_to_data: Unexpected bridge type 0 is not 1D.*",
            ".*ERR syncd[0-9]*#SDK.*mlnx_bridge_port_lag_or_port_get: Invalid port type - 2.*",
            ".*ERR syncd[0-9]*#SDK.*mlnx_bridge_port_isolation_group_get: Isolation group is only supported for "
            "bridge port type port.*",
            ".*ERR syncd[0-9]*#SDK.*mlnx_debug_counter_availability_get: Unsupported debug counter type - (0|1).*",
            ".*ERR syncd[0-9]*#SDK.*mlnx_get_port_stats_ext: Invalid port counter (177|178|179|180|181|182).*",
            ".*ERR syncd[0-9]*#SDK.*Failed getting attrib SAI_BRIDGE_.*",
            ".*ERR syncd[0-9]*#SDK.*sai_get_attributes: Failed attribs dispatch.*",
            ".*ERR syncd[0-9]*#SDK.*Failed command read at communication channel: Connection reset by peer.*",
            ".*WARNING syncd[0-9]*#syncd.*skipping since it causes crash.*",
            ".*ERR syncd[0-9]*#SDK.*validate_port: Can't add port which is under bridge.*",
            ".*ERR syncd[0-9]*#SDK.*listFailedAttributes.*",
            ".*ERR syncd[0-9]*#SDK.*processSingleVid: failed to create object SAI_OBJECT_TYPE_LAG_MEMBER: SAI_STATUS_INVALID_PARAMETER.*",          # noqa E501
            # Known issue, captured here: https://github.com/sonic-net/sonic-buildimage/issues/10000 , ignore it for now
            ".*ERR swss[0-9]*#fdbsyncd.*readData.*netlink reports an error=-25 on reading a netlink socket.*",
            ".*ERR swss[0-9]*#portsyncd.*readData.*netlink reports an error=-33 on reading a netlink socket.*",
            ".*ERR teamd[0-9]*#teamsyncd.*readData.*netlink reports an error=-33 on reading a netlink socket.*",
            ".*ERR teamd[0-9]*#teamsyncd.*readData.*Unable to initialize team socket.*",
            ".*ERR swss[0-9]*#orchagent.*set status: SAI_STATUS_ATTR_NOT_IMPLEMENTED_0.*",
            ".*ERR swss[0-9]*#orchagent.*setIntfVlanFloodType.*",
            ".*ERR swss[0-9]*#orchagent.*applyDscpToTcMapToSwitch.*",
            ".*ERR swss[0-9]*#buffermgrd.*Failed to process invalid entry.*",
            ".*ERR snmp#snmpd.*",
            ".*ERR dhcp_relay#dhcp6?relay.*bind: Failed to bind socket to link local ipv6 address on interface .* "
            "after [0-9]+ retries",
            ".*ERR gbsyncd#syncd: :- updateNotificationsPointers: pointer for SAI_SWITCH_ATTR_REGISTER_READ is not "
            "handled.*",
            ".*ERR gbsyncd#syncd: :- updateNotificationsPointers: pointer for SAI_SWITCH_ATTR_REGISTER_WRITE is not "
            "handled.*",
            ".*ERR gbsyncd#syncd: :- diagShellThreadProc: Failed to enable switch shell: SAI_STATUS_NOT_SUPPORTED.*",
            ".*ERR swss[0-9]*#orchagent: :- updateNotifications: pointer for SAI_SWITCH_ATTR_REGISTER_WRITE is not handled.*",      # noqa E501
            ".*ERR swss[0-9]*#orchagent: :- updateNotifications: pointer for SAI_SWITCH_ATTR_REGISTER_READ is not handled.*",       # noqa E501
            ".*ERR swss[0-9]*#orchagent:.*pfcFrameCounterCheck: Invalid port oid.*",
            ".*ERR swss[0-9]*#orchagent: :- mcCounterCheck: Invalid port oid.*",
            ".*ERR lldp[0-9]*#lldp-syncd \[lldp_syncd\].*Could not infer system information from.*",    # noqa W605
            ".*ERR lldp[0-9]*#lldpmgrd.*Port init timeout reached (300 seconds), resuming lldpd.*",
            ".*ERR syncd[0-9]*#syncd.*threadFunction: time span WD exceeded.*create:SAI_OBJECT_TYPE_SWITCH.*",
            ".*ERR syncd[0-9]*#syncd.*logEventData:.*SAI_SWITCH_ATTR.*",
            ".*ERR syncd[0-9]*#syncd.*logEventData:.*SAI_OBJECT_TYPE_SWITCH.*",
            ".*ERR syncd[0-9]*#syncd.*setEndTime:.*SAI_OBJECT_TYPE_SWITCH.*",
            ".*ERR syncd[0-9]*#syncd:.*SAI_API_PORT:_brcm_sai_port_wred_stats_get:.*port gport get failed with error Feature unavailable.*",        # noqa E501
            ".*ERR syncd[0-9]*#syncd:.*SAI_API_PORT:_brcm_sai_get_recycle_port_attribute.*Error processing port attributes for attr_id.*",          # noqa E501
            ".*ERR syncd[0-9]*#syncd:.*SAI_API_PORT:_brcm_sai_get_recycle_port_attribute.*Unknown port attribute.*",
            ".*ERR syncd[0-9]*#syncd:.*SAI_API_PORT:_brcm_sai_port_wred_stats_get:15102 Hardware failure -16 in getting WRED stat 68 for port.*",   # noqa E501
            ".*ERR swss[0-9]*#orchagent: :- doLagMemberTask: Failed to locate port.*",
            ".*ERR swss[0-9]*#orchagent:.*update: Failed to get port by bridge port ID.*",
            ".*ERR swss[0-9]*#orchagent:.*handlePortStatusChangeNotification: Failed to get port object for port id.*",
            ".*ERR swss[0-9]*#orchagent: :- getResAvailability: Failed to get availability counter.*",
            ".*ERR swss[0-9]*#supervisor-proc-exit-listener: Process 'orchagent' is not running in namespace.*",
    ]
    ignore_regex_dict = {
        'common': [
            ".*ERR monit.*",
            ".*ERR systemd.*Failed to start .* [Cc]ontainer.*",
            ".*ERR kernel.*PortChannel.*",
            ".*ERR route_check.*",
            ".*ERR wrong number of arguments for 'hset' command: Input/output error.*"
        ],
        'pmon': [
            ".*ERR pmon#xcvrd.*initializeGlobalConfig.*",
            ".*ERR pmon#thermalctld.*Caught exception while initializing thermal manager.*",
            ".*ERR pmon#xcvrd.*Could not establish the active side.*",
            ".*ERR pmon#xcvrd.*sx_api_host_ifc_trap_id_register_set exited with error.*",
            ".*ERR pmon#xcvrd.*sx_api_host_ifc_close exited with error.*"
        ],
        'eventd': [
            ".*ERR eventd#eventd.*The eventd service started.*",
            ".*ERR eventd#eventd.*deserialize Failed: input stream errorstr.*"
        ],
        'swss': swss_syncd_teamd_regex,
        'syncd': swss_syncd_teamd_regex,
        'teamd': swss_syncd_teamd_regex,
    }

    # During syncd restart, the pmon container is also restarted,
    # and we noticed some errors in the pmon container
    ignore_regex_dict['syncd'].extend(ignore_regex_dict['pmon'])

    feature = enum_dut_feature

    impacted_duts = []
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        impacted_duts = duthosts
    else:
        impacted_duts = [duthost]

    logger.info("Impacted DUTs: '{}'".format(impacted_duts))

    if loganalyzer:
        for a_dut in impacted_duts:
            loganalyzer[a_dut.hostname].ignore_regex.extend(ignore_regex_dict['common'])
            if feature in ignore_regex_dict:
                loganalyzer[a_dut.hostname].ignore_regex.extend(ignore_regex_dict[feature])


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

    program_list = duthost.shell("docker exec {} supervisorctl status"
                                 .format(container_name), module_ignore_errors=True)
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

    program_list = duthost.shell("docker exec {} supervisorctl status"
                                 .format(container_name), module_ignore_errors=True)
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
    result = duthost.shell(r"docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
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


def is_hiting_start_limit(duthost, service_name):
    """
    @summary: Determine whether the service can not be restarted is due to
              start-limit-hit or not
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(service_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False


def clear_failed_flag_and_restart(duthost, service_name, container_name):
    """
    @summary: If a container hits the restart limitation, then we clear the failed flag and
              restart it.
    """
    logger.info("{} hits start limit and clear reset-failed flag".format(service_name))
    duthost.shell("sudo systemctl reset-failed {}.service".format(service_name))
    duthost.shell("sudo systemctl start {}.service".format(service_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           0,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart container '{}' after reset-failed was cleared".format(container_name))


def verify_autorestart_with_critical_process(duthost, container_name, service_name, program_name,
                                             program_pid):
    """
    @summary: Kill a critical process in a container to verify whether the container
              is stopped and restarted correctly
    """
    global PROGRAM_STATUS
    pytest_assert(wait_until(40, 3, 0, is_process_running, duthost, container_name, program_name),
                  "Program '{}' in container '{}' is in the '{}' state, expected 'RUNNING'"
                  .format(program_name, container_name, PROGRAM_STATUS))

    kill_process_by_pid(duthost, container_name, program_name, program_pid)
    logger.info("Waiting until container '{}' is stopped...".format(container_name))
    stopped = wait_until(CONTAINER_STOP_THRESHOLD_SECS,
                         CONTAINER_CHECK_INTERVAL_SECS,
                         0,
                         check_container_state, duthost, container_name, False)
    pytest_assert(stopped, "Failed to stop container '{}'".format(container_name))
    logger.info("Container '{}' was stopped".format(container_name))

    logger.info("Waiting until container '{}' is restarted...".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           0,
                           check_container_state, duthost, container_name, True)
    if not restarted:
        if is_hiting_start_limit(duthost, service_name):
            clear_failed_flag_and_restart(duthost, service_name, container_name)
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
                         0,
                         check_container_state, duthost, container_name, False)
    pytest_assert(not stopped, "Container '{}' was stopped unexpectedly".format(container_name))
    logger.info("Container '{}' did not stop".format(container_name))
    logger.info("Restart the program '{}' in container '{}'".format(program_name, container_name))
    duthost.shell("docker exec {} supervisorctl start {}".format(container_name, program_name))


def check_all_critical_processes_status(duthost):
    """Checks whether critical processes are running.

    Args:
      duthost: An ansible object of DuT.

    Returns:
      Ture if critical processes are running. Otherwise False.
    """
    processes_status = duthost.all_critical_process_status()
    for container_name, processes in list(processes_status.items()):
        if processes["status"] is False or len(processes["exited_critical_process"]) > 0:
            logger.info("The status of checking process in container '{}' is: {}"
                        .format(container_name, processes["status"]))
            logger.info("The processes not running in container '{}' are: '{}'"
                        .format(container_name, processes["exited_critical_process"]))
            return False

    return True


def postcheck_critical_processes_status(duthost, feature_autorestart_states, up_bgp_neighbors):
    """Restarts the containers which hit the restart limitation. Then post checks
       to see whether all the critical processes are alive and
       expected BGP sessions are up after testing the autorestart feature.

    Args:
      duthost: An ansible object of DuT.
      feature_autorestart_states: A dictionary includes the feature name (key) and
        its auto-restart state (value).
      up_bgp_neighbors: A list includes the IP of neighbors whose BGP session are up.

    Returns:
      True if post check succeeds; Otherwise False.
    """
    # Check if all critical processes are running with timeout 100 sec, if not
    # then this timeout will help to stabilize service state and to spot
    # start-limit-hit if it was exceeded.
    wait_until(
        100, POST_CHECK_INTERVAL_SECS, 0,
        check_all_critical_processes_status, duthost
    )

    for feature_name in list(feature_autorestart_states.keys()):
        if feature_name in duthost.DEFAULT_ASIC_SERVICES:
            for asic in duthost.asics:
                service_name = asic.get_service_name(feature_name)
                container_name = asic.get_docker_name(feature_name)
                if is_hiting_start_limit(duthost, service_name):
                    clear_failed_flag_and_restart(duthost, service_name, container_name)
        else:
            # service_name and container_name will be same as feature
            # name for features that are not in DEFAULT_ASIC_SERVICES.
            if is_hiting_start_limit(duthost, feature_name):
                clear_failed_flag_and_restart(duthost, feature_name, feature_name)

    critical_proceses = wait_until(
        POST_CHECK_THRESHOLD_SECS, POST_CHECK_INTERVAL_SECS, 0,
        check_all_critical_processes_status, duthost
    )

    bgp_check = wait_until(
        POST_CHECK_THRESHOLD_SECS, POST_CHECK_INTERVAL_SECS, 0,
        duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"
    )

    return critical_proceses, bgp_check


def is_process_running(duthost, container_name, program_name):
    global PROGRAM_STATUS
    program_status, _ = get_program_info(duthost, container_name, program_name)
    PROGRAM_STATUS = program_status
    if program_status == "RUNNING":
        return True
    elif program_status in ["EXITED", "STOPPED", "STARTING"]:
        return False
    else:
        pytest.fail("Failed to find program '{}' in container '{}'"
                    .format(program_name, container_name))


def run_test_on_single_container(duthost, container_name, service_name, tbinfo):
    feature_autorestart_states = duthost.get_container_autorestart_states()
    disabled_containers = get_disabled_container_list(duthost)

    skip_condition = disabled_containers[:]
    skip_condition.append("database")
    skip_condition.append("acms")
    if tbinfo["topo"]["type"] != "t0":
        skip_condition.append("radv")

    # bgp0 -> bgp, bgp -> bgp, p4rt -> p4rt
    feature_name = ''.join(re.match(CONTAINER_NAME_REGEX, container_name).groups()[:-1])

    # Skip testing the database container, radv container on T1 devices and containers/services which are disabled
    pytest_require(feature_name not in skip_condition,
                   "Skipping test for container {}".format(feature_name))

    is_running = is_container_running(duthost, container_name)
    pytest_assert(is_running, "Container '{}' is not running. Exiting...".format(container_name))

    up_bgp_neighbors = duthost.get_bgp_neighbors_per_asic("established")

    logger.info("Start testing the container '{}'...".format(container_name))

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
        if feature_name == "syncd" and critical_process == "dsserve":
            continue
        _, program_pid = get_program_info(duthost, container_name, critical_process)
        verify_autorestart_with_critical_process(duthost, container_name, service_name, critical_process,
                                                 program_pid)
        # Sleep 20 seconds in order to let the processes come into live after container is restarted.
        # We will uncomment the following line once the "extended" mode is added
        # time.sleep(20)
        # We are currently only testing one critical process, that is why we use 'break'. Once
        # we add the "extended" mode, we will remove this statement
        break

    for critical_group in critical_group_list:
        group_program_info = get_group_program_info(duthost, container_name, critical_group)
        for program_name in group_program_info:
            verify_autorestart_with_critical_process(duthost, container_name, service_name, program_name,
                                                     group_program_info[program_name][1])
            # We are currently only testing one critical program for each critical group, which is
            # why we use 'break' statement. Once we add the "extended" mode, we will remove this
            # statement
            break

    critical_proceses, bgp_check = postcheck_critical_processes_status(
        duthost, feature_autorestart_states, up_bgp_neighbors
    )
    if not (critical_proceses and bgp_check):
        config_reload(duthost, safe_reload=True)
        # after config reload, the feature autorestart config is reset,
        # so, before next test, enable again
        enable_autorestart(duthost)

        failed_check = "[Critical Process] " if not critical_proceses else ""
        failed_check += "[BGP] " if not bgp_check else ""
        processes_status = duthost.all_critical_process_status()
        pstatus = [
            {
                k: {
                    "status": v["status"],
                    "exited_critical_process": v["exited_critical_process"]
                }
            } for k, v in list(processes_status.items()) if v[
                "status"
            ] is False and len(v["exited_critical_process"]) > 0
        ]

        pytest.fail(
            ("{}check failed, testing feature {}, \nBGP:{}, \nNeighbors:{}"
             "\nProcess status {}").format(
                failed_check, container_name,
                [{x: v['state']} for x, v in list(duthost.get_bgp_neighbors().items()) if v['state'] != 'established'],
                up_bgp_neighbors, pstatus
            )
        )

    logger.info("End of testing the container '{}'".format(container_name))


@pytest.mark.disable_loganalyzer
def test_containers_autorestart(duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index,
                                enum_dut_feature, tbinfo):
    """
    @summary: Test the auto-restart feature of each container against two scenarios: killing
              a non-critical process to verify the container is still running; killing each
              critical process to verify the container will be stopped and restarted
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    asic = duthost.asic_instance(enum_rand_one_asic_index)
    service_name = asic.get_service_name(enum_dut_feature)
    container_name = asic.get_docker_name(enum_dut_feature)
    run_test_on_single_container(duthost, container_name, service_name, tbinfo)

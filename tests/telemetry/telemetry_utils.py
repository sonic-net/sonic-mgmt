import logging
import pytest

from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

TELEMETRY_PORT = 50051
METHOD_GET = "get"
METHOD_SUBSCRIBE = "subscribe"
SUBSCRIBE_MODE_STREAM = 0
SUBMODE_SAMPLE = 2

MONIT_RESTART_THRESHOLD_SECS = 320
MONIT_CHECK_INTERVAL_SECS = 5
CONTAINER_RESTART_THRESHOLD_SECS = 180
CONTAINER_CHECK_INTERVAL_SECS = 1


def assert_equal(actual, expected, message):
    """Helper method to compare an expected value vs the actual value.
    """
    pytest_assert(actual == expected, "{0}. Expected {1} vs actual {2}".format(message, expected, actual))


def get_dict_stdout(gnmi_out, certs_out):
    """ Extracts dictionary from redis output.
    """
    gnmi_list = []
    gnmi_list = get_list_stdout(gnmi_out) + get_list_stdout(certs_out)
    # Elements in list alternate between key and value. Separate them and combine into a dict.
    key_list = gnmi_list[0::2]
    value_list = gnmi_list[1::2]
    params_dict = dict(zip(key_list, value_list))
    return params_dict


def get_list_stdout(cmd_out):
    out_list = []
    for x in cmd_out:
        result = x.encode('UTF-8')
        out_list.append(result)
    return out_list


def skip_201911_and_older(duthost):
    """ Skip the current test if the DUT version is 201911 or older.
    """
    if parse_version(duthost.kernel_version) <= parse_version('4.9.0'):
        pytest.skip("Test not supported for 201911 images. Skipping the test")


def skip_arm_platform(duthost):
    """ Skip the current test if DUT is arm platform.
    """
    platform = duthost.facts["platform"]
    if 'x86_64' not in platform:
        pytest.skip("Test not supported for current platform. Skipping the test")


def setup_telemetry_forpyclient(duthost):
    """ Set client_auth=false. This is needed for pyclient to successfully set up channel with gnmi server.
        Restart telemetry process
    """
    client_auth_out = duthost.shell('sonic-db-cli CONFIG_DB HGET "TELEMETRY|gnmi" "client_auth"',
                                    module_ignore_errors=False)['stdout_lines']
    client_auth = str(client_auth_out[0])
    if client_auth == "true":
        duthost.shell('sonic-db-cli CONFIG_DB HSET "TELEMETRY|gnmi" "client_auth" "false"', module_ignore_errors=False)
        duthost.service(name="telemetry", state="restarted")
    else:
        logger.info('client auth is false. No need to restart telemetry')
    return client_auth


def restore_telemetry_forpyclient(duthost, default_client_auth):
    client_auth_out = duthost.shell('sonic-db-cli CONFIG_DB HGET "TELEMETRY|gnmi" "client_auth"',
                                    module_ignore_errors=False)['stdout_lines']
    client_auth = str(client_auth_out[0])
    if client_auth != default_client_auth:
        duthost.shell('sonic-db-cli CONFIG_DB HSET "TELEMETRY|gnmi" "client_auth" {}'.format(default_client_auth),
                      module_ignore_errors=False)
        duthost.service(name="telemetry", state="restarted")


def generate_client_cli(duthost, gnxi_path, method=METHOD_GET, xpath="COUNTERS/Ethernet0", target="COUNTERS_DB",
                        subscribe_mode=SUBSCRIBE_MODE_STREAM, submode=SUBMODE_SAMPLE,
                        intervalms=0, update_count=3, num_connections=1):
    """ Generate the py_gnmicli command line based on the given params.
    """
    cmdFormat = 'python ' + gnxi_path + 'gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m {2} -x {3} -xt {4} -o {5}'
    cmd = cmdFormat.format(duthost.mgmt_ip, TELEMETRY_PORT, method, xpath, target, "ndastreamingservertest")

    if method == METHOD_SUBSCRIBE:
        cmd += " --subscribe_mode {0} --submode {1} --interval {2} --update_count {3} --create_connections {4}".format(
                subscribe_mode,
                submode, intervalms,
                update_count, num_connections)
    return cmd


def backup_monit_config_files(duthost):
    """Backs up Monit configuration files on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Backing up Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("cp -f /etc/monit/monitrc /tmp/")
    duthost.shell("mv -f /etc/monit/conf.d/monit_* /tmp/")
    duthost.shell("cp -f /tmp/monit_telemetry /etc/monit/conf.d/")
    logger.info("Monit configuration files on DuT '{}' is backed up.".format(duthost.hostname))


def customize_monit_config_files(duthost, temp_config_line):
    """Customizes the Monit configuration file on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.
        temp_config_line: A string to replace the initial Monit configuration.

    Returns:
        None.
    """
    logger.info("Modifying Monit config to eliminate start delay and decrease interval ...")
    duthost.shell("sed -i '$s/^./#/' /etc/monit/conf.d/monit_telemetry")
    duthost.shell("echo '{}' | tee -a /etc/monit/conf.d/monit_telemetry".format(temp_config_line))
    duthost.shell("sed -i '/with start delay 300/s/^./#/' /etc/monit/monitrc")
    logger.info("Modifying Monit config to eliminate start delay and decrease interval are done.")


def restore_monit_config_files(duthost):
    """Restores the initial Monit configuration file on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Restoring original Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("mv -f /tmp/monitrc /etc/monit/")
    duthost.shell("mv -f /tmp/monit_* /etc/monit/conf.d/")
    logger.info("Original Monit configuration files on DuT '{}' are restored.".format(duthost.hostname))


def check_monit_running(duthost):
    """Checks whether Monit is running or not.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        Returns True if Monit is running; Otherwist, returns False.
    """
    monit_services_status = duthost.get_monit_services_status()
    if not monit_services_status:
        return False

    return True


def restart_monit_service(duthost):
    """Restarts Monit service and polls Monit running status.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Restarting Monit service ...")
    duthost.shell("systemctl restart monit")
    logger.info("Monit service is restarted.")

    logger.info("Checks whether Monit is running or not after restarted ...")
    is_monit_running = wait_until(MONIT_RESTART_THRESHOLD_SECS,
                                  MONIT_CHECK_INTERVAL_SECS,
                                  0,
                                  check_monit_running,
                                  duthost)
    pytest_assert(is_monit_running, "Monit is not running after restarted!")
    logger.info("Monit is running!")


def check_critical_processes(duthost, container_name):
    """Checks whether the critical processes are running after container was restarted.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Returns:
        None.
    """
    status_result = duthost.critical_process_status(container_name)
    if status_result["status"] is False or len(status_result["exited_critical_process"]) > 0:
        return False

    return True


def postcheck_critical_processes(duthost, container_name):
    """Checks whether the critical processes are running after container was restarted.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Returns:
        None.
    """
    logger.info("Checking the running status of critical processes in '{}' container ..."
                .format(container_name))
    is_succeeded = wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS, 0,
                              check_critical_processes, duthost, container_name)
    if not is_succeeded:
        pytest.fail("Not all critical processes in '{}' container are running!"
                    .format(container_name))
    logger.info("All critical processes in '{}' container are running.".format(container_name))

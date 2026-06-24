import logging
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


def get_pid(duthost, process_name):
    """Get the PID of a process by name."""
    return duthost.shell("pgrep {}".format(process_name),
                         module_ignore_errors=True)["stdout"]


def get_mgmt_vrf_state(duthost):
    """
    Check if management VRF is currently enabled.
    Returns True if mgmt VRF exists, False otherwise.
    """
    command = 'show mgmt-vrf | grep ManagementVRF | cut -d ":" -f 2'
    result = duthost.shell(command, module_ignore_errors=True)
    if 'Disabled' in result:
        return False
    elif 'Enabled' in result:
        return True
    return False


def save_reload_config(duthost):
    """
    Save and reload the configuration, waiting for critical
    processes to restart.
    """
    def _check_process_ready(duthost, process_name, old_pid):
        new_pid = get_pid(duthost, process_name)
        logger.debug("_check_orchagent_ready: {} PID {}"
                     .format(process_name, new_pid))
        return new_pid != "" and new_pid != old_pid

    orchagent_pid = get_pid(duthost, "orchagent")
    telemetry_pid = get_pid(duthost, "telemetry")

    result = duthost.shell("sudo config save -y", module_ignore_errors=True)
    logger.debug("Save config: {}".format(result))
    result = duthost.shell("sudo config reload -y -f",
                           module_ignore_errors=True)
    logger.debug("Reload config: {}".format(result))

    pytest_assert(wait_until(360, 2, 0, _check_process_ready, duthost,
                             "orchagent", orchagent_pid),
                  "orchagent did not start after subtype change")

    pytest_assert(wait_until(360, 2, 0, _check_process_ready, duthost,
                             "telemetry", telemetry_pid),
                  "telemetry did not start after subtype change")


def gnmi_set(duthost, ptfhost, delete_list, update_list, replace_list):
    """
    Execute a gNMI set operation.

    Args:
        duthost: The DUT host object
        ptfhost: The PTF host object
        delete_list: List of paths to delete
        update_list: List of paths to update
        replace_list: List of paths to replace
    """
    ip = duthost.mgmt_ip
    port = 8080
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 --notls '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-m set-update '
    xpath = ''
    xvalue = ''
    for path in delete_list:
        path = path.replace('sonic-db:', '')
        xpath += ' ' + path
        xvalue += ' ""'
    for update in update_list:
        update = update.replace('sonic-db:', '')
        result = update.rsplit(':', 1)
        xpath += ' ' + result[0]
        xvalue += ' ' + result[1]
    for replace in replace_list:
        replace = replace.replace('sonic-db:', '')
        result = replace.rsplit(':', 1)
        xpath += ' ' + result[0]
        if '#' in result[1]:
            xvalue += ' ""'
        else:
            xvalue += ' ' + result[1]
    cmd += '--xpath ' + xpath
    cmd += ' '
    cmd += '--value ' + xvalue
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    error = "GRPC error\n"
    if error in output['stdout']:
        result = output['stdout'].split(error, 1)
        raise Exception("GRPC error:" + result[1])
    return


def enable_zmq_fixture(duthost, enable_mgmt_vrf=False):
    """
    Common fixture logic for enabling ZMQ.

    Args:
        duthost: The DUT host object
        enable_mgmt_vrf: If True, enable management VRF before config save

    Returns:
        A tuple of (initial_mgmt_vrf_enabled, subtype) for cleanup
    """
    # Capture initial management VRF state if needed
    initial_mgmt_vrf_enabled = None
    if enable_mgmt_vrf:
        initial_mgmt_vrf_enabled = get_mgmt_vrf_state(duthost)
        logger.debug("Initial management VRF state: {}".format(
            "enabled" if initial_mgmt_vrf_enabled else "disabled"))

    command = 'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" subtype'
    subtype = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.debug("subtype: {}".format(subtype))

    # the device already enable SmartSwitch
    if subtype == "SmartSwitch":
        if enable_mgmt_vrf:
            # Enable management VRF in CONFIG_DB without applying immediately.
            # Using sonic-db-cli instead of 'config vrf add mgmt' to avoid
            # disrupting SSH connectivity before the config reload.
            logger.debug("Enabling management VRF")
            duthost.shell(
                'sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" '
                '"mgmtVrfEnabled" "true"')
            save_reload_config(duthost)
        return initial_mgmt_vrf_enabled, subtype

    # enable ZMQ
    command = 'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" subtype SmartSwitch'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.debug("set subtype subtype: {}".format(result))

    if enable_mgmt_vrf:
        # Enable management VRF in CONFIG_DB without applying immediately.
        # Using sonic-db-cli instead of 'config vrf add mgmt' to avoid
        # disrupting SSH connectivity before the config reload.
        logger.debug("Enabling management VRF")
        duthost.shell(
            'sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" '
            '"mgmtVrfEnabled" "true"')

    save_reload_config(duthost)

    pytest_assert(wait_until(360, 10, 120,
                             duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    pytest_assert(
        wait_until(360, 10, 0, duthost.check_bgp_session_state, bgp_neighbors),
        "bgp sessions {} are not up".format(bgp_neighbors)
    )

    return initial_mgmt_vrf_enabled, subtype


def cleanup_zmq_fixture(duthost, initial_mgmt_vrf_enabled,
                        subtype, enable_mgmt_vrf=False):
    """
    Common fixture cleanup logic for ZMQ tests.

    Args:
        duthost: The DUT host object
        initial_mgmt_vrf_enabled: The initial state of management VRF
                                   (or None if not tracked)
        subtype: The original subtype value
        enable_mgmt_vrf: If True, restore management VRF to initial state
    """
    # Only revert if we changed the subtype
    if subtype != "SmartSwitch":
        # revert change
        command = \
            'sonic-db-cli CONFIG_DB hdel "DEVICE_METADATA|localhost" subtype'
        result = duthost.shell(command, module_ignore_errors=True)
        logger.debug("revert subtype subtype: {}".format(result))

    # Restore management VRF to initial state if needed
    if enable_mgmt_vrf and initial_mgmt_vrf_enabled is not None:
        if not initial_mgmt_vrf_enabled:
            logger.debug("Restoring management VRF to disabled state")
            duthost.shell(
                'sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" '
                '"mgmtVrfEnabled" "false"')

    # Only reload if we made changes
    if subtype != "SmartSwitch" or \
       (enable_mgmt_vrf and not initial_mgmt_vrf_enabled):
        save_reload_config(duthost)

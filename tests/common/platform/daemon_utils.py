"""
Helper script for checking status of platform daemon status

This script contains re-usable functions for checking status of platform daemon status.
"""
import logging

AMD_ELBA_PLATFORM = 'arm64-elba-asic-flash128-r0'

def check_pmon_daemon_status(dut):
    """
    @summary: check daemon running status inside pmon docker.

    This function use command "supervisorctl status" inside the container and check the status from the command output.
    If the daemon status is "RUNNING" then return True, if daemon not exist or status is not "RUNNING", return false.
    """
    unsupported_daemon_values_per_platform  = {AMD_ELBA_PLATFORM : ['pcied']}
    platform = dut.facts['platform']
    daemons = dut.get_pmon_daemon_states()
    ret = True
    for daemon, state in list(daemons.items()):
        if daemon in unsupported_daemon_values_per_platform.get(platform, []):
            logging.info(f"Daemon '{daemon}' in State '{state}', is not supported in Platform '{platform}'")
            continue
        logging.debug("Daemon %s status is %s" % (daemon, state))
        if state != 'RUNNING':
            ret = False

    return ret


def check_pmon_daemon_enable_status(dut, daemon_name):
    """
    @summary: check daemon running status inside pmon docker.

    This function use command "supervisorctl status" inside the container and check the status from the command output.
    If the daemon status is "RUNNING" then return True, if daemon not exist or status is not "RUNNING", return false.
    """
    daemons = dut.get_pmon_daemon_states()
    ret = False
    for daemon, state in list(daemons.items()):
        logging.debug("Daemon %s status is %s" % (daemon, state))
        if daemon == daemon_name:
            ret = True

    return ret

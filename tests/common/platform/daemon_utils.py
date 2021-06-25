"""
Helper script for checking status of platform daemon status

This script contains re-usable functions for checking status of platform daemon status.
"""
import logging


def check_pmon_daemon_status(dut):
    """
    @summary: check daemon running status inside pmon docker.

    This function use command "supervisorctl status" inside the container and check the status from the command output.
    If the daemon status is "RUNNING" then return True, if daemon not exist or status is not "RUNNING", return false.
    """
    daemons = dut.get_pmon_daemon_states()
    ret     = True
    for daemon, state in daemons.items():
        logging.debug("Daemon %s status is %s" % (daemon, state))
        if state != 'RUNNING':
            ret = False

    return ret

def get_pmon_daemon_running_status(dut, daemon_name):
    """
    @summary: check daemon running status inside pmon docker.

    This function use command "supervisorctl status daemon_name" inside the container and check the status from the command output.
    The daemon status can be "RUNNING"/"EXITED"/"STOPPED"
    """
    return dut.get_pmon_daemon_status()

def get_pmon_daemon_enable_status(dut, daemon_name):
    """
    @summary: check daemon enabled status inside pmon docker.

    This function use command "cat /usr/share/sonic/device/{platform}/pmon_daemon_control.json" inside the container and check the enabled status from the command output.
    """
    return dut.get_pmon_daemon_enable_status(daemon_name)

def stop_pmon_daemon(dut, daemon_name, sig_name):
    """
    @summary: check daemon running status inside pmon docker.

    This function use command "supervisorctl stop" or "kill sig_name pid" inside the container and check command status from the command output.
    If the command output is "stopped" for "supervisorctl stop" then return True, if not, return false.
    If the command output is "" for "kill sig_name pid" then return True, if not, return false.
    """
    return dut.stop_pmon_daemon(daemon_name)

def start_pmon_daemon(dut, daemon_name):
    """
    @summary: check daemon running status inside pmon docker.

    This function use command "supervisorctl start" inside the container and start the daemon.
    If the command output is "started" then return true, if not, return false.
    """
    return dut.start_pmon_daemon(daemon_name)

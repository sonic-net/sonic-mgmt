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
    daemon_list = dut.get_pmon_daemon_list()
    daemon_status = {}
    try:
        for daemon in daemon_list:
            output = dut.shell('docker exec pmon supervisorctl status | grep %s' % daemon, module_ignore_errors=True)
            if bool(output["stdout_lines"]):
                expected_line = output["stdout_lines"][0]
                expected_line_list = expected_line.split()
                daemon_status[daemon] = (daemon in expected_line_list and 'RUNNING' in expected_line_list)
                logging.debug("Daemon %s status is %s" % (daemon, str(daemon_status[daemon])))
            else:
                logging.debug("Daemon %s does not exist" % daemon)
                return False
        return all(daemon_status.values())
    except:
        return False

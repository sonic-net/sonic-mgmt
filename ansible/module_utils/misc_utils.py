#!/usr/bin/python
"""
Miscellaneous utility functions for ansible modules
"""

import time


def wait_for_path(ssh, host_ip, path_to_check, empty_ok=False, tries=5, delay=60):
    """
    Wait for a file path to exist on a remote host over SSH.

    Args:
        ssh: paramiko SSH client connection
        host_ip: IP address of the host (for logging)
        path_to_check: File path to check for existence
        empty_ok: If False, also verify the file is not empty
        tries: Number of retry attempts
        delay: Delay in seconds between retries

    Raises:
        FileNotFoundError: If the path doesn't exist after all retries
    """
    for attempt in range(tries):
        try:
            if empty_ok:
                check_cmd = "test -e {}".format(path_to_check)
            else:
                check_cmd = "test -s {}".format(path_to_check)

            _, stdout, stderr = ssh.exec_command(check_cmd)
            exit_code = stdout.channel.recv_exit_status()

            if exit_code == 0:
                return True

        except Exception:
            pass

        if attempt < tries - 1:
            time.sleep(delay)

    raise FileNotFoundError("Path {} not found on {} after {} attempts".format(
        path_to_check, host_ip, tries))

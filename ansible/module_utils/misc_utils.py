import time


def wait_for_path(ssh, host_ip, path_to_check, empty_ok=False, tries=1, delay=5):
    with ssh.open_sftp() as sftp:
        for _ in range(tries):
            try:
                stat_result = sftp.stat(path_to_check)
                if empty_ok or stat_result.st_size > 0:
                    return
            except FileNotFoundError:
                pass
            time.sleep(delay)
    raise FileNotFoundError(
         "Failed to find {}path {} on host {} after {} retries.".
         format("" if empty_ok else "not empty ",
                path_to_check,
                host_ip,
                tries))

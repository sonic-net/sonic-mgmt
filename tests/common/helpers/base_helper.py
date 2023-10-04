"""
A helper module for all test types. Helper functions here are run on the sonic management docker.
"""


def read_logs(log_file_path):
    """
    Read logs from the sonic-mgmt docker.
    Args:
        duthost: DUT fixture
        log_file_path: Path of the log file to read

    Returns:
        log (List): Contents of the log file line by line as a list
    """
    try:
        with open(log_file_path, "r") as f:
            lines = f.readlines()
    except Exception:
        return None
    logs = []
    for line in lines:
        res = line.split(",")
        logs.append(res)

    return logs

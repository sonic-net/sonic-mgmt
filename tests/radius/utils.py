import os
import yaml
import logging
import json
import time

from scapy.all import rdpcap
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)


RADIUS_CRED_FILE = "radius_creds.yaml"
TCPDUMP_CAPTURE_TIME = 30
TCPDUMP_START_TIME = 5
DUT_CAPTURE_FILE = "/tmp/test_radius_source_ip.pcap"
DOCKER_TMP = "/tmp/"


def load_radius_creds():
    """
    loading testing radius creds into machine readable format
    """
    creds_file_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), RADIUS_CRED_FILE
    )
    return yaml.safe_load(open(creds_file_path).read())


def check_radius_stats(dut):
    """
    Function to return RADIUS Status from a Dut
    """
    # Initialize the stats object with default values
    stats_obj = {"access_rejects": 0, "access_accepts": 0}

    # Get the radius statistics output
    stats = dut.command("show radius")

    for line in stats["stdout"].splitlines():
        for key in stats_obj.keys():
            if key in line:
                # Extract the value after the key
                stats_obj[key] = int(line.split(key + " ")[-1])

    return stats_obj


def check_group_output(result, creds, user_type):
    """
    Check if a user belongs to a specific group
    """
    pytest_assert(not result["failed"], result["stderr"])
    for line in result["stdout_lines"]:
        objects = line.split(":")
        # userids are stored in object[3]
        if "docker" == objects[0]:
            pytest_assert(creds in objects[3])
        if "sudo" == objects[0]:
            if user_type == "rw":
                pytest_assert(creds in objects[3])
            else:
                pytest_assert(creds not in objects[3])


def ssh_remote_run(localhost, remote_ip, username, password, cmd):
    """
    ssh to a remote host using the username
    and password passed into the function
    """
    res = localhost.shell(
        "sshpass -p {} ssh "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "{}@{} {}".format(password, username, remote_ip, cmd),
        module_ignore_errors=True,
    )
    return res


def ssh_remote_allow_run(localhost, remote_ip, username, password, cmd):
    """
    Ensure command that is run on remote DUT is not allowed
    return True if command is accepted due to local Auth permission mapping
    """
    res = ssh_remote_run(localhost, remote_ip, username, password, cmd)
    # Verify that the command is allowed
    logger.info('check command "{}" rc={}'.format(cmd, res["rc"]))
    expected = (
        "Make sure your account has RW permission to current device"
        not in res["stderr"]
        and "Permission denied" not in res["stderr"]
    )
    if not expected:
        logger.error('error output="{}"'.format(res["stderr"]))
    return expected


def ssh_remote_ban_run(localhost, remote_ip, username, password, cmd):
    """
    Ensure command that is run on remote DUT is not allowed
    return True if command is rejected due to local Auth permission mapping
    """
    res = ssh_remote_run(localhost, remote_ip, username, password, cmd)
    # Verify that the command is allowed
    logger.info('check command "{}" rc={}'.format(cmd, res["rc"]))
    return (
        res["rc"] != 0
        and "Make sure your account has RW permission to current device"
        in res["stderr"]
    )


def start_tcpdump_and_try_login(
    duthost, ptfhost_mgmt_ip, localhost, radius_creds
):
    """
    The function serves as  worker function to test the source IP feature
    inside the RADIUS feature
    Order of operations:
     - Determine the correct egress interface based on the
       route to the RADIUS server
     - Start a tcpdump capture on this interface of the DUT
     - Run a test login to the DUT from a different session
       forcing RADIUS traffic
     - Analyze packet capture
    """
    ptf_mgmt_prefix = ptfhost_mgmt_ip + "/32"
    route_json = json.loads(
        duthost.command(
            "show ip route {} json".format(ptf_mgmt_prefix)
        )["stdout"]
    )
    assert ptf_mgmt_prefix in route_json.keys()
    tcpdump_int = route_json[ptf_mgmt_prefix][0]["nexthops"][0][
        "interfaceName"
    ]

    tcpdump_command = (
        "sudo timeout {timeout} tcpdump -i {intf} port 1812 -w {dut_cap_file}"
        .format(
            timeout=TCPDUMP_CAPTURE_TIME,
            intf=tcpdump_int,
            dut_cap_file=DUT_CAPTURE_FILE,
        )
    )

    # remove any lingering tcpdump files
    duthost.command("sudo rm -rf {}".format(DUT_CAPTURE_FILE))
    tcpdump_task, tcpdump_result = duthost.shell(
        tcpdump_command, module_async=True
    )
    # wait for tcpdump to fully start
    time.sleep(TCPDUMP_START_TIME)
    logging.debug("Radius Capture file started, begin login test")
    ssh_remote_run(
        localhost,
        duthost.mgmt_ip,
        radius_creds["invalid_user"],
        radius_creds["invalid_user_passwd"],
        "show radius",
    )

    # stop tcpdump thread
    tcpdump_task.close()
    tcpdump_task.join()
    duthost.fetch(src=DUT_CAPTURE_FILE, dest=DOCKER_TMP)
    return os.path.join(
        DOCKER_TMP, duthost.hostname, DUT_CAPTURE_FILE.lstrip(os.path.sep)
    )


def verify_radius_capture(pcap_file, source_ip):
    """
    Opens a properly formatted PCAP file and checks
    if the first packet contains the expected source IP
    """
    packets = rdpcap(pcap_file)
    # first packet source should be from the DUT
    return packets[0]["IP"].src == source_ip

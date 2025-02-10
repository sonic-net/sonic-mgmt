import pytest
import shlex
from .utils import (
    check_group_output,
    ssh_remote_run,
    ssh_remote_allow_run,
    ssh_remote_ban_run,
    check_radius_stats,
)

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]


def test_radius_rw_user(
    localhost, duthosts, enum_rand_one_per_hwsku_hostname, radius_creds
):
    """test radius rw user"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    before_stats = check_radius_stats(duthost)

    res = ssh_remote_run(
        localhost,
        dutip,
        radius_creds["radius_rw_user"],
        radius_creds["radius_rw_user_passwd"],
        "cat /etc/group",
    )
    after_stats = check_radius_stats(duthost)
    check_group_output(res, radius_creds["radius_rw_user"], "rw")
    pytest_assert(
        after_stats["access_accepts"] > before_stats["access_accepts"]
    )
    pytest_assert(
        after_stats["access_rejects"] == before_stats["access_rejects"]
    )


def test_radius_ro_user(
    localhost, duthosts, enum_rand_one_per_hwsku_hostname, radius_creds
):
    """test radius RO user"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    before_stats = check_radius_stats(duthost)
    res = ssh_remote_run(
        localhost,
        dutip,
        radius_creds["radius_ro_user"],
        radius_creds["radius_ro_user_passwd"],
        "cat /etc/passwd",
    )

    check_group_output(res, radius_creds["radius_ro_user"], "ro")

    after_stats = check_radius_stats(duthost)
    pytest_assert(
        after_stats["access_accepts"] > before_stats["access_accepts"]
    )
    pytest_assert(
        after_stats["access_rejects"] == before_stats["access_rejects"]
    )


def test_radius_command_auth(
    localhost, duthosts, enum_rand_one_per_hwsku_hostname, radius_creds
):
    """test radius loccal command auth"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    show_commands = [
        "show version",
        "show interface status",
        "show lldp table",
        "show ip bgp summary",
        "show ip route",
        "docker ps",
        "sudo cat /var/log/syslog",
    ]

    for command in show_commands:
        allowed = ssh_remote_allow_run(
            localhost,
            dutip,
            radius_creds["radius_ro_user"],
            radius_creds["radius_ro_user_passwd"],
            command,
        )
        pytest_assert(allowed, "command '{}' not authorized".format(command))

    commands = [
        # all commands under the config tree
        "sudo config -h",
        "sudo cat /var/log/auth.log",
    ]

    # these commands should be not authorized
    for command in commands:
        banned = ssh_remote_ban_run(
            localhost,
            dutip,
            radius_creds["radius_ro_user"],
            radius_creds["radius_ro_user_passwd"],
            command,
        )
        pytest_assert(banned, "command '{}' authorized".format(command))


def test_radius_fallback(
    localhost, duthosts, enum_rand_one_per_hwsku_hostname, radius_creds
):
    """setup local user and test auth failthrough"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Escape special characters in user and password
    newuser_quoted = shlex.quote(radius_creds["local_user"])
    localpw_quoted = shlex.quote(radius_creds["local_user_passwd"])
    change_pw_command = "echo '{}:{}' | sudo chpasswd".format(
        newuser_quoted, localpw_quoted
    )

    duthost.shell(
        "sudo useradd -m -s /bin/bash {}".format(newuser_quoted),
        module_ignore_errors=True,
    )
    duthost.shell(change_pw_command, module_ignore_errors=True)

    dutip = duthost.mgmt_ip
    before_stats = check_radius_stats(duthost)
    res = ssh_remote_run(
        localhost, dutip, newuser_quoted, localpw_quoted, "show radius"
    )
    after_stats = check_radius_stats(duthost)

    pytest_assert(not res["failed"], res["stderr"])
    pytest_assert(
        after_stats["access_rejects"] > before_stats["access_rejects"]
    )


def test_radius_failed_auth(
    localhost, duthosts, enum_rand_one_per_hwsku_hostname, radius_creds
):
    """test user that should fail RADIUS authentication"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    dutip = duthost.mgmt_ip
    before_stats = check_radius_stats(duthost)
    res = ssh_remote_run(
        localhost,
        dutip,
        radius_creds["invalid_user"],
        radius_creds["invalid_user_passwd"],
        "show radius",
    )
    after_stats = check_radius_stats(duthost)

    pytest_assert(res["failed"])
    pytest_assert(
        after_stats["access_rejects"] > before_stats["access_rejects"]
    )


'''
Commenting out this function until
https://github.com/sonic-net/sonic-buildimage/issues/21386
is fixed
def test_radius_source_int(
    localhost,
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    radius_creds,
    routed_interfaces,
    ptfhost,
):
    """test RADIUS source interface feature"""
    if len(routed_interfaces) == 0:
        pytest.skip(
            "DUT has no routed interfaces, skipping RADIUS source IP test"
        )
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    source_int, source_ip = routed_interfaces[0]

    # remove current radius server config and reconfigure with source int
    duthost.command("sudo config radius delete {}".format(ptfhost.mgmt_ip))
    duthost.command(
        "sudo config radius add {} --key {} -s {}".format(
            ptfhost.mgmt_ip, radius_creds["radius_secret"], source_int
        )
    )

    # start tcpdump and testlogin
    pcap_file = start_tcpdump_and_try_login(
        duthost, ptfhost.mgmt_ip, localhost, radius_creds
    )

    pytest_assert(verify_radius_capture(pcap_file, source_ip))
'''

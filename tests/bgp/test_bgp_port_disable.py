import pytest
import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

FRR_USER_UID = '300'
RESTRICTED_ACCESS_PORTS = ['2605', '2616']
UID_RESTRICTED_PORTS = ['2601', '2620']


def generate_iptables_rule():
    iptables_rules = []
    iptables_rules.append("-o lo -p tcp -m tcp --dport 2601 -j DROP")
    iptables_rules.append("-o lo -p tcp -m tcp --dport 2620 -j DROP")
    iptables_rules.append("-o lo -p tcp -m tcp --dport 2601 -m owner --uid-owner 300 -j ACCEPT")
    iptables_rules.append("-o lo -p tcp -m tcp --dport 2620 -m owner --uid-owner 300 -j ACCEPT")
    return iptables_rules


def restart_caclmgrd(duthost):
    def _check_caclmgrd_running():
        command = 'pgrep -f -c caclmgrd'
        return int(duthost.shell(command, module_ignore_errors=True)['stdout']) >= 1

    duthost.shell('sudo systemctl restart caclmgrd')
    time.sleep(10)
    pytest_assert(wait_until(20, 1, 0, _check_caclmgrd_running), "caclmgrd not running")


def setup_iptables_rule(duthost, action="add"):
    if action == "add":
        restart_caclmgrd(duthost)
    else:
        iptables_rules = generate_iptables_rule()

        # Dynamically construct and execute iptables deletion commands
        for rule in iptables_rules:
            command = "sudo iptables -D OUTPUT {}".format(rule)
            duthost.shell(command)


def verify_daemon_tcp_ports(duthost):
    # Capture local address/port to verify restrictions
    netstat_outputs = duthost.shell("sudo netstat -tlnp |  awk '{print $4}'", module_ignore_errors=True)["stdout"]

    for port in RESTRICTED_ACCESS_PORTS:
        pytest_assert(port not in netstat_outputs, "port {} is accessable".format(port))

    for port in UID_RESTRICTED_PORTS:
        pytest_assert(port in netstat_outputs, "port {} is not accessable".format(port))


def verify_iptables_rules_exist(duthost):
    expected_rules = generate_iptables_rule()
    iptables_output = duthost.command("sudo iptables -S")["stdout_lines"]

    logger.info('iptables_output = {}'.format(iptables_output))

    for rule in expected_rules:
        command = "-A OUTPUT {}".format(rule)
        pytest_assert(command in iptables_output, "'{}' is missing".format(rule))


def verify_port_accessibility_for_other_users(duthost, port, restrict=True):
    command = ('timeout 5s bash -c "until </dev/tcp/localhost/{}; do sleep 0.1; done" '
               '&& echo "success" || echo "fail"'.format(port))
    output = duthost.shell(command)["stdout"]
    if restrict:
        pytest_assert("fail" in output, "Port {} is accessible by users other than FRR_USER_UID".format(port))
    else:
        pytest_assert("success" in output, "Port {} is not accessible".format(port))


def verify_port_accessibility_fpmsyncd(duthost):
    cmd = "docker exec -it bgp bash -c 'supervisorctl restart fpmsyncd'"

    duthost.command(cmd, module_ignore_errors=True)
    time.sleep(5)

    # verify the connection between fpmsyncd and zebra
    cmd = 'sudo ss -tupn | grep 2620'
    output = duthost.shell(cmd)['stdout']
    logger.info("cmd = {}, output = {}".format(cmd, output))
    pytest_assert("fpmsyncd" in output and "zebra" in output, "Connection issue detected")


def test_zebra_uid(duthost):
    uid_command = "ps -ef | grep /usr/lib/frr/zebra | grep -v grep | awk '{print $1}'"
    uid_output = duthost.shell(uid_command)["stdout"].strip()
    if not uid_output:
        pytest.fail("Failed to get zebra uid")
    pytest_assert(uid_output == FRR_USER_UID, "uid output = {} are not equal to expected zebra uid = {}"
                  .format(uid_output, FRR_USER_UID))


def test_daemon_tcp_port_access_restrictions(duthost):
    verify_daemon_tcp_ports(duthost)
    verify_iptables_rules_exist(duthost)
    for port in UID_RESTRICTED_PORTS:
        verify_port_accessibility_for_other_users(duthost, port)
    verify_port_accessibility_fpmsyncd(duthost)


def test_iptables_rule_persistence(duthost):
    restart_caclmgrd(duthost)
    verify_daemon_tcp_ports(duthost)
    verify_iptables_rules_exist(duthost)
    for port in UID_RESTRICTED_PORTS:
        verify_port_accessibility_for_other_users(duthost, port)
    verify_port_accessibility_fpmsyncd(duthost)


def test_add_remove_stress(duthost):
    for _ in range(10):  # Repeat the add/remove cycle
        setup_iptables_rule(duthost, "remove")
        verify_port_accessibility_fpmsyncd(duthost)

        setup_iptables_rule(duthost, "add")
        for port in UID_RESTRICTED_PORTS:
            verify_port_accessibility_for_other_users(duthost, port)
        verify_port_accessibility_fpmsyncd(duthost)

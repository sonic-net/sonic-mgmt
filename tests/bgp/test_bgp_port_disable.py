import pytest
import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

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


def get_asic_namespace_hosts(duthost):
    if duthost.is_multi_asic:
        return duthost.asics
    return [duthost.sonichost]


def get_cacl_namespace_hosts(duthost):
    hosts = get_asic_namespace_hosts(duthost)
    if duthost.is_multi_asic:
        return [duthost.sonichost, *hosts]
    return hosts


def check_iptables_rules_exist(duthost):
    expected_rules = {"-A OUTPUT {}".format(rule) for rule in generate_iptables_rule()}
    for host in get_cacl_namespace_hosts(duthost):
        result = host.command("iptables -S")
        if not expected_rules.issubset(result["stdout_lines"]):
            return False
    return True


def wait_for_iptables_rules(duthost):
    consecutive_passes = 0

    def _rules_are_stable():
        nonlocal consecutive_passes
        # Require consecutive passes to avoid treating stale rules as a completed caclmgrd update.
        if check_iptables_rules_exist(duthost):
            consecutive_passes += 1
        else:
            consecutive_passes = 0
        return consecutive_passes >= 3

    return wait_until(60, 1, 0, _rules_are_stable)


def restart_caclmgrd(duthost):
    def _check_caclmgrd_running():
        command = 'pgrep -f -c caclmgrd'
        return int(duthost.shell(command, module_ignore_errors=True)['stdout']) >= 1

    duthost.shell('sudo systemctl restart caclmgrd')
    time.sleep(10)
    pytest_assert(wait_until(20, 1, 0, _check_caclmgrd_running), "caclmgrd not running")
    pytest_assert(wait_for_iptables_rules(duthost), "FRR access-control rules did not stabilize")


def setup_iptables_rule(duthost, action="add"):
    if action == "add":
        restart_caclmgrd(duthost)
    else:
        iptables_rules = generate_iptables_rule()
        for host in get_cacl_namespace_hosts(duthost):
            for rule in iptables_rules:
                host.command("iptables -D OUTPUT {}".format(rule))


def verify_daemon_tcp_ports(duthost):
    for host in get_asic_namespace_hosts(duthost):
        namespace = getattr(host, "namespace", None) or "host"
        netstat_outputs = []
        for line in host.command("netstat -tlnp")["stdout_lines"]:
            fields = line.split()
            if len(fields) >= 4 and fields[0] in ("tcp", "tcp6"):
                netstat_outputs.append(fields[3])

        for port in RESTRICTED_ACCESS_PORTS:
            pytest_assert(
                not any(address.endswith(":{}".format(port)) for address in netstat_outputs),
                "port {} is accessible in namespace {}".format(port, namespace)
            )

        for port in UID_RESTRICTED_PORTS:
            pytest_assert(
                any(address.endswith(":{}".format(port)) for address in netstat_outputs),
                "port {} is not accessible in namespace {}".format(port, namespace)
            )


def verify_iptables_rules_exist(duthost):
    expected_rules = generate_iptables_rule()
    for host in get_cacl_namespace_hosts(duthost):
        namespace = getattr(host, "namespace", None) or "host"
        iptables_output = host.command("iptables -S")["stdout_lines"]
        logger.info("iptables output in namespace %s: %s", namespace, iptables_output)

        for rule in expected_rules:
            command = "-A OUTPUT {}".format(rule)
            pytest_assert(
                command in iptables_output,
                "'{}' is missing in namespace {}".format(rule, namespace)
            )


def verify_port_accessibility_for_other_users(duthost, port, restrict=True):
    command = (
        "bash -c 'timeout 5s bash -c "
        "\"until </dev/tcp/localhost/{}; do sleep 0.1; done\" "
        "&& echo success || echo fail'"
    ).format(port)
    for host in get_asic_namespace_hosts(duthost):
        namespace = getattr(host, "namespace", None) or "host"
        output = host.command(command)["stdout"]
        if restrict:
            pytest_assert(
                "fail" in output,
                "Port {} is accessible by users other than FRR_USER_UID in namespace {}".format(port, namespace)
            )
        else:
            pytest_assert(
                "success" in output,
                "Port {} is not accessible in namespace {}".format(port, namespace)
            )


def check_fpmsyncd_connection(namespace, host):
    cmd = "ss -tupn '( sport = :2620 or dport = :2620 )'"
    output = host.command(cmd)["stdout"]
    logger.info("cmd = %s, namespace = %s, output = %s", cmd, namespace, output)
    return "fpmsyncd" in output and "zebra" in output


def verify_port_accessibility_fpmsyncd(duthost):
    duthost.docker_cmds_on_all_asics("supervisorctl restart fpmsyncd", "bgp")

    for host in get_asic_namespace_hosts(duthost):
        namespace = getattr(host, "namespace", None) or "host"
        pytest_assert(
            wait_until(20, 1, 0, check_fpmsyncd_connection, namespace, host),
            "Connection issue detected in namespace {}".format(namespace)
        )


def test_zebra_uid(duthost):
    uid_command = "ps -ef | grep /usr/lib/frr/zebra | grep -v grep | awk '{print $1}'"
    uid_output = duthost.shell(uid_command)["stdout_lines"]
    if not uid_output:
        pytest.fail("Failed to get zebra uid")
    pytest_assert(
        all(uid == FRR_USER_UID for uid in uid_output),
        "uid output = {} are not equal to expected zebra uid = {}".format(uid_output, FRR_USER_UID)
    )


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


def test_add_remove_stress(duthost, restart_caclmgrd_after_stress_test):
    for _ in range(10):  # Repeat the add/remove cycle
        setup_iptables_rule(duthost, "remove")
        verify_port_accessibility_fpmsyncd(duthost)

        setup_iptables_rule(duthost, "add")
        for port in UID_RESTRICTED_PORTS:
            verify_port_accessibility_for_other_users(duthost, port)
        verify_port_accessibility_fpmsyncd(duthost)


@pytest.fixture(scope="function")
def restart_caclmgrd_after_stress_test(duthost):
    yield
    # Ensure recovery action is always performed
    restart_caclmgrd(duthost)

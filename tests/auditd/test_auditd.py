import json
import pytest
import logging
import uuid
from tests.common.fixtures.tacacs import tacacs_creds   # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running
from tests.common.helpers.tacacs.tacacs_helper import check_tacacs, ssh_remote_run  # noqa: F401

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

RULES_DIR = "/etc/audit/rules.d/"
DOCKER_EXEC_CMD = "docker exec {} bash -c "
NSENTER_CMD = "nsenter --target 1 --pid --mount --uts --ipc --net "
CURL_HTTP_CODE_CMD = "curl -s -o /dev/null -w \%\{http_code\} http://localhost:50058"   # noqa: W605
CURL_CMD = "curl http://localhost:50058"    # noqa: W605
logger = logging.getLogger(__name__)


def verify_container_running(duthost, container_name):
    is_running = is_container_running(duthost, container_name)
    if not is_running:
        pytest.skip("Container {} is not running".format(container_name))


def test_auditd_functionality(duthosts, enum_rand_one_per_hwsku_hostname, check_auditd):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    container_name = "auditd"
    verify_container_running(duthost, container_name)
    hwsku = duthost.facts["hwsku"]
    if "Nokia-7215" in hwsku or "Nokia-7215-M0" in hwsku:
        rule_checksum = "fffb00199104c493d04a621b257c579c48d77225"
    else:
        rule_checksum = "3042c67383dccff079755c5f3daa2820e2ca392a"

    cmd = "sudo sh -c \"find {} -name *.rules -type f | sort | xargs cat 2>/dev/null | sha1sum\"".format(RULES_DIR)
    output = duthost.command(cmd)["stdout"]
    pytest_assert(rule_checksum in output, "Rule files checksum is not as expected")

    cmd = "cat /etc/audit/auditd.conf | sha1sum"
    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) + "'{} {}'".format(NSENTER_CMD, cmd))["stdout"]
    pytest_assert("7cdbd1450570c7c12bdc67115b46d9ae778cbd76" in output, "auditd.conf checksum is not as expected")

    cmd = 'grep "^active = yes" /etc/audit/plugins.d/syslog.conf'
    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) + """'{} {}'""".format(NSENTER_CMD, cmd))["stdout"]
    pytest_assert("active = yes" in output, "syslog.conf does not contain active=yes as expected")

    cmd = 'grep "^CPUQuota=10%" /lib/systemd/system/auditd.service'
    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) + """'{} {}'""".format(NSENTER_CMD, cmd))["stdout"]
    pytest_assert("CPUQuota=10%" in output, "auditd.service does not contain CPUQuota=10% as expected")

    cmd = "systemctl is-active auditd"
    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) + "'{} {}'".format(NSENTER_CMD, cmd))["stdout"]
    pytest_assert(output == "active", "Auditd daemon is not running")

    output = duthost.shell("show logging | grep 'audisp-syslog'")["stdout_lines"]
    pytest_assert(len(output) > 0, "Auditd logs are not sent to syslog")


def test_auditd_watchdog_functionality(duthosts, enum_rand_one_per_hwsku_hostname, check_auditd):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    container_name = "auditd_watchdog"
    verify_container_running(duthost, container_name)

    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) +
                             "'{} {}'".format(NSENTER_CMD, CURL_HTTP_CODE_CMD), module_ignore_errors=True)["stdout"]
    pytest_assert(output == "200", "Auditd watchdog reports auditd container is unhealthy")

    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) +
                             "'{} {}'".format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        pytest.fail("Invalid JSON response from auditd watchdog: {}".format(output))

    # Define expected keys
    expected_keys = [
        "auditd_conf",
        "syslog_conf",
        "auditd_rules",
        "auditd_service",
        "auditd_active",
        "rate_limit"
    ]

    # Check if all expected keys exist and have the value "OK"
    for key in expected_keys:
        pytest_assert(response.get(key) == "OK",
                      "Auditd watchdog check failed for {}: {}".format(key, response.get(key)))


def test_auditd_file_deletion(localhost, duthosts, enum_rand_one_per_hwsku_hostname,
                              tacacs_creds, check_tacacs, check_auditd):            # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    container_name = "auditd"
    verify_container_running(duthost, container_name)

    random_uuid = str(uuid.uuid4())
    random_file = f"/tmp/test_file_deletion_{random_uuid}"
    duthost.command(f"touch {random_file}")
    duthost.command(f"rm -f  {random_file}")
    cmd = f"sudo zgrep '{random_uuid}' /var/log/syslog* | grep 'audisp-syslog'"
    result = duthost.shell(cmd)["stdout_lines"]
    print(result)
    logger.info(result)
    assert any(random_uuid in line for line in result if line.strip()), \
        "Auditd file_deletion rule does not contain the expected logs"

    random_uuid = str(uuid.uuid4())
    random_file = f"/tmp/test_file_deletion_{random_uuid}"
    duthost.command(f"touch {random_file}")
    duthost.command(f"sudo rm -f {random_file}")
    cmd = f"sudo zgrep '{random_uuid}' /var/log/syslog* | grep 'audisp-syslog'"
    result = duthost.shell(cmd)["stdout_lines"]
    print(result)
    logger.info(result)
    assert any(random_uuid in line for line in result if line.strip()), \
        "Auditd file_deletion rule does not contain the expected logs"


def test_auditd_process_audit(localhost, duthosts, enum_rand_one_per_hwsku_hostname,
                              tacacs_creds, check_tacacs, check_auditd):            # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    container_name = "auditd"
    verify_container_running(duthost, container_name)

    ssh_remote_run(localhost,
                   dutip,
                   tacacs_creds['tacacs_rw_user'],
                   tacacs_creds['tacacs_rw_user_passwd'],
                   "echo 'Test Process Audit'")
    cmd = """show logging | grep 'audisp-syslog' | grep 'process_audit' | grep 'AUID="test_rwuser"' """
    result = duthost.shell(cmd)['stdout_lines']
    assert len(result) > 0, "Auditd process_audit rule does not contain the expected logs"


def test_auditd_user_group_management(localhost, duthosts, enum_rand_one_per_hwsku_hostname,
                                      tacacs_creds, check_tacacs, check_auditd):    # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    container_name = "auditd"
    verify_container_running(duthost, container_name)

    ssh_remote_run(localhost,
                   dutip,
                   tacacs_creds['tacacs_rw_user'],
                   tacacs_creds['tacacs_rw_user_passwd'],
                   "sudo su - anotheruser -c 'whoami'")
    cmd = """show logging | grep 'audisp-syslog' | grep 'user_group_management' | grep 'AUID="test_rwuser"' """
    result = duthost.shell(cmd)['stdout_lines']
    assert len(result) > 0, "Auditd user_group_management rule does not contain the expected logs"


def test_auditd_docker_commands(localhost, duthosts, enum_rand_one_per_hwsku_hostname,
                                tacacs_creds, check_tacacs, check_auditd):          # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    container_name = "auditd"
    verify_container_running(duthost, container_name)

    ssh_remote_run(localhost,
                   dutip,
                   tacacs_creds['tacacs_rw_user'],
                   tacacs_creds['tacacs_rw_user_passwd'],
                   "sudo docker ps")
    cmd = """show logging | grep 'audisp-syslog' | grep 'docker_commands' | grep 'AUID="test_rwuser"' """
    result = duthost.shell(cmd)['stdout_lines']
    assert len(result) > 0, "Auditd docker_commands rule does not contain the expected logs"


def test_auditd_config_changes(localhost, duthosts, enum_rand_one_per_hwsku_hostname,
                               tacacs_creds, check_tacacs, check_auditd):           # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    container_name = "auditd"
    verify_container_running(duthost, container_name)

    watch_files = {
        "group_changes": ["/etc/group"],
        "hosts_changes": ["/etc/hosts"],
        "passwd_changes": ["/etc/passwd"],
        "shadow_changes": ["/etc/shadow"],
        "sudoers_changes": ["/etc/sudoers"],
        "time_changes": ["/etc/localtime"],
        "auth_logs": ["/var/log/auth.log",
                      "/var/log.tmpfs/auth.log"],
        "cron_changes": ["/etc/crontab",
                         "/etc/cron.d",
                         "/etc/cron.daily",
                         "/etc/cron.hourly",
                         "/etc/cron.weekly",
                         "/etc/cron.monthly"],
        "dns_change": ["/etc/resolv.conf"],
        "docker_config": ["/etc/docker/daemon.json"],
        "docker_daemon": ["/usr/bin/dockerd"],
        "docker_service": ["/lib/systemd/system/docker.service"],
        "docker_socket": ["/lib/systemd/system/docker.socket"],
        "modules_changes": ["/sbin/insmod",
                            "/sbin/rmmod",
                            "/sbin/modprobe"],
        "log_changes": ["/var/log/testfile",
                        "/var/log.tmpfs/testfile"],
        "bin_changes": ["/bin/testfile"],
        "sbin_changes": ["/sbin/testfile"],
        "usr_bin_changes": ["/usr/bin/testfile"],
        "usr_sbin_changes": ["/usr/sbin/testfile"],
        "docker_storage": ["/var/lib/docker/testfile"]
    }

    for rule, files in watch_files.items():
        for file in files:
            ssh_remote_run(localhost,
                           dutip,
                           tacacs_creds['tacacs_rw_user'],
                           tacacs_creds['tacacs_rw_user_passwd'],
                           f"sudo touch {file}")
            cmd = f"""show logging | grep 'audisp-syslog' | grep '{rule}' | grep 'AUID="test_rwuser"' """
            result = duthost.shell(cmd)['stdout_lines']
            assert len(result) > 0, f"Auditd {rule} rule does not contain the expected logs"


def test_auditd_host_failure(localhost, duthosts, enum_rand_one_per_hwsku_hostname, check_auditd_failure):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    container_name = "auditd_watchdog"
    verify_container_running(duthost, container_name)

    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) +
                             "'{} {}'".format(NSENTER_CMD, CURL_HTTP_CODE_CMD), module_ignore_errors=True)["stdout"]
    pytest_assert(output == "500", "Auditd watchdog reports auditd container is healthy")

    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) +
                             "'{} {}'".format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        pytest.fail("Invalid JSON response from auditd watchdog: {}".format(output))

    # Define expected keys
    expected_keys = [
        "auditd_active"
    ]

    # Check if all expected keys exist and have the value "OK"
    for key in expected_keys:
        pytest_assert(response.get(key) != "FAIL",
                      "Auditd watchdog check not failed for {}: {}".format(key, response.get(key)))


def test_32bit_failure(duthosts, enum_rand_one_per_hwsku_hostname, check_auditd_failure_32bit, check_auditd):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    container_name = "auditd_watchdog"
    verify_container_running(duthost, container_name)

    hwsku = duthost.facts["hwsku"]
    if "Nokia-7215" not in hwsku and "Nokia-7215-M0" not in hwsku:
        pytest.skip("This test is only for Nokia-7215 and Nokia-7215-M0")

    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) +
                             "'{} {}'".format(NSENTER_CMD, CURL_HTTP_CODE_CMD), module_ignore_errors=True)["stdout"]
    pytest_assert(output == "500", "Auditd watchdog reports auditd container is healthy")

    output = duthost.command(DOCKER_EXEC_CMD.format(container_name) +
                             "'{} {}'".format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
    pytest_assert('"auditd_active":"FAIL ' in output, "Auditd watchdog reports auditd container is healthy")


def debug_log(duthost):
    content = duthost.command(r"sudo cat /etc/audit/rules.d/audit.rules", module_ignore_errors=True)["stdout"]
    logger.warning("Content of /etc/audit/rules.d/audit.rules: {}".format(content))

    running_config = duthost.command(r"sudo auditctl -s", module_ignore_errors=True)["stdout"]
    logger.warning("Auditd running config: {}".format(running_config))


def read_watchdog(duthost):
    output = duthost.command(DOCKER_EXEC_CMD.format("auditd_watchdog") +
                             "'{} {}'".format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        pytest.fail("Invalid JSON response from auditd watchdog: {} exception: {}".format(output, e))


def test_rate_limit(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    verify_container_running(duthost, "auditd_watchdog")

    debug_log(duthost)
    rate_limit_status = read_watchdog(duthost).get("rate_limit")
    pytest_assert(rate_limit_status == "OK",
                  "Auditd watchdog check rate limit failed for: {}".format(rate_limit_status))

    # watchdog will report FAIL when auditd running config mismatch with config file
    duthost.command(r"sudo cp /etc/audit/rules.d/audit.rules /etc/audit.rules_backup")
    duthost.command(r"sudo sed -i -e '$a\'$'\n''-r 1000' /etc/audit/rules.d/audit.rules")
    duthost.command(r"sudo auditctl -r 2000")

    debug_log(duthost)
    rate_limit_status = read_watchdog(duthost).get("rate_limit")

    # revert change before check result, so assert failed will not break next test
    duthost.command(r"sudo cp /etc/audit.rules_backup /etc/audit/rules.d/audit.rules")
    duthost.command(r"sudo service auditd restart")

    pytest_assert(rate_limit_status.startswith("FAIL (rate_limit: "),
                  "Auditd watchdog check rate limit failed for: {}".format(rate_limit_status))

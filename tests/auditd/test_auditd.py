import re
import json
import uuid
import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.tacacs.tacacs_helper import ssh_remote_run

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

RULES_DIR = "/etc/audit/rules.d/"
NSENTER_CMD = "nsenter --target 1 --pid --mount --uts --ipc --net"
DOCKER_EXEC_CMD = "docker exec {} bash -c "
AUDITD_CMD = DOCKER_EXEC_CMD.format("auditd") + "'{} {}'"
AUDITD_WATCHDOG_CMD = DOCKER_EXEC_CMD.format("auditd_watchdog") + "'{} {}'"
CURL_HTTP_CODE_CMD = "curl -s -o /dev/null -w \%\{http_code\} http://localhost:50058"   # noqa: W605
CURL_CMD = "curl http://localhost:50058"    # noqa: W605
logger = logging.getLogger(__name__)


def is_log_valid(pattern, logs):
    for log in logs:
        if pattern in log and "ansible-ansible" not in log:
            return True
    return False


def extract_audit_timestamp(logs, include_seq=False):
    """
    Extracts the audit timestamp from auditd logs.

    Args:
        logs: A list of log lines
        include_seq:
            - If False: extracts only the timestamp portion (e.g., '1688329461.744').
            - If True: extracts the full timestamp with sequence number (e.g., '1688329461.744:1123').

    Returns:
        str: The extracted timestamp or full timestamp with sequence, or an empty string if not found.

    Regex explanation:
        - r'audit\((\d+\.\d+):\d+\)' matches the timestamp only.
            Example match: audit(1688329461.744:1123) --> group(1) = '1688329461.744'   # noqa: W605
        - r'audit\((\d+\.\d+:\d+)\)' matches the full timestamp with sequence.
            Example match: audit(1688329461.744:1123) --> group(1) = '1688329461.744:1123'   # noqa: W605

    Notes:
        - Lines containing 'ansible-ansible' (produced by Ansible) are skipped

    Example:
        log1: "type=SYSCALL msg=audit(1688329461.744:1123): arch=c000003e syscall=59 ..."
        - extract_audit_timestamp([log1], include_seq=False) --> '1688329461.744'

        log2: "type=PATH msg=audit(1688329461.744:1124): item=0 name=\"/usr/bin/docker\" ..."
        - extract_audit_timestamp([log2], include_seq=True) --> '1688329461.744:1124'
    """

    # Choose regex based on whether to include the sequence number
    regex = r'audit\((\d+\.\d+:\d+)\)' if include_seq else r'audit\((\d+\.\d+):\d+\)'
    for log in logs:
        # Skip logs produced by Ansible
        if "ansible-ansible" not in log:
            match = re.search(regex, log)
            if match:
                return match.group(1)
    # No matching timestamp found
    return ''


def test_auditd_functionality(duthosts,
                              enum_rand_one_per_hwsku_hostname,
                              verify_auditd_containers_running,
                              check_auditd):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    output = duthost.command("file -L /bin/sh")["stdout"]
    if "32-bit" in output:
        rule_checksum = "ac45b13d45de02f08e12918e38b4122206859555"
    elif "64-bit" in output:
        rule_checksum = "1c532e73fdd3f7366d9c516eb712102d3063bd5a"

    cmd = "sudo sh -c \"find {} -name *.rules -type f | sort | xargs cat 2>/dev/null | sha1sum\"".format(RULES_DIR)
    output = duthost.command(cmd)["stdout"]
    pytest_assert(rule_checksum in output, "Rule files checksum is not as expected")

    cmd = "cat /etc/audit/auditd.conf | sha1sum"
    output = duthost.command(AUDITD_CMD.format(NSENTER_CMD, cmd))["stdout"]
    pytest_assert("7cdbd1450570c7c12bdc67115b46d9ae778cbd76" in output, "auditd.conf checksum is not as expected")

    cmd = 'grep "^active = yes" /etc/audit/plugins.d/syslog.conf'
    output = duthost.command(AUDITD_CMD.format(NSENTER_CMD, cmd))["stdout"]
    pytest_assert("active = yes" in output, "syslog.conf does not contain active=yes as expected")

    cmd = 'grep "^CPUQuota=10%" /lib/systemd/system/auditd.service'
    output = duthost.command(AUDITD_CMD.format(NSENTER_CMD, cmd))["stdout"]
    pytest_assert("CPUQuota=10%" in output, "auditd.service does not contain CPUQuota=10% as expected")

    cmd = "systemctl is-active auditd"
    output = duthost.command(AUDITD_CMD.format(NSENTER_CMD, cmd))["stdout"]
    pytest_assert(output == "active", "Auditd daemon is not running")

    output = duthost.shell("show logging | grep 'audisp-syslog'")["stdout_lines"]
    pytest_assert(len(output) > 0, "Auditd logs are not sent to syslog")


def test_auditd_watchdog_functionality(duthosts,
                                       enum_rand_one_per_hwsku_hostname,
                                       verify_auditd_containers_running,
                                       check_auditd):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.command(AUDITD_WATCHDOG_CMD.format(NSENTER_CMD, CURL_HTTP_CODE_CMD),
                             module_ignore_errors=True)["stdout"]
    pytest_assert(output == "200", "Auditd watchdog reports auditd container is unhealthy")

    output = duthost.command(AUDITD_WATCHDOG_CMD.format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
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


def test_modules_changes(localhost,
                         duthosts,
                         enum_rand_one_per_hwsku_hostname,
                         creds,
                         verify_auditd_containers_running,
                         check_auditd,
                         reset_auditd_rate_limit):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    kernel_version = duthost.command("uname -r")["stdout"].strip()
    ssh_remote_run(localhost, dutip, creds['sonicadmin_user'], creds['sonicadmin_password'],
                   "sudo cat /lib/modules/6.1.0-29-2-amd64/kernel/drivers/net/dummy.ko > /dev/null")

    # Search SYSCALL & PATH logs
    cmd = f"sudo zgrep /lib/modules/{kernel_version}/kernel/drivers/net/dummy.ko /var/log/syslog* | grep type=PATH"
    logs = duthost.shell(cmd)["stdout_lines"]

    assert is_log_valid("type=PATH", logs), "Auditd modules_changes rule does not contain the PATH logs"

    full_timestamp = extract_audit_timestamp(logs, include_seq=True)

    cmd = f"sudo zgrep {full_timestamp} /var/log/syslog* | grep modules_changes"
    logs = duthost.shell(cmd)["stdout_lines"]

    assert is_log_valid("type=SYSCALL", logs), "Auditd modules_changes rule does not contain the SYSCALL logs"


def test_directory_based_keys(localhost,
                              duthosts,
                              enum_rand_one_per_hwsku_hostname,
                              creds,
                              verify_auditd_containers_running,
                              check_auditd,
                              reset_auditd_rate_limit):
    """
    Test directory-based rules (triggered by creating files in watched directories)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    random_uuid = str(uuid.uuid4())
    key_file_mapping = {
        "file_deletion": ["/tmp/"],
        "cron_changes": ["/etc/cron.d/",
                         "/etc/cron.daily/",
                         "/etc/cron.hourly/",
                         "/etc/cron.weekly/",
                         "/etc/cron.monthly/"],
        "docker_storage": ["/var/lib/docker/"],
        "usr_bin_changes": ["/bin/",
                            "/usr/bin/"],
        "usr_sbin_changes": ["/sbin/",
                             "/usr/sbin/"],
        "log_changes": ["/var/log/"],
        "user_group_management": ["/tmp/"],
        "70726F636573735F617564697401746163706C7573": ["/tmp/"]
    }

    for key, paths in key_file_mapping.items():
        for path in paths:
            random_file = f"{path}{random_uuid}"
            # Trigger audit event
            ssh_remote_run(localhost, dutip, creds['sonicadmin_user'], creds['sonicadmin_password'],
                           f"sudo touch {random_file}")

            ssh_remote_run(localhost, dutip, creds['sonicadmin_user'], creds['sonicadmin_password'],
                           f"sudo rm -f  {random_file}")

            cmd = f"sudo zgrep '{random_file}' /var/log/syslog*"
            logs = duthost.shell(cmd)["stdout_lines"]

            timestamp = extract_audit_timestamp(logs)

            # Search SYSCALL & PATH logs
            cmd = f"""sudo zgrep '{timestamp}' /var/log/syslog* | grep '{key}' """
            logs = duthost.shell(cmd)["stdout_lines"]
            assert is_log_valid("type=SYSCALL", logs), \
                f"Auditd {key} rule does not contain the SYSCALL logs"

            full_timestamp = extract_audit_timestamp(logs, include_seq=True)

            if key == "user_group_management":
                continue
            cmd = f"""sudo zgrep '{full_timestamp}' /var/log/syslog* """
            logs = duthost.shell(cmd)["stdout_lines"]
            assert is_log_valid("type=PATH", logs), \
                f"Auditd {key} rule does not contain the PATH logs"


def test_file_based_keys(localhost,
                         duthosts,
                         enum_rand_one_per_hwsku_hostname,
                         creds,
                         verify_auditd_containers_running,
                         check_auditd,
                         reset_auditd_rate_limit):
    """
    Test file-based auditd rules using 'sudo chown root:root <file>'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    key_file_mapping = {
        "auth_logs": ["/var/log/auth.log"],
        "cron_changes": ["/etc/crontab"],
        "dns_changes": ["/etc/resolv.conf", "/run/resolvconf/resolv.conf"],
        "docker_daemon": ["/usr/bin/dockerd"],
        "docker_service": ["/lib/systemd/system/docker.service"],
        "docker_socket": ["/lib/systemd/system/docker.socket"],
        "group_changes": ["/etc/group"],
        "hosts_changes": ["/etc/hosts"],
        "passwd_changes": ["/etc/passwd"],
        "shadow_changes": ["/etc/shadow"],
        "shutdown_reboot": ["/var/log/wtmp"],
        "sudoers_changes": ["/etc/sudoers"],
        "time_changes": ["/etc/localtime", "/usr/share/zoneinfo/Etc/UTC"],
    }

    for key, paths in key_file_mapping.items():
        for path in paths:
            # Trigger audit event
            chown_cmd = f"sudo chown root:root {path}"
            ssh_remote_run(localhost, dutip, creds['sonicadmin_user'], creds['sonicadmin_password'], chown_cmd)

            # Search SYSCALL & PATH logs
            cmd = f"sudo zgrep '{path}' /var/log/syslog*"
            logs = duthost.shell(cmd)["stdout_lines"]

            assert is_log_valid("type=PATH", logs), \
                f"Auditd {key} rule does not contain the PATH logs for {path}"

            full_timestamp = extract_audit_timestamp(logs, include_seq=True)

            cmd = f"sudo zgrep {full_timestamp} /var/log/syslog* | grep '{key}'"
            logs = duthost.shell(cmd)["stdout_lines"]

            assert is_log_valid("type=SYSCALL", logs), \
                f"Auditd {key} rule does not contain the SYSCALL logs for {path}"


def test_docker_config(localhost,
                       duthosts,
                       enum_rand_one_per_hwsku_hostname,
                       creds,
                       verify_auditd_containers_running,
                       check_auditd,
                       reset_auditd_rate_limit):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    key_file_mapping = {
        "docker_config": ["/etc/docker/daemon.json"],
    }

    for key, paths in key_file_mapping.items():
        for path in paths:
            # Check if the file exists
            check_cmd = f"sudo test -e {path} && echo exists || echo missing"
            exists = duthost.shell(check_cmd)['stdout_lines']

            if "exists" in exists:
                # File exists, trigger event using chown
                ssh_remote_run(localhost, dutip, creds['sonicadmin_user'], creds['sonicadmin_password'],
                               f"sudo chown root:root {path}")
            elif "missing" in exists:
                # File doesn't exist, create and delete to trigger event
                ssh_remote_run(localhost, dutip, creds['sonicadmin_user'], creds['sonicadmin_password'],
                               f"sudo touch {path}")
                ssh_remote_run(localhost, dutip, creds['sonicadmin_user'], creds['sonicadmin_password'],
                               f"sudo rm -f {path}")

            # Search SYSCALL & PATH logs
            cmd = f"sudo zgrep '{path}' /var/log/syslog*"
            logs = duthost.shell(cmd)["stdout_lines"]

            assert is_log_valid("type=PATH", logs), \
                f"Auditd {key} rule does not contain the PATH logs for {path}"

            full_timestamp = extract_audit_timestamp(logs, include_seq=True)
            cmd = f"sudo zgrep {full_timestamp} /var/log/syslog* | grep '{key}'"
            logs = duthost.shell(cmd)["stdout_lines"]

            assert is_log_valid("type=SYSCALL", logs), \
                f"Auditd {key} rule does not contain the SYSCALL logs for {path}"


def test_docker_commands(localhost,
                         duthosts,
                         enum_rand_one_per_hwsku_hostname,
                         creds,
                         verify_auditd_containers_running,
                         check_auditd,
                         reset_auditd_rate_limit):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    ssh_remote_run(localhost, dutip, creds['sonicadmin_user'], creds['sonicadmin_password'], "docker ps")

    # Search SYSCALL & PATH logs
    cmd = "sudo zgrep docker_commands /var/log/syslog* | grep /usr/bin/docker"
    logs = duthost.shell(cmd)["stdout_lines"]

    assert is_log_valid("type=SYSCALL", logs), "Auditd docker_commands rule does not contain the SYSCALL logs"

    full_timestamp = extract_audit_timestamp(logs, include_seq=True)

    cmd = f"sudo zgrep {full_timestamp} /var/log/syslog*"
    logs = duthost.shell(cmd)["stdout_lines"]

    assert is_log_valid("type=PATH", logs), "Auditd docker_commands rule does not contain the PATH logs"


def test_auditd_host_failure(localhost,
                             duthosts,
                             enum_rand_one_per_hwsku_hostname,
                             verify_auditd_containers_running,
                             check_auditd_failure,
                             reset_auditd_rate_limit):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.command(AUDITD_WATCHDOG_CMD.format(NSENTER_CMD, CURL_HTTP_CODE_CMD),
                             module_ignore_errors=True)["stdout"]
    pytest_assert(output == "500", "Auditd watchdog reports auditd container is healthy")

    output = duthost.command(AUDITD_WATCHDOG_CMD.format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
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


def test_32bit_failure(duthosts,
                       enum_rand_one_per_hwsku_hostname,
                       verify_auditd_containers_running,
                       check_auditd_failure_32bit,
                       check_auditd,
                       reset_auditd_rate_limit):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    hwsku = duthost.facts["hwsku"]
    if "Nokia-7215" not in hwsku and "Nokia-7215-M0" not in hwsku:
        pytest.skip("This test is only for Nokia-7215 and Nokia-7215-M0")

    output = duthost.command(AUDITD_WATCHDOG_CMD.format(NSENTER_CMD, CURL_HTTP_CODE_CMD),
                             module_ignore_errors=True)["stdout"]
    pytest_assert(output == "500", "Auditd watchdog reports auditd container is healthy")

    output = duthost.command(AUDITD_WATCHDOG_CMD.format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
    pytest_assert('"auditd_active":"FAIL ' in output, "Auditd watchdog reports auditd container is healthy")


def debug_log(duthost):
    content = duthost.command(r"sudo cat /etc/audit/rules.d/audit.rules", module_ignore_errors=True)["stdout"]
    logger.warning("Content of /etc/audit/rules.d/audit.rules: {}".format(content))

    running_config = duthost.command(r"sudo auditctl -s", module_ignore_errors=True)["stdout"]
    logger.warning("Auditd running config: {}".format(running_config))


def read_watchdog(duthost):
    output = duthost.command(AUDITD_WATCHDOG_CMD.format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        pytest.fail("Invalid JSON response from auditd watchdog: {} exception: {}".format(output, e))


def test_rate_limit(duthosts,
                    enum_rand_one_per_hwsku_hostname,
                    verify_auditd_containers_running):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

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

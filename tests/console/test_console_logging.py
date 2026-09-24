"""
Test cases for the console logging feature on a BMC DUT.

The feature adds persistent logging of a console line's output to a file on the
BMC, with logrotate integration.

On a BMC, line 0 is wired to the host CPU (remote_device 'SwitchCpu'), so the
log under test holds the host CPU's serial console output.
"""
import logging
import time

import pexpect
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.console_helper import (
    create_ssh_client,
    disconnect_console_client,
    ensure_console_session_up,
    generate_random_string,
    get_host_ip_and_creds,
    wait_for_line_idle,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
    # Logging changes restart the console proxy and generate expected service logs.
    # Disable LogAnalyzer to prevent false test failures.
    pytest.mark.disable_loganalyzer,
]


CONSOLE_MONITOR_SCRIPT = "/usr/local/bin/console-monitor"
LOGROTATE_DIR = "/etc/logrotate.d"
# console-monitor writes /etc/logrotate.d/console-monitor-logging-<line>
LOGROTATE_CONF_FMT = "{}/console-monitor-logging-{}"

# Defaults that 'config console logging <line> enable' is expected to fill in.
DEFAULT_LOG_FILE_FMT = "/var/log/console-{}.log"
DEFAULT_LOGROTATE_SIZE = "10M"
DEFAULT_LOGROTATE_COUNT = "10"

LOGGING_FIELDS = ("logging_enabled", "log_file", "logrotate_size", "logrotate_count")

SETTLE_SEC = 20         # Allow console-monitor to process CONFIG_DB changes and restart the proxy
MARKER_DRAIN_SEC = 3    # Allow echoed marker bytes to reach the log file

# Small logrotate threshold for tests that exercise rotation without huge fills.
LOGROTATE_SIZE_TEST = "1k"
LOGROTATE_COUNT_TEST = "3"
# logrotate treats 'k' as 1024; exceed that threshold without a multi-kB pad.
BYTES_UNDER_SIZE_THRESHOLD = 900
BYTES_OVER_SIZE_THRESHOLD = 1100
LOGROTATE_STATUS_FILE = "/var/lib/logrotate/status"
SYSLOG_FILE = "/var/log/syslog"


def get_db_console_port_field(duthost, line, field):
    """
    Read one CONSOLE_PORT field; returns '' when the field is absent.
    """
    res = duthost.shell(
        "sonic-db-cli CONFIG_DB HGET 'CONSOLE_PORT|{}' {}".format(line, field),
        module_ignore_errors=True)
    return res['stdout'].strip() if res['rc'] == 0 else ''


def run_logging_cli(duthost, args, expect_success=True):
    """
    Run 'config console logging <args>' and assert on the exit status.
    """
    cmd = "sudo config console logging {}".format(args)
    res = duthost.shell(cmd, module_ignore_errors=True)
    if expect_success:
        pytest_assert(res['rc'] == 0,
                      "'{}' failed unexpectedly: rc={} stderr={}".format(cmd, res['rc'], res['stderr']))
    else:
        pytest_assert(res['rc'] != 0,
                      "'{}' was accepted but should have been rejected".format(cmd))
    return res


def file_path_exists(duthost, path):
    return duthost.shell("sudo test -e {}".format(path), module_ignore_errors=True)['rc'] == 0


def wait_for_file_path(duthost, path, present=True, timeout=SETTLE_SEC):
    """
    Wait for a path to appear or disappear. Returns True on success.
    """
    return wait_until(timeout, 2, 0, lambda: file_path_exists(duthost, path) == present)


def read_file(duthost, path):
    return duthost.shell("sudo cat {}".format(path), module_ignore_errors=True)['stdout']


def get_inode(duthost, path):
    res = duthost.shell("sudo stat -c %i {}".format(path), module_ignore_errors=True)
    pytest_assert(res['rc'] == 0, "Cannot stat {}: {}".format(path, res['stderr']))
    return res['stdout'].strip()


def check_msg_in_log(duthost, log_path, marker):
    res = duthost.shell("sudo grep -c -F -- '{}' {}".format(marker, log_path),
                        module_ignore_errors=True)
    if res['rc'] != 0:
        return False
    return int(res['stdout'].strip() or 0) > 0


def truncate_log_file(duthost, path):
    """
    Empty the log without deleting it so old content cannot match a new marker.
    """
    duthost.shell("sudo truncate -s 0 {}".format(path), module_ignore_errors=True)


def register_rotated_log_cleanup(cleanup_paths, log_file, max_suffix=5):
    """
    Register possible rotated log filenames for removal during fixture teardown.
    """
    for suffix in range(1, max_suffix + 1):
        cleanup_paths.append("{}.{}".format(log_file, suffix))
        cleanup_paths.append("{}.{}.gz".format(log_file, suffix))


def remove_rotated_log_artifacts(duthost, log_file):
    duthost.shell("sudo rm -f {}.[0-9]*".format(log_file), module_ignore_errors=True)


def clear_logrotate_status_for_log(duthost, log_file):
    """
    Drop status entries for 'log_file' so the next run can rotate on size.
    """
    duthost.shell(
        r"sudo sed -i '\|{}|d' {}".format(log_file, LOGROTATE_STATUS_FILE),
        module_ignore_errors=True)


def append_bytes_to_log(duthost, log_file, num_bytes):
    """
    Append test data to the end of the log while the proxy remains active.
    """
    duthost.shell(
        "sudo bash -c \"head -c {} /dev/zero | tr '\\0' 'A' >> '{}'\"".format(
            num_bytes, log_file),
        module_ignore_errors=True)


def run_logrotate(duthost, logrotate_conf, force=False):
    """
    Run logrotate for the generated configuration, optionally forcing rotation.
    """
    cmd = "sudo /usr/sbin/logrotate "
    if force:
        cmd += "-f "
    cmd += logrotate_conf
    return duthost.shell(cmd, module_ignore_errors=True)


def count_rotated_backups(duthost, log_file):
    """
    Return paths matching log.N or log.N.gz (numbered backups only).
    """
    res = duthost.shell(
        "sudo sh -c \"ls -1 {}.[0-9]* 2>/dev/null || true\"".format(log_file),
        module_ignore_errors=True)
    return [line for line in res['stdout'].splitlines() if line.strip()]


def is_proxy_service_active(duthost, line):
    """
    Return whether the console proxy service for the specified line is active.
    """
    res = duthost.shell(
        "sudo systemctl show console-monitor-proxy@{}.service -p ActiveState --value".format(line),
        module_ignore_errors=True)
    return res['rc'] == 0 and res['stdout'].strip() == 'active'


def wait_for_proxy_active(duthost, line, timeout=SETTLE_SEC):
    """
    Wait for console-monitor-proxy@<line> after enable/disable restarts it.
    """
    pytest_assert(
        wait_until(timeout, 2, 0, lambda: is_proxy_service_active(duthost, line)),
        "console-monitor-proxy@{}.service did not become active within {}s".format(line, timeout))


def emit_console_marker(duthost, creds, line):
    """
    Send a unique marker through the console session and return it.

    Only the device->user(session) direction is logged, so the marker is not written into
    the line (host CPU); it is typed into a session and reaches the log via the far end's
    terminal echo. Ctrl-U then discards the typed line so nothing is ever
    submitted as a command to the host CPU.
    """
    marker = "cslog_{}".format(generate_random_string(10))
    ip, user, password = get_host_ip_and_creds(duthost, creds)
    client = None
    try:
        client = create_ssh_client(ip, "{}:{}".format(user, line), password)
        ensure_console_session_up(client, line)
        # SwitchCpu getty often needs CRs before a login prompt appears.
        for _ in range(3):
            client.send('\r')
            time.sleep(0.5)
        index = client.expect([r'[Ll]ogin:', pexpect.TIMEOUT], timeout=10)
        if index == 1:
            pytest.fail(
                "Precondition failure, not a logging defect: no login prompt on console "
                "line {} after waking the far end".format(line))
        client.send(marker)
        # Drain first so echoed marker bytes reach the log before Ctrl-U erase chars.
        time.sleep(MARKER_DRAIN_SEC)
        client.sendcontrol('u')
        # Wait for the host to process Ctrl+U before closing the console connection.
        time.sleep(0.5)
    except Exception as e:
        pytest.fail(
            "Precondition failure, not a logging defect: could not drive console line {} "
            "to emit a marker: {}".format(line, e))
    finally:
        disconnect_console_client(client)
        duthost.shell("sudo consutil clear {}".format(line), module_ignore_errors=True)

    # Wait until the console line is fully released after disconnecting.
    wait_for_line_idle(duthost, line)
    logger.info("Emitted console marker %s on line %s", marker, line)
    return marker


@pytest.fixture(scope="module", autouse=True)
def skip_if_console_logging_unsupported(duthost):
    """
    Skip the module unless both the CLI group and the console-monitor are supported in this image.
    """
    cli = duthost.shell("sudo config console logging --help", module_ignore_errors=True)
    pytest_require(cli['rc'] == 0,
                   "'config console logging' not present in the image")

    daemon = duthost.shell("sudo grep -q logging_enabled {}".format(CONSOLE_MONITOR_SCRIPT),
                           module_ignore_errors=True)
    pytest_require(daemon['rc'] == 0,
                   "console-monitor has no logging support in the image")


@pytest.fixture(scope="module")
def target_line(duthost, console_facts):
    """
    The console line under test: the one wired to the host CPU if identifiable.
    """
    lines = console_facts.get('lines', {})
    pytest_require(len(lines) > 0, "No console lines are configured on the DUT")

    ordered = sorted(lines.keys(), key=int)
    for line_id in ordered:
        if get_db_console_port_field(duthost, line_id, 'remote_device') == 'SwitchCpu':
            logger.info("Using line %s (remote_device SwitchCpu)", line_id)
            return line_id

    logger.info("No SwitchCpu line found; falling back to lowest configured line %s", ordered[0])
    return ordered[0]


@pytest.fixture(scope="function", autouse=True)
def require_proxy_running(duthost, target_line):
    """
    Verify whether the console monitor proxy service is active and running.
    """
    pytest_require(is_proxy_service_active(duthost, target_line),
                   "console-monitor-proxy@{}.service is not active".format(target_line))
    yield


@pytest.fixture(scope="function")
def preserve_logging_config(duthost, target_line):
    """
    Snapshot the line's logging config and restore it afterward during teardown.

    Yields a list of cleanup paths; append any log file path the test creates; it will be removed
    during teardown.
    """
    saved = {field: get_db_console_port_field(duthost, target_line, field) for field in LOGGING_FIELDS}
    logrotate_conf = LOGROTATE_CONF_FMT.format(LOGROTATE_DIR, target_line)
    logrotate_conf_existed = file_path_exists(duthost, logrotate_conf)
    logger.info("Saved logging config for line %s: %s", target_line, saved)

    cleanup_paths = []
    yield cleanup_paths

    for field, value in saved.items():
        if value:
            duthost.shell(
                "sudo sonic-db-cli CONFIG_DB HSET 'CONSOLE_PORT|{}' {} '{}'".format(
                    target_line, field, value),
                module_ignore_errors=True)
        else:
            duthost.shell(
                "sudo sonic-db-cli CONFIG_DB HDEL 'CONSOLE_PORT|{}' {}".format(target_line, field),
                module_ignore_errors=True)

    if not logrotate_conf_existed:
        duthost.shell("sudo rm -f {}".format(logrotate_conf), module_ignore_errors=True)

    for path in cleanup_paths:
        duthost.shell("sudo rm -f {}".format(path), module_ignore_errors=True)

    logger.info("Restored logging config for line %s", target_line)


def test_logging_enable_applies_defaults(duthost, target_line, preserve_logging_config):
    """
    'enable' fills in the defaults and generates a logrotate config.

    Verifies the CLI writes all four CONFIG_DB fields, that the daemon creates
    the log file, and that the generated logrotate configuration uses
    copytruncate so the proxy can continue writing after rotation.
    """
    expected_log = DEFAULT_LOG_FILE_FMT.format(target_line)
    logrotate_conf = LOGROTATE_CONF_FMT.format(LOGROTATE_DIR, target_line)

    run_logging_cli(duthost, "{} disable".format(target_line))
    run_logging_cli(duthost, "{} enable".format(target_line))

    expected_fields = {
        'logging_enabled': 'yes',
        'log_file': expected_log,
        'logrotate_size': DEFAULT_LOGROTATE_SIZE,
        'logrotate_count': DEFAULT_LOGROTATE_COUNT,
    }
    for field, expected in expected_fields.items():
        actual = get_db_console_port_field(duthost, target_line, field)
        pytest_assert(actual == expected,
                      "CONSOLE_PORT|{} {}: expected '{}', got '{}'".format(
                          target_line, field, expected, actual))

    pytest_assert(wait_for_file_path(duthost, expected_log),
                  "Log file {} was not created after enabling logging".format(expected_log))

    pytest_assert(wait_for_file_path(duthost, logrotate_conf),
                  "Logrotate config {} was not generated".format(logrotate_conf))

    conf = read_file(duthost, logrotate_conf)
    logger.info("Generated logrotate config:\n%s", conf)
    pytest_assert(expected_log in conf,
                  "Logrotate config does not reference {}: {}".format(expected_log, conf))
    pytest_assert('copytruncate' in conf,
                  "Logrotate config lacks 'copytruncate'; rotation would orphan the "
                  "proxy's open descriptor and silently stop logging: {}".format(conf))
    pytest_assert('size {}'.format(DEFAULT_LOGROTATE_SIZE) in conf,
                  "Logrotate config lacks 'size {}': {}".format(DEFAULT_LOGROTATE_SIZE, conf))
    pytest_assert('rotate {}'.format(DEFAULT_LOGROTATE_COUNT) in conf,
                  "Logrotate config lacks 'rotate {}': {}".format(DEFAULT_LOGROTATE_COUNT, conf))


def test_logging_captures_console_output(duthost, creds, target_line, preserve_logging_config):
    """
    Console output reaches the log file once logging is enabled.
    """
    log_file = DEFAULT_LOG_FILE_FMT.format(target_line)

    run_logging_cli(duthost, "{} enable".format(target_line))
    pytest_assert(wait_for_file_path(duthost, log_file),
                  "Log file {} was not created after enabling logging".format(log_file))
    wait_for_proxy_active(duthost, target_line)
    truncate_log_file(duthost, log_file)

    marker = emit_console_marker(duthost, creds, target_line)

    pytest_assert(
        wait_until(SETTLE_SEC, 2, 0, lambda: check_msg_in_log(duthost, log_file, marker)),
        "Marker '{}' never appeared in {} although logging is enabled".format(marker, log_file))


def test_logging_disable_stops_capture(duthost, creds, target_line, preserve_logging_config):
    """
    'disable' stops writing to the log and removes the logrotate config.

    Verifies that logging works before disabling it, then confirms that no new
    console output is captured after logging is disabled.
    """
    log_file = DEFAULT_LOG_FILE_FMT.format(target_line)
    logrotate_conf = LOGROTATE_CONF_FMT.format(LOGROTATE_DIR, target_line)

    run_logging_cli(duthost, "{} enable".format(target_line))
    pytest_assert(wait_for_file_path(duthost, log_file),
                  "Log file {} was not created after enabling logging".format(log_file))
    wait_for_proxy_active(duthost, target_line)
    truncate_log_file(duthost, log_file)

    marker_enabled = emit_console_marker(duthost, creds, target_line)
    pytest_assert(
        wait_until(SETTLE_SEC, 2, 0, lambda: check_msg_in_log(duthost, log_file, marker_enabled)),
        "Marker '{}' was not captured before disabling logging".format(marker_enabled))

    run_logging_cli(duthost, "{} disable".format(target_line))

    enabled = get_db_console_port_field(duthost, target_line, 'logging_enabled')
    pytest_assert(enabled in ('no', ''),
                  "logging_enabled should be 'no' or absent after disable, got '{}'".format(enabled))

    pytest_assert(wait_for_file_path(duthost, logrotate_conf, present=False),
                  "Logrotate config {} still present after disabling logging".format(logrotate_conf))

    truncate_log_file(duthost, log_file)
    marker_disabled = emit_console_marker(duthost, creds, target_line)

    time.sleep(MARKER_DRAIN_SEC)
    pytest_assert(not check_msg_in_log(duthost, log_file, marker_disabled),
                  "Marker '{}' was written to {} even though logging is disabled".format(
                      marker_disabled, log_file))


def test_logging_filename_and_logrotate_options(duthost, creds, target_line, preserve_logging_config):
    """
    A custom log path and rotation options are honoured end to end.
    """
    custom_log = "/var/log/console-mgmt-{}.log".format(generate_random_string(6))
    preserve_logging_config.append(custom_log)
    logrotate_conf = LOGROTATE_CONF_FMT.format(LOGROTATE_DIR, target_line)

    run_logging_cli(duthost, "{} enable".format(target_line))
    run_logging_cli(duthost, "{} filename {} --logrotate-size 1M --logrotate-count 3".format(
        target_line, custom_log))

    expected_fields = {
        'log_file': custom_log,
        'logrotate_size': '1M',
        'logrotate_count': '3',
    }

    for field, expected in expected_fields.items():
        actual = get_db_console_port_field(duthost, target_line, field)
        pytest_assert(actual == expected,
                      "CONSOLE_PORT|{} {}: expected '{}', got '{}'".format(
                          target_line, field, expected, actual))

    pytest_assert(wait_for_file_path(duthost, custom_log),
                  "Custom log file {} was not created".format(custom_log))
    wait_for_proxy_active(duthost, target_line)

    def _conf_updated():
        conf = read_file(duthost, logrotate_conf)
        return custom_log in conf and 'size 1M' in conf and 'rotate 3' in conf

    pytest_assert(wait_until(SETTLE_SEC, 2, 0, _conf_updated),
                  "Logrotate config was not regenerated for the custom path. Current:\n{}".format(
                      read_file(duthost, logrotate_conf)))

    marker = emit_console_marker(duthost, creds, target_line)
    pytest_assert(
        wait_until(SETTLE_SEC, 2, 0, lambda: check_msg_in_log(duthost, custom_log, marker)),
        "Marker '{}' never appeared in the custom log {}".format(marker, custom_log))


@pytest.mark.parametrize("bad_option", [
    "--logrotate-size 10X",
    "--logrotate-size M",
    "--logrotate-count 0",
    "--logrotate-count 101",
])
def test_logging_rejects_invalid_logrotate_options(
    duthost, target_line, preserve_logging_config, bad_option
):
    """
    Invalid rotation options are rejected and leave CONFIG_DB untouched.

    Verify that invalid commands return an error and do not change any logging
    settings in CONFIG_DB.
    """
    run_logging_cli(duthost, "{} enable".format(target_line))
    before = {field: get_db_console_port_field(duthost, target_line, field) for field in LOGGING_FIELDS}

    run_logging_cli(duthost, "{} filename /var/log/console-invalid.log {}".format(
        target_line, bad_option), expect_success=False)

    after = {field: get_db_console_port_field(duthost, target_line, field) for field in LOGGING_FIELDS}
    pytest_assert(before == after,
                  "Rejected command '{}' still modified CONFIG_DB: before={} after={}".format(
                      bad_option, before, after))


@pytest.mark.parametrize("bad_path_type", [
    "relative_path",
    "white_space",
    "curly_braces",
])
def test_logging_rejects_invalid_filename(
    duthost, target_line, preserve_logging_config, bad_path_type
):
    """
    Invalid log file paths are rejected and leave CONFIG_DB untouched.

    Verify that the log file must be an absolute path and must not contain
    white space or curly braces.
    """
    suffix = generate_random_string(6)
    bad_paths = {
        "relative_path": "console-relative-{}.log".format(suffix),
        "white_space": "/var/log/console bad-{}.log".format(suffix),
        "curly_braces": "/var/log/console-{{{}}}.log".format(suffix),
    }
    bad_path = bad_paths[bad_path_type]

    run_logging_cli(duthost, "{} enable".format(target_line))
    before = {field: get_db_console_port_field(duthost, target_line, field) for field in LOGGING_FIELDS}

    # Quote the path so the CLI receives it as a single argument
    run_logging_cli(duthost, "{} filename '{}'".format(target_line, bad_path), expect_success=False)

    after = {field: get_db_console_port_field(duthost, target_line, field) for field in LOGGING_FIELDS}
    pytest_assert(before == after,
                  "Rejected filename '{}' still modified CONFIG_DB: before={} after={}".format(
                      bad_path, before, after))


def test_logging_rejects_symlink_filename(duthost, creds, target_line, preserve_logging_config):
    """
    The daemon refuses to write the console log through a symlink.

    The CLI accepts a symlink path, but console-monitor must fail to open it,
    and console output must not be written to the symlink target.
    """
    suffix = generate_random_string(6)
    link_path = "/var/log/console-link-{}.log".format(suffix)
    link_target = "/var/log/console-link-target-{}.log".format(suffix)
    preserve_logging_config.extend([link_path, link_target])
    duthost.shell("sudo touch {} && sudo ln -s {} {}".format(link_target, link_target, link_path))

    run_logging_cli(duthost, "{} enable".format(target_line))
    run_logging_cli(duthost, "{} filename {}".format(target_line, link_path))
    wait_for_proxy_active(duthost, target_line)

    open_error = "Failed to open log file {}".format(link_path)
    pytest_assert(
        wait_until(SETTLE_SEC, 2, 0, lambda: check_msg_in_log(duthost, SYSLOG_FILE, open_error)),
        "console-monitor did not report '{}' in {}".format(open_error, SYSLOG_FILE))

    emit_console_marker(duthost, creds, target_line)
    time.sleep(MARKER_DRAIN_SEC)

    target_content = read_file(duthost, link_target)
    pytest_assert(target_content == '',
                  "Console output was written through symlink {} to {}: {}".format(
                      link_path, link_target, target_content))


def test_logging_rotates_when_size_exceeded(duthost, creds, target_line, preserve_logging_config):
    """
    Verify that the log rotates only after exceeding the configured size.
    no rotation below threshold, rotation at/above threshold.

    The proxy keeps the active log file open for writing, so copytruncate allows
    rotation without changing the file being used by the proxy.
    """
    log_file = DEFAULT_LOG_FILE_FMT.format(target_line)
    logrotate_conf = LOGROTATE_CONF_FMT.format(LOGROTATE_DIR, target_line)

    run_logging_cli(duthost, "{} enable".format(target_line))
    run_logging_cli(duthost, "{} filename {} --logrotate-size {} --logrotate-count {}".format(
        target_line, log_file, LOGROTATE_SIZE_TEST, LOGROTATE_COUNT_TEST))
    pytest_assert(wait_for_file_path(duthost, log_file),
                  "Log file {} was not created after enabling logging".format(log_file))
    pytest_assert(wait_for_file_path(duthost, logrotate_conf),
                  "Logrotate config {} was not generated".format(logrotate_conf))
    wait_for_proxy_active(duthost, target_line)

    register_rotated_log_cleanup(preserve_logging_config, log_file)
    remove_rotated_log_artifacts(duthost, log_file)
    clear_logrotate_status_for_log(duthost, log_file)
    truncate_log_file(duthost, log_file)

    append_bytes_to_log(duthost, log_file, BYTES_UNDER_SIZE_THRESHOLD)
    res = run_logrotate(duthost, logrotate_conf, force=False)
    pytest_assert(res['rc'] == 0,
                  "logrotate failed while log was below size threshold: rc={} stderr={}".format(
                      res['rc'], res['stderr']))
    pytest_assert(not file_path_exists(duthost, "{}.1".format(log_file)),
                  "Logrotate created {}.1 even though the log was only {} bytes "
                  "(below {} size threshold)".format(
                      log_file, BYTES_UNDER_SIZE_THRESHOLD, LOGROTATE_SIZE_TEST))
    pytest_assert(not file_path_exists(duthost, "{}.1.gz".format(log_file)),
                  "Logrotate created {}.1.gz even though the log was below size threshold".format(
                      log_file))

    clear_logrotate_status_for_log(duthost, log_file)
    truncate_log_file(duthost, log_file)

    append_bytes_to_log(duthost, log_file, BYTES_OVER_SIZE_THRESHOLD)
    inode_before = get_inode(duthost, log_file)

    res = run_logrotate(duthost, logrotate_conf, force=False)
    pytest_assert(res['rc'] == 0,
                  "logrotate failed on the generated config: rc={} stderr={}".format(
                      res['rc'], res['stderr']))

    rotated = duthost.shell("sudo ls {}.1*".format(log_file), module_ignore_errors=True)
    pytest_assert(rotated['rc'] == 0 and rotated['stdout'].strip(),
                  "No rotated artifact matching {}.1* after size threshold was exceeded".format(
                      log_file))
    logger.info("Rotated artifacts: %s", rotated['stdout'].strip())

    inode_after = get_inode(duthost, log_file)
    pytest_assert(inode_before == inode_after,
                  "Live log {} changed inode across rotation ({} -> {}); the config is not "
                  "using copytruncate and the proxy is now writing to an unlinked file".format(
                      log_file, inode_before, inode_after))

    truncate_log_file(duthost, log_file)
    marker = emit_console_marker(duthost, creds, target_line)
    pytest_assert(
        wait_until(SETTLE_SEC, 2, 0, lambda: check_msg_in_log(duthost, log_file, marker)),
        "Logging stopped after rotation: marker '{}' never reached {}".format(marker, log_file))


def test_logging_rotate_count_retention(duthost, target_line, preserve_logging_config):
    """
    Verify that only the configured number of rotated backup files is retained.
    """
    log_file = DEFAULT_LOG_FILE_FMT.format(target_line)
    logrotate_conf = LOGROTATE_CONF_FMT.format(LOGROTATE_DIR, target_line)
    rotate_count = int(LOGROTATE_COUNT_TEST)

    run_logging_cli(duthost, "{} enable".format(target_line))
    run_logging_cli(duthost, "{} filename {} --logrotate-size {} --logrotate-count {}".format(
        target_line, log_file, LOGROTATE_SIZE_TEST, LOGROTATE_COUNT_TEST))
    pytest_assert(wait_for_file_path(duthost, log_file),
                  "Log file {} was not created after enabling logging".format(log_file))
    pytest_assert(wait_for_file_path(duthost, logrotate_conf),
                  "Logrotate config {} was not generated".format(logrotate_conf))
    wait_for_proxy_active(duthost, target_line)

    register_rotated_log_cleanup(preserve_logging_config, log_file)
    remove_rotated_log_artifacts(duthost, log_file)
    clear_logrotate_status_for_log(duthost, log_file)
    truncate_log_file(duthost, log_file)

    num_rotations = rotate_count + 2
    for _ in range(num_rotations):
        append_bytes_to_log(duthost, log_file, BYTES_OVER_SIZE_THRESHOLD)
        res = run_logrotate(duthost, logrotate_conf, force=True)
        pytest_assert(res['rc'] == 0,
                      "logrotate failed during retention exercise: rc={} stderr={}".format(
                          res['rc'], res['stderr']))

    backups = count_rotated_backups(duthost, log_file)
    logger.info("Rotated backups after %s cycles: %s", num_rotations, backups)
    pytest_assert(len(backups) <= rotate_count,
                  "Expected at most {} backup files, found {}: {}".format(
                      rotate_count, len(backups), backups))

    for suffix in range(rotate_count + 1, num_rotations + 1):
        pytest_assert(not file_path_exists(duthost, "{}.{}".format(log_file, suffix)),
                      "Backup {}.{} should not exist when rotate is {}".format(
                          log_file, suffix, rotate_count))
        pytest_assert(not file_path_exists(duthost, "{}.{}.gz".format(log_file, suffix)),
                      "Backup {}.{}.gz should not exist when rotate is {}".format(
                          log_file, suffix, rotate_count))

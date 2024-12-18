import logging
import time
import pytest
from tests.common.devices.ptf import PTFHost
from tests.common.helpers.tacacs.tacacs_helper import stop_tacacs_server, start_tacacs_server, \
    per_command_accounting_skip_versions, remove_all_tacacs_server
from .utils import check_server_received, change_and_wait_aaa_config_update, get_auditd_config_reload_timestamp, \
    ensure_tacacs_server_running_after_ut, ssh_connect_remote_retry, ssh_run_command    # noqa: F401
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


def cleanup_tacacs_log(ptfhost, rw_user_client):
    try:
        ptfhost.command('rm /var/log/tac_plus.acct')
    except RunAnsibleModuleFail:
        logger.info("/var/log/tac_plus.acct does not exist.")

    res = ptfhost.command('touch /var/log/tac_plus.acct')
    logger.info(res["stdout_lines"])

    ssh_run_command(rw_user_client, 'sudo truncate -s 0 /var/log/syslog')


def host_run_command(host, command):
    if isinstance(host, PTFHost):
        return host.command(command)
    else:
        return host.shell("sudo {0}".format(command))


def flush_log(host, log_file):
    if "syslog" in log_file:
        # force flush syslog by reopen log file and write cached data to disk:
        #   https://man7.org/linux/man-pages/man8/rsyslogd.8.html
        #   https://man7.org/linux/man-pages/man1/sync.1.html
        host_run_command(host, "kill -HUP $(cat /var/run/rsyslogd.pid)")
        host_run_command(host, "sync {0}".format(log_file))
    else:
        host_run_command(host, "sync {0}".format(log_file))


def wait_for_log(host, log_file, pattern, timeout=80, check_interval=1):
    wait_time = 0
    while wait_time <= timeout:
        flush_log(host, log_file)
        sed_command = "sed -nE '{0}' {1}".format(pattern, log_file)
        logger.debug(sed_command)  # lgtm [py/clear-text-logging-sensitive-data]
        res = host_run_command(host, sed_command)

        logger.debug(res["stdout_lines"])
        if len(res["stdout_lines"]) > 0:
            return res["stdout_lines"]

        time.sleep(check_interval)
        wait_time += check_interval

    return []


def check_tacacs_server_log_exist(ptfhost, tacacs_creds, command):
    username = tacacs_creds['tacacs_rw_user']
    """
        Find logs run by tacacs_rw_user from tac_plus.acct:
            Find logs match following format: "tacacs_rw_user ... cmd=command"
            Print matched logs with /P command.
    """
    log_pattern = "/	{0}	.*	cmd=.*{1}/P".format(username, command)
    logs = wait_for_log(ptfhost, "/var/log/tac_plus.acct", log_pattern)
    pytest_assert(len(logs) > 0)


def check_tacacs_server_no_other_user_log(ptfhost, tacacs_creds):
    username = tacacs_creds['tacacs_rw_user']
    """
        Find logs not run by tacacs_rw_user & admin from tac_plus.acct:
            Remove all tacacs_rw_user's and admin's log with /D command.
            Print logs not removed by /D command, which are not run by tacacs_rw_user and admin.
    """
    log_pattern = "/	{0}	/D;/	{1}	/D;/.*/P".format(username, "admin")
    logs = wait_for_log(ptfhost, "/var/log/tac_plus.acct", log_pattern)
    pytest_assert(len(logs) == 0, "Expected to find no accounting logs but found: {}".format(logs))


def check_local_log_exist(duthost, tacacs_creds, command):
    """
        Remove all ansible command log with /D command,
        which will match following format:
            "ansible.legacy.command Invoked"

        Find logs run by tacacs_rw_user from syslog:
            Find logs match following format:
                "INFO audisp-tacplus: Accounting: user: tacacs_rw_user,.*, command: .*command,"
            Print matched logs with /P command.
    """
    username = tacacs_creds['tacacs_rw_user']
    log_pattern = "/ansible.legacy.command Invoked/D;\
                  /INFO audisp-tacplus.+Accounting: user: {0},.*, command: .*{1},/P" \
                  .format(username, command)
    logs = wait_for_log(duthost, "/var/log/syslog", log_pattern)

    if len(logs) == 0:
        # Print recent logs for debug
        recent_logs = duthost.command("tail /var/log/syslog -n 1000")
        logger.debug("Found logs: %s", recent_logs)

        # Missing log may caused by incorrect NSS config
        tacacs_config = duthost.command("cat /etc/tacplus_nss.conf")
        logger.debug("tacplus_nss.conf: %s", tacacs_config)

    pytest_assert(len(logs) > 0)

    # exclude logs of the sed command produced by Ansible
    logs = list([line for line in logs if 'sudo sed' not in line])
    logger.info("Found logs: %s", logs)

    pytest_assert(logs, 'Failed to find an expected log message by pattern: ' + log_pattern)


def check_local_no_other_user_log(duthost, tacacs_creds):
    """
        Find logs not run by tacacs_rw_user from syslog:
            Remove all ansible command log with /D command,
            which will match following format:
                "ansible.legacy.command Invoked"

            Remove all tacacs_rw_user's log with /D command,
            which will match following format:
                "INFO audisp-tacplus: Accounting: user: tacacs_rw_user"

            Find all other user's log, which will match following format:
                "INFO audisp-tacplus: Accounting: user:"

            Print matched logs with /P command, which are not run by tacacs_rw_user.
    """
    username = tacacs_creds['tacacs_rw_user']
    log_pattern = "/ansible.legacy.command Invoked/D;\
                  /INFO audisp-tacplus: Accounting: user: {0},/D;\
                  /INFO audisp-tacplus: Accounting: user:/P" \
                  .format(username)
    logs = wait_for_log(duthost, "/var/log/syslog", log_pattern)

    logger.info("Found logs: %s", logs)
    pytest_assert(len(logs) == 0, "Expected to find no accounting logs but found: {}".format(logs))


@pytest.fixture
def rw_user_client(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    ssh_client = ssh_connect_remote_retry(
                    dutip,
                    tacacs_creds['tacacs_rw_user'],
                    tacacs_creds['tacacs_rw_user_passwd'],
                    duthost)
    yield ssh_client
    ssh_client.close()


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202112
    Args:
        duthost: Hostname of DUT.
    Returns:
        None.
    """
    skip_release(duthost, per_command_accounting_skip_versions)


def test_accounting_tacacs_only(
                            ptfhost,
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            tacacs_creds,
                            check_tacacs,
                            rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting tacacs+")
    cleanup_tacacs_log(ptfhost, rw_user_client)

    ssh_run_command(rw_user_client, "grep")

    # Verify TACACS+ server side have user command record.
    check_tacacs_server_log_exist(ptfhost, tacacs_creds, "grep")
    # Verify TACACS+ server side not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, tacacs_creds)


def test_accounting_tacacs_only_all_tacacs_server_down(
                                                    ptfhost,
                                                    duthosts,
                                                    enum_rand_one_per_hwsku_hostname,
                                                    tacacs_creds,
                                                    check_tacacs,
                                                    rw_user_client,
                                                    ensure_tacacs_server_running_after_ut):  # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting tacacs+")
    cleanup_tacacs_log(ptfhost, rw_user_client)

    """
        when user login server are accessible.
        user run some command in whitelist and server are accessible.
    """
    ssh_run_command(rw_user_client, "grep")

    # Verify TACACS+ server side have user command record.
    check_tacacs_server_log_exist(ptfhost, tacacs_creds, "grep")
    # Verify TACACS+ server side not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, tacacs_creds)

    cleanup_tacacs_log(ptfhost, rw_user_client)

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)

    """
        then all server not accessible, and run some command
        Verify local user still can run command without any issue.
    """
    ssh_run_command(rw_user_client, "grep")

    #  Cleanup UT.
    start_tacacs_server(ptfhost)


def test_accounting_tacacs_only_some_tacacs_server_down(
                                                    ptfhost,
                                                    duthosts,
                                                    enum_rand_one_per_hwsku_hostname,
                                                    tacacs_creds,
                                                    check_tacacs,
                                                    rw_user_client):
    """
        Setup multiple tacacs server for this UT.
        Tacacs server 127.0.0.1 not accessible.
    """
    invalid_tacacs_server_ip = "127.0.0.1"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tacacs_server_ip = ptfhost.mgmt_ip

    # when tacacs config change multiple time in short time
    # auditd service may been request reload during reloading
    # when this happen, auditd will ignore request and only reload once
    last_timestamp = get_auditd_config_reload_timestamp(duthost)

    duthost.shell("sudo config tacacs timeout 1")
    remove_all_tacacs_server(duthost)
    duthost.shell("sudo config tacacs add %s --port 59" % invalid_tacacs_server_ip)
    duthost.shell("sudo config tacacs add %s --port 59" % tacacs_server_ip)
    change_and_wait_aaa_config_update(duthost,
                                      "sudo config aaa accounting tacacs+",
                                      last_timestamp)

    cleanup_tacacs_log(ptfhost, rw_user_client)

    ssh_run_command(rw_user_client, "grep")

    # Verify TACACS+ server side have user command record.
    check_tacacs_server_log_exist(ptfhost, tacacs_creds, "grep")
    # Verify TACACS+ server side not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, tacacs_creds)

    # Cleanup
    duthost.shell("sudo config tacacs delete %s" % invalid_tacacs_server_ip)


def test_accounting_local_only(
                            ptfhost,
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            tacacs_creds,
                            check_tacacs,
                            rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting local")
    cleanup_tacacs_log(ptfhost, rw_user_client)

    ssh_run_command(rw_user_client, "grep")

    # Verify syslog have user command record.
    check_local_log_exist(duthost, tacacs_creds, "grep")

    # Verify syslog not have any command record which not run by user.
    check_local_no_other_user_log(duthost, tacacs_creds)


def test_accounting_tacacs_and_local(
                                    ptfhost,
                                    duthosts,
                                    enum_rand_one_per_hwsku_hostname,
                                    tacacs_creds,
                                    check_tacacs,
                                    rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(duthost, 'sudo config aaa accounting "tacacs+ local"')
    cleanup_tacacs_log(ptfhost, rw_user_client)

    ssh_run_command(rw_user_client, "grep")

    # Verify TACACS+ server and syslog have user command record.
    check_tacacs_server_log_exist(ptfhost, tacacs_creds, "grep")
    check_local_log_exist(duthost, tacacs_creds, "grep")
    # Verify TACACS+ server and syslog not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, tacacs_creds)
    check_local_no_other_user_log(duthost, tacacs_creds)


def test_accounting_tacacs_and_local_all_tacacs_server_down(
                                                        ptfhost,
                                                        duthosts,
                                                        enum_rand_one_per_hwsku_hostname,
                                                        tacacs_creds,
                                                        check_tacacs,
                                                        rw_user_client,
                                                        ensure_tacacs_server_running_after_ut):  # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(duthost, 'sudo config aaa accounting "tacacs+ local"')
    cleanup_tacacs_log(ptfhost, rw_user_client)

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)

    """
        After all server not accessible, run some command
        Verify local user still can run command without any issue.
    """
    ssh_run_command(rw_user_client, "grep")

    # Verify syslog have user command record.
    check_local_log_exist(duthost, tacacs_creds, "grep")
    # Verify syslog not have any command record which not run by user.
    check_local_no_other_user_log(duthost, tacacs_creds)

    #  Cleanup UT.
    start_tacacs_server(ptfhost)


def test_send_remote_address(
                            ptfhost,
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            tacacs_creds,
                            check_tacacs,
                            rw_user_client):
    """
        Verify TACACS+ send remote address to server.
    """
    exit_code, stdout_stream, stderr_stream = ssh_run_command(rw_user_client, "echo $SSH_CONNECTION")
    pytest_assert(exit_code == 0)

    # Remote address is first part of SSH_CONNECTION: '10.250.0.1 47462 10.250.0.101 22'
    stdout = stdout_stream.readlines()
    remote_address = stdout[0].split(" ")[0]
    check_server_received(ptfhost, remote_address)

import logging
import time
from tests.common.devices.ptf import PTFHost


import pytest


from .test_authorization import ssh_connect_remote, ssh_run_command, \
        per_command_check_skip_versions, remove_all_tacacs_server
from .utils import stop_tacacs_server, start_tacacs_server, check_server_received
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
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


def wait_for_log(host, log_file, pattern, timeout=20, check_interval=1):
    wait_time = 0
    while wait_time <= timeout:
        sed_command = "sed -nE '{0}' {1}".format(pattern, log_file)
        logger.info(sed_command)  # lgtm [py/clear-text-logging-sensitive-data]
        if isinstance(host, PTFHost):
            res = host.command(sed_command)
        else:
            res = host.shell(sed_command)

        logger.info(res["stdout_lines"])
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
        Find logs not run by tacacs_rw_user from tac_plus.acct:
            Remove all tacacs_rw_user's log with /D command.
            Print logs not removed by /D command, which are not run by tacacs_rw_user.
    """
    log_pattern = "/	{0}	/D;/.*/P".format(username)
    logs = wait_for_log(ptfhost, "/var/log/tac_plus.acct", log_pattern)
    pytest_assert(len(logs) == 0, "Expected to find no accounting logs but found: {}".format(logs))


def check_local_log_exist(duthost, tacacs_creds, command):
    """
        Find logs run by tacacs_rw_user from syslog:
            Find logs match following format:
                "INFO audisp-tacplus: Accounting: user: tacacs_rw_user,.*, command: .*command,"
            Print matched logs with /P command.
    """
    username = tacacs_creds['tacacs_rw_user']
    log_pattern = "/INFO audisp-tacplus.+Accounting: user: {0},.*, command: .*{1},/P" \
                  .format(username, command)
    logs = wait_for_log(duthost, "/var/log/syslog", log_pattern)
    pytest_assert(len(logs) > 0)

    # exclude logs of the sed command produced by Ansible
    logs = list([line for line in logs if 'sudo sed' not in line])
    logger.info("Found logs: %s", logs)

    pytest_assert(logs, 'Failed to find an expected log message by pattern: ' + log_pattern)


def check_local_no_other_user_log(duthost, tacacs_creds):
    """
        Find logs not run by tacacs_rw_user from syslog:

            Remove all tacacs_rw_user's log with /D command,
            which will match following format:
                "INFO audisp-tacplus: Accounting: user: tacacs_rw_user"

            Find all other user's log, which will match following format:
                "INFO audisp-tacplus: Accounting: user:"

            Print matched logs with /P command, which are not run by tacacs_rw_user.
    """
    username = tacacs_creds['tacacs_rw_user']
    log_pattern = "/INFO audisp-tacplus: Accounting: user: {0},/D;/INFO audisp-tacplus: Accounting: user:/P" \
                  .format(username)
    logs = wait_for_log(duthost, "/var/log/syslog", log_pattern)

    logger.info("Found logs: %s", logs)
    pytest_assert(len(logs) == 0, "Expected to find no accounting logs but found: {}".format(logs))


@pytest.fixture
def rw_user_client(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    ssh_client = ssh_connect_remote(dutip,
                                    tacacs_creds['tacacs_rw_user'],
                                    tacacs_creds['tacacs_rw_user_passwd'])
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
    skip_release(duthost, per_command_check_skip_versions)


def test_accounting_tacacs_only(
                            ptfhost,
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            tacacs_creds,
                            check_tacacs,
                            rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa accounting tacacs+")
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
                                                    rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa accounting tacacs+")
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
    duthost.shell("sudo config tacacs timeout 1")
    remove_all_tacacs_server(duthost)
    duthost.shell("sudo config tacacs add %s" % invalid_tacacs_server_ip)
    duthost.shell("sudo config tacacs add %s" % tacacs_server_ip)
    duthost.shell("sudo config aaa accounting tacacs+")

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
    duthost.shell("sudo config aaa accounting local")
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
    duthost.shell('sudo config aaa accounting "tacacs+ local"')
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
                                                        rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell('sudo config aaa accounting "tacacs+ local"')
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
    exit_code, stdout, stderr = ssh_run_command(rw_user_client, "echo $SSH_CONNECTION")
    pytest_assert(exit_code == 0)

    # Remote address is first part of SSH_CONNECTION: '10.250.0.1 47462 10.250.0.101 22'
    remote_address = stdout[0].split(" ")[0]
    check_server_received(ptfhost, remote_address)

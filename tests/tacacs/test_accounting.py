import logging

import pytest

from .test_authorization import ssh_connect_remote, ssh_run_command, per_command_check_skip_versions, remove_all_tacacs_server
from .utils import stop_tacacs_server, start_tacacs_server
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

def check_tacacs_server_log_exist(ptfhost, tacacs_creds, command):
    username = tacacs_creds['tacacs_rw_user']
    """
        Find logs run by tacacs_rw_user from tac_plus.acct:
            Find logs match following format: "tacacs_rw_user ... cmd=command"
            Print matched logs with /P command.
    """
    sed_command = "sed -nE '/	{0}	.*	cmd=.*{1}/P' /var/log/tac_plus.acct".format(username, command)
    res = ptfhost.command(sed_command)
    logger.info(sed_command)  # lgtm [py/clear-text-logging-sensitive-data]
    logger.info(res["stdout_lines"])
    pytest_assert(len(res["stdout_lines"]) > 0)

def check_tacacs_server_no_other_user_log(ptfhost, tacacs_creds):
    username = tacacs_creds['tacacs_rw_user']
    """
        Find logs not run by tacacs_rw_user from tac_plus.acct:
            Remove all tacacs_rw_user's log with /D command.
            Print logs not removed by /D command, which are not run by tacacs_rw_user.
    """
    sed_command = "sed -nE '/	{0}	/D;/.*/P' /var/log/tac_plus.acct".format(username)
    res = ptfhost.command(sed_command)
    logger.info(sed_command)  # lgtm [py/clear-text-logging-sensitive-data]
    logger.info(res["stdout_lines"])
    pytest_assert(len(res["stdout_lines"]) == 0)

def check_local_log_exist(duthost, tacacs_creds, command):
    """
        Find logs run by tacacs_rw_user from syslog:
            Find logs match following format: "INFO audisp-tacplus: Accounting: user: tacacs_rw_user,.*, command: .*command,"
            Print matched logs with /P command.
    """

    username = tacacs_creds['tacacs_rw_user']
    expected_log_pattern = "INFO audisp-tacplus.+Accounting: user: {0},.*, command: .*{1},".format(username, command)
    sed_command = "sudo sed -nE '/{}/P' /var/log/syslog".format(expected_log_pattern)
    output = duthost.shell(sed_command)
    exit_code, stdout_lines = output['rc'], output['stdout_lines']

    # exclude logs of the sed command produced by Ansible
    stdout_lines = list(filter(lambda line: 'sudo sed' not in line, stdout_lines))
    logger.info("Searched for accounting logs with the command: %s", sed_command)  # lgtm [py/clear-text-logging-sensitive-data]
    logger.info("Found logs: %s", stdout_lines)

    pytest_assert(exit_code == 0)
    pytest_assert(stdout_lines, 'Failed to find an expected log message by pattern: ' + expected_log_pattern)

def check_local_no_other_user_log(duthost, tacacs_creds):
    """
        Find logs not run by tacacs_rw_user from syslog:
            Remove all tacacs_rw_user's log with /D command, which will match following format: "INFO audisp-tacplus: Accounting: user: tacacs_rw_user"
            Find all other user's log, which will match following format: "INFO audisp-tacplus: Accounting: user:"
            Print matched logs with /P command, which are not run by tacacs_rw_user.
    """

    username = tacacs_creds['tacacs_rw_user']
    sed_command = "sudo sed -nE '/INFO audisp-tacplus: Accounting: user: {0},/D;/INFO audisp-tacplus: Accounting: user:/P' /var/log/syslog".format(username)
    output = duthost.shell(sed_command)
    exit_code, stdout = output['rc'], output['stdout']

    pytest_assert(exit_code == 0)
    logger.info("Searched for accounting logs with the command: %s", sed_command)  # lgtm [py/clear-text-logging-sensitive-data]
    logger.info("Found logs: %s", stdout)
    pytest_assert(len(stdout) == 0, "Expected to find no accounting logs but found" + stdout)

@pytest.fixture
def rw_user_client(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    ssh_client = ssh_connect_remote(dutip, tacacs_creds['tacacs_rw_user'],
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

def test_accounting_tacacs_only(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs, rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa accounting tacacs+")
    cleanup_tacacs_log(ptfhost, rw_user_client)

    ssh_run_command(rw_user_client, "grep")

    # Verify TACACS+ server side have user command record.
    check_tacacs_server_log_exist(ptfhost, tacacs_creds, "grep")
    # Verify TACACS+ server side not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, tacacs_creds)


def test_accounting_tacacs_only_all_tacacs_server_down(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs, rw_user_client):
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

def test_accounting_tacacs_only_some_tacacs_server_down(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs, rw_user_client):
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

def test_accounting_local_only(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs, rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa accounting local")
    cleanup_tacacs_log(ptfhost, rw_user_client)

    ssh_run_command(rw_user_client, "grep")

    # Verify syslog have user command record.
    check_local_log_exist(duthost, tacacs_creds, "grep")

    # Verify syslog not have any command record which not run by user.
    check_local_no_other_user_log(duthost, tacacs_creds)

def test_accounting_tacacs_and_local(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs, rw_user_client):
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

def test_accounting_tacacs_and_local_all_tacacs_server_down(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs, rw_user_client):
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

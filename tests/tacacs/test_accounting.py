import crypt
import paramiko
import pytest

from .test_authorization import ssh_connect_remote, ssh_run_command, check_ssh_output, remote_user_client
from .test_ro_user import ssh_remote_run
from tests.common.helpers.assertions import pytest_assert
from .utils import stop_tacacs_server, start_tacacs_server

logger = logging.getLogger(__name__)

def cleanup_tacacs_server_log(ptfhost):
    res = ptfhost.command('> /var/log/tac_plus.acct')
    logger.info(res["stdout_lines"])

def check_tacacs_server_log_exist(ptfhost, creds_all_duts, command):
    username = creds_all_duts[duthost]['tacacs_authorization_user']
    # check if tacacs accounting log contain user commands
    sed_command = "sudo sed -nE '/user: {0},.*command: \{1},/P' /var/log/tac_plus.acct".format(username, command)
    logger.info(res["stdout_lines"])

def check_tacacs_server_no_other_user_log(ptfhost, creds_all_duts):
    username = creds_all_duts[duthost]['tacacs_authorization_user']
    # check if tacacs accounting log contain user commands
    sed_command = "sudo sed -E '/user: {0},/D' /var/log/tac_plus.acct".format(username)
    logger.info(res["stdout_lines"])

def check_local_log_exist(remote_user_client, creds_all_duts, command):
    username = creds_all_duts[duthost]['tacacs_authorization_user']
    # check if tacacs accounting log contain user commands
    sed_command = "sudo sed -nE '/user: {0},.*command: \{1},/P' /var/log/syslog".format(username, command)
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, sed_command)
    pytest_assert(exit_code == 0)
    logger.info(stdout)

def check_local_no_other_user_log(remote_user_client, creds_all_duts):
    username = creds_all_duts[duthost]['tacacs_authorization_user']
    # check if tacacs accounting log contain user commands
    sed_command = "sudo sed -E '/user: {0},/D' /var/log/syslog".format(username)
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, sed_command)
    pytest_assert(exit_code == 0)
    logger.info(stdout)

def test_accounting_tacacs_only(localhost, ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs, remote_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa accounting tacacs+")
    cleanup_tacacs_server_log(ptfhost)

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Verify TACACS+ server side have user command record.
    check_tacacs_server_log_exist(ptfhost, creds_all_duts, "show")
    # Verify TACACS+ server side not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, creds_all_duts)


def test_accounting_tacacs_only_all_tacacs_server_down(localhost, ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs, remote_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa accounting tacacs+")
    cleanup_tacacs_server_log(ptfhost)

    """
        when user login server are accessible.
        user run some command in whitelist and server are accessible.
    """
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Verify TACACS+ server side have user command record.
    check_tacacs_server_log_exist(ptfhost, creds_all_duts, "show")
    # Verify TACACS+ server side not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, creds_all_duts)

    cleanup_tacacs_server_log(ptfhost)

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)
    
    """
        then all server not accessible, and run some command
        Verify local user still can run command without any issue.
    """
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    #  Cleanup UT.
    start_tacacs_server(ptfhost)

def test_accounting_tacacs_only_some_tacacs_server_down(localhost, ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs, remote_user_client):
    """
        Setup multiple tacacs server for this UT.
        Tacacs server 127.0.0.1 not accessible.
    """
    invalid_tacacs_server_ip = "127.0.0.1"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tacacs_server_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    duthost.shell("sudo config tacacs timeout 1")
    for tacacs_server in config_facts.get('TACPLUS_SERVER', {}):
        duthost.shell("sudo config tacacs delete %s" % tacacs_server)
    duthost.shell("sudo config tacacs add %s" % invalid_tacacs_server_ip)
    duthost.shell("sudo config tacacs add %s" % tacacs_server_ip)
    duthost.shell("sudo config aaa accounting tacacs+")

    cleanup_tacacs_server_log(ptfhost)

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Verify TACACS+ server side have user command record.
    check_tacacs_server_log_exist(ptfhost, creds_all_duts, "show")
    # Verify TACACS+ server side not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, creds_all_duts)

    cleanup_tacacs_server_log(ptfhost)

    # Cleanup
    duthost.shell("sudo config tacacs delete %s" % invalid_tacacs_server_ip)

def test_accounting_tacacs_and_local(localhost, ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs, remote_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell('sudo config aaa accounting "tacacs+ local"')
    cleanup_tacacs_server_log(ptfhost)

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Verify TACACS+ server and syslog have user command record.
    check_tacacs_server_log_exist(ptfhost, creds_all_duts, "show")
    check_local_log_exist(remote_user_client, creds_all_duts, "show")
    # Verify TACACS+ server and syslog not have any command record which not run by user.
    check_tacacs_server_no_other_user_log(ptfhost, creds_all_duts)
    check_local_no_other_user_log(remote_user_client, creds_all_duts)

    cleanup_tacacs_server_log(ptfhost)

def test_accounting_tacacs_and_local_all_tacacs_server_down(localhost, ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs, remote_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell('sudo config aaa accounting "tacacs+ local"')
    cleanup_tacacs_server_log(ptfhost)

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)
    
    """
        After all server not accessible, run some command
        Verify local user still can run command without any issue.
    """
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Verify syslog have user command record.
    check_local_log_exist(remote_user_client, creds_all_duts, "show")
    # Verify syslog not have any command record which not run by user.
    check_local_no_other_user_log(remote_user_client, creds_all_duts)

    #  Cleanup UT.
    start_tacacs_server(ptfhost)

def test_accounting_local_only(localhost, ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs, remote_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa accounting local")
    cleanup_tacacs_server_log(ptfhost)

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Verify syslog have user command record.
    check_local_log_exist(remote_user_client, creds_all_duts, "show")
    # Verify syslog not have any command record which not run by user.
    check_local_no_other_user_log(remote_user_client, creds_all_duts)
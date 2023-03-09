import logging
import paramiko
import time
import pytest

from tests.tacacs.utils import stop_tacacs_server, start_tacacs_server
from tests.tacacs.utils import per_command_check_skip_versions, remove_all_tacacs_server, get_ld_path
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

TIMEOUT_LIMIT = 120


def ssh_connect_remote(remote_ip, remote_username, remote_password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        remote_ip, username=remote_username, password=remote_password, allow_agent=False,
        look_for_keys=False, auth_timeout=TIMEOUT_LIMIT)
    return ssh


def check_ssh_connect_remote_failed(remote_ip, remote_username, remote_password):
    login_failed = False
    try:
        ssh_connect_remote(remote_ip, remote_username, remote_password)
    except paramiko.ssh_exception.AuthenticationException as e:
        login_failed = True
        logger.info("Paramiko SSH connect failed with authentication: " + repr(e))

    pytest_assert(login_failed)


def ssh_run_command(ssh_client, command):
    stdin, stdout, stderr = ssh_client.exec_command(command, timeout=TIMEOUT_LIMIT)
    exit_code = stdout.channel.recv_exit_status()
    stdout_lines = stdout.readlines()
    stderr_lines = stderr.readlines()
    return exit_code, stdout_lines, stderr_lines


def check_ssh_output(res, exp_val):
    content_exist = False
    for line in res:
        if exp_val in line:
            content_exist = True
            break
    pytest_assert(content_exist)


def check_ssh_output_any_of(res, exp_vals):
    content_exist = False
    for line in res:
        for exp_val in exp_vals:
            if exp_val in line:
                content_exist = True
                break

    pytest_assert(content_exist)


@pytest.fixture
def remote_user_client(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    with ssh_connect_remote(
        dutip,
        tacacs_creds['tacacs_authorization_user'],
        tacacs_creds['tacacs_authorization_user_passwd']
    ) as ssh_client:
        yield ssh_client


@pytest.fixture
def local_user_client():
    with paramiko.SSHClient() as ssh_client:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        yield ssh_client


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202112
    Args:
        duthost: Hostname of DUT.
    Returns:
        None.
    """
    skip_release(duthost, per_command_check_skip_versions)


@pytest.fixture
def setup_authorization_tacacs(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization tacacs+")
    yield
    duthost.shell("sudo config aaa authorization local")    # Default authorization method is local


@pytest.fixture
def setup_authorization_tacacs_local(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization \"tacacs+ local\"")
    yield
    duthost.shell("sudo config aaa authorization local")    # Default authorization method is local


def check_authorization_tacacs_only(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, remote_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    """
        Verify TACACS+ user run command in server side whitelist:
            If command have local permission, user can run command.
    """
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "config aaa")
    pytest_assert(exit_code == 1)
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # Verify TACACS+ user can't run command not in server side whitelist.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "cat /etc/passwd")
    pytest_assert(exit_code == 1)
    check_ssh_output(stdout, '/usr/bin/cat authorize failed by TACACS+ with given arguments, not executing')

    # Verify Local user can't login.
    dutip = duthost.mgmt_ip
    check_ssh_connect_remote_failed(
        dutip, tacacs_creds['local_user'],
        tacacs_creds['local_user_passwd']
    )


def test_authorization_tacacs_only(duthosts, enum_rand_one_per_hwsku_hostname, setup_authorization_tacacs,
                                   tacacs_creds, check_tacacs, remote_user_client):
    check_authorization_tacacs_only(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, remote_user_client)


def test_authorization_tacacs_only_some_server_down(
        duthosts, enum_rand_one_per_hwsku_hostname,
        setup_authorization_tacacs, tacacs_creds, ptfhost, check_tacacs, remote_user_client):
    """
        Setup multiple tacacs server for this UT.
        Tacacs server 127.0.0.1 not accessible.
    """
    invalid_tacacs_server_ip = "127.0.0.1"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tacacs_server_ip = ptfhost.mgmt_ip
    duthost.shell("sudo config tacacs timeout 1")

    # cleanup all tacacs server, if UT break, tacacs server may still left in dut and will break next UT.
    remove_all_tacacs_server(duthost)

    duthost.shell("sudo config tacacs add %s" % invalid_tacacs_server_ip)
    duthost.shell("sudo config tacacs add %s" % tacacs_server_ip)

    # The above "config tacacs add" commands will trigger hostcfgd to regenerate tacacs config.
    # If we immediately run "show aaa" command, the client may still be using the first invalid tacacs server.
    # The second valid tacacs may not take effect yet. Wait some time for the valid tacacs server to take effect.
    time.sleep(2)

    """
        Verify TACACS+ user run command in server side whitelist:
            If command have local permission, user can run command.
            If command not have local permission, user can't run command.
        Verify TACACS+ user can't run command not in server side whitelist.
        Verify Local user can't login.
    """
    check_authorization_tacacs_only(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, remote_user_client)

    # Cleanup
    duthost.shell("sudo config tacacs delete %s" % invalid_tacacs_server_ip)
    duthost.shell("sudo config tacacs timeout 5")


def test_authorization_tacacs_only_then_server_down_after_login(
        setup_authorization_tacacs, ptfhost, check_tacacs, remote_user_client):

    # Verify when server are accessible, TACACS+ user can run command in server side whitelist.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)

    # Verify when server are not accessible, TACACS+ user can't run any command.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 1)
    check_ssh_output(stdout, '/usr/local/bin/show not authorized by TACACS+ with given arguments, not executing')

    #  Cleanup UT.
    start_tacacs_server(ptfhost)


def test_authorization_tacacs_and_local(
        duthosts, enum_rand_one_per_hwsku_hostname,
        setup_authorization_tacacs_local, tacacs_creds, check_tacacs, remote_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    """
        Verify TACACS+ user run command in server side whitelist:
            If command have local permission, user can run command.
    """
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "config aaa")
    pytest_assert(exit_code == 1)
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # Verify TACACS+ user can run command not in server side whitelist, but have local permission.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "cat /etc/passwd")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'root:x:0:0:root:/root:/bin/bash')

    # Verify Local user can't login.
    dutip = duthost.mgmt_ip
    check_ssh_connect_remote_failed(
        dutip, tacacs_creds['local_user'],
        tacacs_creds['local_user_passwd']
    )


def test_authorization_tacacs_and_local_then_server_down_after_login(
        duthosts, enum_rand_one_per_hwsku_hostname,
        setup_authorization_tacacs_local, tacacs_creds, ptfhost, check_tacacs, remote_user_client, local_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)

    # Verify TACACS+ user can run command not in server side whitelist but have permission in local.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "cat /etc/passwd")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'root:x:0:0:root:/root:/bin/bash')

    # Verify TACACS+ user can't run command in server side whitelist also not have permission in local.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "config tacacs")
    pytest_assert(exit_code == 1)
    check_ssh_output(stdout, '/usr/local/bin/config not authorized by TACACS+ with given arguments, not executing')
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # Verify Local user can login when tacacs closed, and run command with local permission.
    dutip = duthost.mgmt_ip
    local_user_client.connect(
        dutip, username=tacacs_creds['local_user'],
        password=tacacs_creds['local_user_passwd'],
        allow_agent=False, look_for_keys=False, auth_timeout=TIMEOUT_LIMIT
    )

    exit_code, stdout, stderr = ssh_run_command(local_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Start tacacs server
    start_tacacs_server(ptfhost)

    # Verify after Local user login, then server becomes accessible,
    # Local user still can run command with local permission.
    exit_code, stdout, stderr = ssh_run_command(local_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')


def test_authorization_local(
        duthosts, enum_rand_one_per_hwsku_hostname,
        tacacs_creds, ptfhost, check_tacacs, remote_user_client, local_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    """
        TACACS server up:
            Verify TACACS+ user can run command if have permission in local.
    """
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "config aaa")
    pytest_assert(exit_code == 1)
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # Shutdown tacacs server.
    stop_tacacs_server(ptfhost)

    """
        TACACS server down:
            Verify Local user can login, and run command with local permission.
    """
    dutip = duthost.mgmt_ip
    local_user_client.connect(
        dutip, username=tacacs_creds['local_user'],
        password=tacacs_creds['local_user_passwd'],
        allow_agent=False, look_for_keys=False, auth_timeout=TIMEOUT_LIMIT
    )

    exit_code, stdout, stderr = ssh_run_command(local_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Cleanup
    start_tacacs_server(ptfhost)


def test_bypass_authorization(
        duthosts, enum_rand_one_per_hwsku_hostname,
        setup_authorization_tacacs, check_tacacs, remote_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    """
        Verify user can't run script with sh/python with following command.
            python ./testscript.py

        NOTE: TACACS UT using tac_plus as server side, there is a bug that tac_plus can't handle an authorization
              message contains more than 10 attributes.
              Because every command parameter will convert to a TACACS attribute, please don't using more than 5
              command parameters in test case.
    """
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, 'echo "" >> ./testscript.py')
    pytest_assert(exit_code == 0)
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "python ./testscript.py")
    pytest_assert(exit_code == 1)
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')

    # Verify user can't run 'find' command with '-exec' parameter.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "find . -exec")
    pytest_assert(exit_code == 1)
    exp_outputs = ['not authorized by TACACS+ with given arguments, not executing',
                   'authorize failed by TACACS+ with given arguments, not executing']
    check_ssh_output_any_of(stdout, exp_outputs)

    # Verify user can run 'find' command without '-exec' parameter.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "find . /bin/sh")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, '/bin/sh')

    # Verify user can't run command with loader:
    #     /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 sh
    ld_path = get_ld_path(duthost)
    if not ld_path:
        exit_code, stdout, stderr = ssh_run_command(remote_user_client, ld_path + " sh")
        pytest_assert(exit_code == 1)
        check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')

    # Verify user can't run command with prefix/quoting:
    #     \sh
    #     "sh"
    #     echo $(sh -c ls)
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "\\sh")
    pytest_assert(exit_code == 1)
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, '"sh"')
    pytest_assert(exit_code == 1)
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')

    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "echo $(sh -c ls)")
    # echo command will run success and return 0, but sh command will be blocked.
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')


def test_backward_compatibility_disable_authorization(
        duthosts, enum_rand_one_per_hwsku_hostname,
        tacacs_creds, ptfhost, check_tacacs, remote_user_client, local_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Verify domain account can run command if have permission in local.
    exit_code, stdout, stderr = ssh_run_command(remote_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)

    # Verify domain account can't login to device successfully.
    dutip = duthost.mgmt_ip
    check_ssh_connect_remote_failed(
        dutip, tacacs_creds['tacacs_authorization_user'],
        tacacs_creds['tacacs_authorization_user_passwd']
    )

    # Verify local admin account can run command if have permission in local.
    dutip = duthost.mgmt_ip
    local_user_client.connect(
        dutip, username=tacacs_creds['local_user'],
        password=tacacs_creds['local_user_passwd'],
        allow_agent=False, look_for_keys=False, auth_timeout=TIMEOUT_LIMIT
    )

    exit_code, stdout, stderr = ssh_run_command(local_user_client, "show aaa")
    pytest_assert(exit_code == 0)
    check_ssh_output(stdout, 'AAA authentication')

    # Verify local admin account can't run command if not have permission in local.
    exit_code, stdout, stderr = ssh_run_command(local_user_client, "config aaa")
    pytest_assert(exit_code == 1)
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # cleanup
    start_tacacs_server(ptfhost)

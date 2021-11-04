import crypt
import paramiko
import pytest

from .test_ro_user import ssh_remote_run
from tests.common.helpers.assertions import pytest_assert
from .utils import stop_tacacs_server, start_tacacs_server

logger = logging.getLogger(__name__)

TIMEOUT_LIMIT   = 120

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def setup_local_user(duthost, creds_all_duts):
    try:
        duthost.shell("sudo deluser {}".format(creds_all_duts[duthost]['tacacs_local_user']))
    except:
        logger.warning("local user not exist")
    
    duthost.shell("sudo useradd {}".format(creds_all_duts[duthost]['tacacs_local_user']))
    duthost.shell('sudo echo "{}:{}" | chpasswd'.format(creds_all_duts[duthost]['tacacs_local_user'],creds_all_duts[duthost]['tacacs_local_user_passwd']))

def ssh_connect_remote(remote_ip, remote_username, remote_password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(remote_ip, username=remote_username, password=remote_password, allow_agent=False, look_for_keys=False, auth_timeout=TIMEOUT_LIMIT)
    return ssh
    

def check_ssh_connect_remote_failed(remote_ip, remote_username, remote_password):
    login_failed = False
    try:
        ssh_client_local = ssh_connect_remote(remote_ip, remote_username, remote_password)
    except paramiko.ssh_exception.AuthenticationException as e:
        login_failed = True
    
    pytest_assert(login_failed == True)

def ssh_run_command(ssh_client, command):
    stdin, stdout, stderr = ssh_client.exec_command(command, timeout=TIMEOUT_LIMIT)
    stdout_lines = stdout.readlines()
    stderr_lines = stderr.readlines()
    return stdout_lines, stderr_lines

def check_ssh_output(res, exp_val):
    content_exist = False
    for l in res:
        if exp_val in l:
            content_exist = True
            break
    pytest_assert(content_exist)

def test_authorization_tacacs_only(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization tacacs+")
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    ssh_client = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'])

    """
        Verify TACACS+ user run command in server side whitelist:
            If command have local permission, user can run command.
    """
    stdout, stderr = ssh_run_command(ssh_client, "show aaa")
    check_ssh_output(stdout, 'AAA authentication')

    """
        Verify TACACS+ user run command in server side whitelist:
            If command not have local permission, user can't run command.
    """
    stdout, stderr = ssh_run_command(ssh_client, "config aaa")
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # Verify TACACS+ user can't run command not in server side whitelist.
    stdout, stderr = ssh_run_command(ssh_client, "cat /etc/passwd")
    check_ssh_output(stdout, '/usr/bin/cat authorize failed by TACACS+ with given arguments, not executing')

    # Verify Local user can't login.
    check_ssh_connect_remote_failed(dutip, creds_all_duts[duthost]['tacacs_local_user'],
                             creds_all_duts[duthost]['tacacs_local_user_passwd'])

    ssh_client.close()

def test_authorization_tacacs_only_some_server_down(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts,ptfhost, check_tacacs):
    """
        Setup multiple tacacs server for this UT.
        Tacacs server 1.2.3.4 not accessible.
    """
    invalied_tacacs_server_ip = "1.2.3.4"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tacacs_server_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    duthost.shell("sudo config tacacs timeout 1")
    for tacacs_server in config_facts.get('TACPLUS_SERVER', {}):
        duthost.shell("sudo config tacacs delete %s" % tacacs_server)
    duthost.shell("sudo config tacacs add %s" % invalied_tacacs_server_ip)
    duthost.shell("sudo config tacacs add %s" % tacacs_server_ip)
    
    """
        Verify TACACS+ user run command in server side whitelist:
            If command have local permission, user can run command.
            If command not have local permission, user can't run command.
        Verify TACACS+ user can't run command not in server side whitelist.
        Verify Local user can't login.
    """
    test_authorization_tacacs_only(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs)

    # Cleanup
    duthost.shell("sudo config tacacs delete %s" % invalied_tacacs_server_ip)

def test_authorization_tacacs_only_then_server_down_after_login(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts,ptfhost, check_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization tacacs+")
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Create a ssh connection to sonic device.
    ssh_client = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'])

    # Verify when server are accessible, TACACS+ user can run command in server side whitelist.
    stdout, stderr = ssh_run_command(ssh_client, "show aaa")
    check_ssh_output(stdout, 'AAA authentication')

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)

    # Verify when server are not accessible, TACACS+ user can't run any command.
    stdout, stderr = ssh_run_command(ssh_client, "show aaa")
    check_ssh_output(stdout, '/usr/local/bin/show not authorized by TACACS+ with given arguments, not executing')

    #  Cleanup UT.
    start_tacacs_server(ptfhost)
    ssh_client.close()

def test_authorization_tacacs_and_local(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts,ptfhost, check_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization \"tacacs+ local\"")
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Create a ssh connection to sonic device.
    ssh_client = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'])


    """
        Verify TACACS+ user run command in server side whitelist:
            If command have local permission, user can run command.
    """
    stdout, stderr = ssh_run_command(ssh_client, "show aaa")
    check_ssh_output(stdout, 'AAA authentication')

    """
        Verify TACACS+ user run command in server side whitelist:
            If command not have local permission, user can't run command.
    """
    stdout, stderr = ssh_run_command(ssh_client, "config aaa")
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # Verify TACACS+ user can run command not in server side whitelist, but have local permission.
    stdout, stderr = ssh_run_command(ssh_client, "cat /etc/passwd")
    check_ssh_output(stdout, 'root:x:0:0:root:/root:/bin/bash')

    # Verify Local user can't login.
    check_ssh_connect_remote_failed(dutip, creds_all_duts[duthost]['tacacs_local_user'],
                             creds_all_duts[duthost]['tacacs_local_user_passwd'])
    
    ssh_client.close()


def test_authorization_tacacs_and_local_then_server_down_after_login(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts,ptfhost, check_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization \"tacacs+ local\"")
    setup_local_user(duthost, creds_all_duts)
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Create a ssh connection to sonic device
    ssh_client = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'])

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)
    
    # Verify TACACS+ user can run command not in server side whitelist but have permission in local.
    stdout, stderr = ssh_run_command(ssh_client, "cat /etc/passwd")
    check_ssh_output(stdout, 'root:x:0:0:root:/root:/bin/bash')
    
    # Verify TACACS+ user can't run command in server side whitelist also not have permission in local.
    stdout, stderr = ssh_run_command(ssh_client, "config tacacs")
    check_ssh_output(stdout, '/usr/local/bin/config not authorized by TACACS+ with given arguments, not executing')
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # Verify Local user can login, and run command with local permission.
    ssh_client_local = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_local_user'],
                         creds_all_duts[duthost]['tacacs_local_user_passwd'])

    # Start tacacs server
    start_tacacs_server(ptfhost)
    
    # Verify after Local user login, then server becomes accessible, Local user still can run command with local permission.
    stdout, stderr = ssh_run_command(ssh_client_local, "show aaa")
    check_ssh_output(stdout, 'AAA authentication')

    # Cleanup
    ssh_client.close()
    ssh_client_local.close()


def test_authorization_local(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts,ptfhost, check_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization local")
    setup_local_user(duthost, creds_all_duts)
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Create a ssh connection to sonic device.
    ssh_client = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'])

    """
        TACACS server up:
            Verify TACACS+ user can run command if have permission in local.
    """
    stdout, stderr = ssh_run_command(ssh_client, "show aaa")
    check_ssh_output(stdout, 'AAA authentication')

    """
        TACACS server up:
            Verify TACACS+ user can't run command if not have permission in local.
    """
    stdout, stderr = ssh_run_command(ssh_client, "config aaa")
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    # Shutdown tacacs server.
    stop_tacacs_server(ptfhost)

    """
        TACACS server down:
            Verify Local user can login, and run command with local permission.
    """
    ssh_client_local = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_local_user'],
                         creds_all_duts[duthost]['tacacs_local_user_passwd'])

    stdout, stderr = ssh_run_command(ssh_client_local, "show aaa")
    check_ssh_output(stdout, 'AAA authentication')
    
    # Cleanup
    start_tacacs_server(ptfhost)
    ssh_client.close()
    ssh_client_local.close()


def test_bypass_authorization(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts,ptfhost, check_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization tacacs+")
    setup_local_user(duthost, creds_all_duts)
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Create a ssh connection to sonic device
    ssh_client = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'])

    """
        Verify user can't run script with sh/python with following command.
            python ./testscript.py
    """
    stdout, stderr = ssh_run_command(ssh_client, 'echo "" >> ./testscript.py')
    stdout, stderr = ssh_run_command(ssh_client, "python ./testscript.py")
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')

    # Verify user can't run 'find' command with '-exec' parameter.
    stdout, stderr = ssh_run_command(ssh_client, "find . -type f -exec /bin/sh ;")
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')

    # Verify user can run 'find' command without '-exec' parameter.
    stdout, stderr = ssh_run_command(ssh_client, "find . /bin/sh")
    check_ssh_output(stdout, '/bin/sh')

    """
        Verify user can't run command with loader:
            /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 sh
    """
    stdout, stderr = ssh_run_command(ssh_client, "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 sh")
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')

    """
        Verify user can't run command with prefix/quoting:
            \sh
            "sh"
            echo $(sh -c ls)
    """
    stdout, stderr = ssh_run_command(ssh_client, "\\sh")
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')
    
    stdout, stderr = ssh_run_command(ssh_client, '"sh"')
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')
    
    stdout, stderr = ssh_run_command(ssh_client, "echo $(sh -c ls)")
    check_ssh_output(stdout, 'authorize failed by TACACS+ with given arguments, not executing')
    
    ssh_client.close()

def test_backward_compatibility_disable_authorization(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts,ptfhost, check_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization local")
    setup_local_user(duthost, creds_all_duts)
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Verify domain account can login to device successfully.
    ssh_client = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'])

    # Verify domain account can run command if have permission in local.
    stdout, stderr = ssh_run_command(ssh_client, "show aaa")
    check_ssh_output(stdout, 'AAA authentication')
    ssh_client.close()

    # Shutdown tacacs server
    stop_tacacs_server(ptfhost)

    # Verify domain account can't login to device successfully.
    check_ssh_connect_remote_failed(dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'])

    # Verify local admin account can login to device successfully.
    ssh_client_local = ssh_connect_remote(dutip, creds_all_duts[duthost]['tacacs_local_user'],
                         creds_all_duts[duthost]['tacacs_local_user_passwd'])

    # Verify local admin account can run command if have permission in local.
    stdout, stderr = ssh_run_command(ssh_client_local, "show aaa")
    check_ssh_output(stdout, 'AAA authentication')

    # Verify local admin account can't run command if not have permission in local.
    stdout, stderr = ssh_run_command(ssh_client_local, "config aaa")
    check_ssh_output(stderr, 'Root privileges are required for this operation')

    ssh_client_local.close()
    start_tacacs_server(ptfhost)

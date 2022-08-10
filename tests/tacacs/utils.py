import crypt
import logging
import re

from tests.common.errors import RunAnsibleModuleFail
from tests.common.utilities import wait_until, check_skip_release
from tests.common.helpers.assertions import pytest_assert
from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)

# per-command authorization and accounting feature not avaliable in following versions
per_command_check_skip_versions = ["201811", "201911", "202012", "202106"]

def check_output(output, exp_val1, exp_val2):
    pytest_assert(not output['failed'], output['stderr'])
    for l in output['stdout_lines']:
        fds = l.split(':')
        if fds[0] == exp_val1:
            pytest_assert(fds[4] == exp_val2)

def check_all_services_status(ptfhost):
    res = ptfhost.command("service --status-all")
    logger.info(res["stdout_lines"])


def start_tacacs_server(ptfhost):
    ptfhost.command("service tacacs_plus restart", module_ignore_errors=True)
    return "tacacs+ running" in ptfhost.command("service tacacs_plus status", module_ignore_errors=True)["stdout_lines"]

def stop_tacacs_server(ptfhost):
    ptfhost.service(name="tacacs_plus", state="stopped")
    check_all_services_status(ptfhost)

def setup_local_user(duthost, tacacs_creds):
    try:
        duthost.shell("sudo deluser {}".format(tacacs_creds['local_user']))
    except RunAnsibleModuleFail:
        logger.info("local user not exist")

    duthost.shell("sudo useradd {}".format(tacacs_creds['local_user']))
    duthost.shell('sudo echo "{}:{}" | chpasswd'.format(tacacs_creds['local_user'],tacacs_creds['local_user_passwd']))

def setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip):
    """setup tacacs client"""

    # configure tacacs client
    default_tacacs_servers = []
    duthost.shell("sudo config tacacs passkey %s" % tacacs_creds[duthost.hostname]['tacacs_passkey'])

    # get default tacacs servers
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for tacacs_server in config_facts.get('TACPLUS_SERVER', {}):
        duthost.shell("sudo config tacacs delete %s" % tacacs_server)
        default_tacacs_servers.append(tacacs_server)
    duthost.shell("sudo config tacacs add %s" % tacacs_server_ip)
    duthost.shell("sudo config tacacs authtype login")

    # enable tacacs+
    duthost.shell("sudo config aaa authentication login tacacs+")

    (skip, _) = check_skip_release(duthost, per_command_check_skip_versions)
    if not skip:
        duthost.shell("sudo config aaa authorization local")
        duthost.shell("sudo config aaa accounting disable")

    # setup local user
    setup_local_user(duthost, tacacs_creds)
    return default_tacacs_servers

def restore_tacacs_servers(duthost, default_tacacs_servers, tacacs_server_ip):
    duthost.shell("sudo config tacacs delete %s" % tacacs_server_ip)
    for tacacs_server in default_tacacs_servers:
        duthost.shell("sudo config tacacs add %s" % tacacs_server)

def fix_symbolic_link_in_config(duthost, ptfhost, symbolic_link_path, path_to_be_fix = None):
    """
        Fix symbolic link in tacacs config
        Because tac_plus server not support regex in command name, and SONiC will send full path to tacacs server side for authorization, so the 'python' and 'ld' path in tac_plus config file need fix.
    """
    read_link_command = "readlink -f {0}".format(symbolic_link_path)
    target_path = duthost.shell(read_link_command)['stdout']
    # Escape path string, will use it as regex in sed command.
    
    link_path_regex = re.escape(symbolic_link_path)
    if path_to_be_fix != None:
        link_path_regex = re.escape(path_to_be_fix)

    target_path_regex = re.escape(target_path)
    ptfhost.shell("sed -i 's/{0}/{1}/g' /etc/tacacs+/tac_plus.conf".format(link_path_regex, target_path_regex))

def get_ld_path(duthost):
    """
        Fix symbolic link in tacacs config
        Because tac_plus server not support regex in command name, and SONiC will send full path to tacacs server side for authorization, so the 'python' and 'ld' path in tac_plus config file need fix.
    """
    find_ld_command = "find /lib/ -type f,l -regex '\/lib\/.*-linux-.*/ld-linux-.*\.so\.[0-9]*'"
    return duthost.shell(find_ld_command)['stdout']

def fix_ld_path_in_config(duthost, ptfhost):
    """
        Fix ld path in tacacs config
    """
    ld_symbolic_link_path = get_ld_path(duthost)
    if not ld_symbolic_link_path:
        fix_symbolic_link_in_config(duthost, ptfhost, ld_symbolic_link_path, "/lib/arch-linux-abi/ld-linux-arch.so")

def setup_tacacs_server(ptfhost, tacacs_creds, duthost):
    """setup tacacs server"""

    # configure tacacs server
    extra_vars = {'tacacs_passkey': tacacs_creds[duthost.hostname]['tacacs_passkey'],
                  'tacacs_rw_user': tacacs_creds['tacacs_rw_user'],
                  'tacacs_rw_user_passwd': crypt.crypt(tacacs_creds['tacacs_rw_user_passwd'], 'abc'),
                  'tacacs_ro_user': tacacs_creds['tacacs_ro_user'],
                  'tacacs_ro_user_passwd': crypt.crypt(tacacs_creds['tacacs_ro_user_passwd'], 'abc'),
                  'tacacs_authorization_user': tacacs_creds['tacacs_authorization_user'],
                  'tacacs_authorization_user_passwd': crypt.crypt(tacacs_creds['tacacs_authorization_user_passwd'], 'abc'),
                  'tacacs_jit_user': tacacs_creds['tacacs_jit_user'],
                  'tacacs_jit_user_passwd': crypt.crypt(tacacs_creds['tacacs_jit_user_passwd'], 'abc'),
                  'tacacs_jit_user_membership': tacacs_creds['tacacs_jit_user_membership']}

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src="tacacs/tac_plus.conf.j2", dest="/etc/tacacs+/tac_plus.conf")

    # Find 'python' command symbolic link target, and fix the tac_plus config file
    fix_symbolic_link_in_config(duthost, ptfhost, "/usr/bin/python")

    # Find ld lib symbolic link target, and fix the tac_plus config file
    fix_ld_path_in_config(duthost, ptfhost)

    ptfhost.lineinfile(path="/etc/default/tacacs+", line="DAEMON_OPTS=\"-d 10 -l /var/log/tac_plus.log -C /etc/tacacs+/tac_plus.conf\"", regexp='^DAEMON_OPTS=.*')
    check_all_services_status(ptfhost)

    # FIXME: This is a short term mitigation, we need to figure out why \nthe tacacs+ server does not start
    # reliably all of a sudden.
    wait_until(5, 1, 0, start_tacacs_server, ptfhost)
    check_all_services_status(ptfhost)


def cleanup_tacacs(ptfhost, tacacs_creds, duthost):
    # stop tacacs server
    stop_tacacs_server(ptfhost)

    # reset tacacs client configuration
    remove_all_tacacs_server(duthost)
    duthost.shell("sudo config tacacs default passkey")
    duthost.shell("sudo config aaa authentication login default")
    duthost.shell("sudo config aaa authentication failthrough default")

    (skip, _) = check_skip_release(duthost, per_command_check_skip_versions)
    if not skip:
        duthost.shell("sudo config aaa authorization local")
        duthost.shell("sudo config aaa accounting disable")

    duthost.user(name=tacacs_creds['tacacs_ro_user'], state='absent', remove='yes', force='yes', module_ignore_errors=True)
    duthost.user(name=tacacs_creds['tacacs_rw_user'], state='absent', remove='yes', force='yes', module_ignore_errors=True)
    duthost.user(name=tacacs_creds['tacacs_jit_user'], state='absent', remove='yes', force='yes', module_ignore_errors=True)


def remove_all_tacacs_server(duthost):
    # use grep command to extract tacacs server address from tacacs config
    find_server_command = 'show tacacs | grep -Po "TACPLUS_SERVER address \K.*"'
    server_list = duthost.shell(find_server_command)['stdout']
    for tacacs_server in server_list:
        tacacs_server = tacacs_server.rstrip()
        if tacacs_server:
            duthost.shell("sudo config tacacs delete %s" % tacacs_server)

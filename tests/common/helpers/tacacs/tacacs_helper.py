import os
import yaml
import pytest
import logging
import time
import crypt
import re
from tests.common.utilities import wait_until, check_skip_release, delete_running_config
from tests.common.helpers.assertions import pytest_assert
from tests.common.errors import RunAnsibleModuleFail
from contextlib import contextmanager

# per-command accounting feature not available in following versions
per_command_accounting_skip_versions = ["201811", "201911", "202106"]
# per-command authorization feature not available in following versions
per_command_authorization_skip_versions = ["201811", "201911", "202012", "202106"]

logger = logging.getLogger(__name__)


def load_tacacs_creds():
    TACACS_CREDS_FILE = 'tacacs_creds.yaml'
    creds_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), TACACS_CREDS_FILE)
    return yaml.safe_load(open(creds_file_path).read())


def setup_local_user(duthost, tacacs_creds):
    try:
        duthost.shell("sudo deluser {}".format(tacacs_creds['local_user']))
    except RunAnsibleModuleFail:
        logger.info("local user not exist")

    duthost.shell("sudo useradd {}".format(tacacs_creds['local_user']))
    duthost.shell('sudo echo "{}:{}" | chpasswd'.format(tacacs_creds['local_user'], tacacs_creds['local_user_passwd']))


def setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip,
                        tacacs_server_passkey, ptfhost, authorization="local"):
    """setup tacacs client"""

    # UT should failed when set reachable TACACS server with this setup_tacacs_client
    retry = 5
    while retry > 0:
        ping_result = duthost.shell("ping {} -c 1 -W 3".format(tacacs_server_ip), module_ignore_errors=True)['stdout']
        logger.info("TACACS server ping result: {}".format(ping_result))
        if "100% packet loss" in ping_result:
            # collect more information for debug testbed network issue
            duthost_interface = duthost.shell("sudo ifconfig eth0")['stdout']
            ptfhost_interface = ptfhost.shell("ifconfig mgmt")['stdout']
            logger.debug("PTF IPV6 address not reachable, dut interfaces: {}, ptfhost interfaces:{}"
                         .format(duthost_interface, ptfhost_interface))
            time.sleep(5)
            retry -= 1
        else:
            break
    if retry == 0:
        pytest_assert(False, "TACACS server not reachable: {}".format(ping_result))

    # configure tacacs client
    default_tacacs_servers = []
    duthost.shell("sudo config tacacs passkey %s" % tacacs_server_passkey)

    # get default tacacs servers
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for tacacs_server in config_facts.get('TACPLUS_SERVER', {}):
        duthost.shell("sudo config tacacs delete %s" % tacacs_server)
        default_tacacs_servers.append(tacacs_server)
    # setup TACACS server with port 59
    # Port 49 bind to another TACACS server for daily work and none TACACS test case
    duthost.shell("sudo config tacacs add %s --port 59" % tacacs_server_ip)
    duthost.shell("sudo config tacacs authtype login")

    # enable tacacs+
    duthost.shell("sudo config aaa authentication login tacacs+")

    (skip, _) = check_skip_release(duthost, per_command_authorization_skip_versions)
    if not skip:
        duthost.shell("sudo config aaa authorization {}".format(authorization))

    (skip, _) = check_skip_release(duthost, per_command_accounting_skip_versions)
    if not skip:
        duthost.shell("sudo config aaa accounting disable")

    # setup local user
    setup_local_user(duthost, tacacs_creds)
    return default_tacacs_servers


def fix_symbolic_link_in_config(duthost, ptfhost, symbolic_link_path, path_to_be_fix=None):
    """
        Fix symbolic link in tacacs config
        Because tac_plus server not support regex in command name, and SONiC will send full path to tacacs server side
        for authorization, so the 'python' and 'ld' path in tac_plus config file need fix.
    """
    read_link_command = "readlink -f {0}".format(symbolic_link_path)
    target_path = duthost.shell(read_link_command)['stdout']
    # Escape path string, will use it as regex in sed command.

    link_path_regex = re.escape(symbolic_link_path)
    if path_to_be_fix is not None:
        link_path_regex = re.escape(path_to_be_fix)

    target_path_regex = re.escape(target_path)
    ptfhost.shell("sed -i 's|{0}|{1}|g' /etc/tacacs+/tac_plus.conf".format(link_path_regex, target_path_regex))


def get_ld_path(duthost):
    """
        Fix symbolic link in tacacs config
        Because tac_plus server not support regex in command name, and SONiC will send full path to tacacs server side
        for authorization, so the 'python' and 'ld' path in tac_plus config file need fix.
    """
    find_ld_command = "find /lib/ -type f,l -regex '\/lib\/.*-linux-.*/ld-linux-.*\.so\.[0-9]*'"   # noqa W605
    return duthost.shell(find_ld_command)['stdout']


def fix_ld_path_in_config(duthost, ptfhost):
    """
        Fix ld path in tacacs config
    """
    ld_symbolic_link_path = get_ld_path(duthost)
    if not ld_symbolic_link_path:
        fix_symbolic_link_in_config(duthost, ptfhost, ld_symbolic_link_path, "/lib/arch-linux-abi/ld-linux-arch.so")


def check_all_services_status(ptfhost):
    res = ptfhost.command("service --status-all")
    logger.info(res["stdout_lines"])


def setup_tacacs_server(ptfhost, tacacs_creds, duthost):
    """setup tacacs server"""

    # configure tacacs server
    extra_vars = {'tacacs_passkey': tacacs_creds[duthost.hostname]['tacacs_passkey'],
                  'tacacs_rw_user': tacacs_creds['tacacs_rw_user'],
                  'tacacs_rw_user_passwd': crypt.crypt(tacacs_creds['tacacs_rw_user_passwd'], 'abc'),
                  'tacacs_ro_user': tacacs_creds['tacacs_ro_user'],
                  'tacacs_ro_user_passwd': crypt.crypt(tacacs_creds['tacacs_ro_user_passwd'], 'abc'),
                  'tacacs_authorization_user': tacacs_creds['tacacs_authorization_user'],
                  'tacacs_authorization_user_passwd': crypt.crypt(
                        tacacs_creds['tacacs_authorization_user_passwd'],
                        'abc'),
                  'tacacs_jit_user': tacacs_creds['tacacs_jit_user'],
                  'tacacs_jit_user_passwd': crypt.crypt(tacacs_creds['tacacs_jit_user_passwd'], 'abc'),
                  'tacacs_jit_user_membership': tacacs_creds['tacacs_jit_user_membership']}

    dut_options = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars
    dut_creds = tacacs_creds[duthost.hostname]
    logger.debug("setup_tacacs_server: dut_options:{}".format(dut_options))
    if 'ansible_user' in dut_options and 'ansible_password' in dut_options:
        duthost_admin_user = dut_options['ansible_user']
        duthost_admin_passwd = dut_options['ansible_password']
        logger.debug("setup_tacacs_server: update extra_vars with ansible_user and ansible_password.")
        extra_vars['duthost_admin_user'] = duthost_admin_user
        extra_vars['duthost_admin_passwd'] = crypt.crypt(duthost_admin_passwd, 'abc')
    elif 'sonicadmin_user' in dut_creds and 'sonicadmin_password' in dut_creds:
        logger.debug("setup_tacacs_server: update extra_vars with sonicadmin_user and sonicadmin_password.")
        extra_vars['duthost_admin_user'] = dut_creds['sonicadmin_user']
        extra_vars['duthost_admin_passwd'] = crypt.crypt(dut_creds['sonicadmin_password'], 'abc')
    elif 'sonicadmin_user' in dut_creds and 'ansible_altpasswords' in dut_creds:
        logger.debug("setup_tacacs_server: update extra_vars with sonicadmin_user and ansible_altpasswords.")
        extra_vars['duthost_admin_user'] = dut_creds['sonicadmin_user']
        extra_vars['duthost_admin_passwd'] = crypt.crypt(dut_creds['ansible_altpasswords'][0], 'abc')
    else:
        logger.debug("setup_tacacs_server: update extra_vars with sonic_login and sonic_password.")
        extra_vars['duthost_admin_user'] = dut_creds['sonic_login']
        extra_vars['duthost_admin_passwd'] = crypt.crypt(dut_creds['sonic_password'], 'abc')

    if 'ansible_ssh_user' in dut_options and 'ansible_ssh_pass' in dut_options:
        duthost_ssh_user = dut_options['ansible_ssh_user']
        duthost_ssh_passwd = dut_options['ansible_ssh_pass']
        if not duthost_ssh_user == extra_vars['duthost_admin_user']:
            logger.debug("setup_tacacs_server: update extra_vars with ansible_ssh_user and ansible_ssh_pass.")
            extra_vars['duthost_ssh_user'] = duthost_ssh_user
            extra_vars['duthost_ssh_passwd'] = crypt.crypt(duthost_ssh_passwd, 'abc')
        else:
            logger.debug("setup_tacacs_server: ansible_ssh_user is the same as duthost_admin_user.")
    else:
        logger.debug("setup_tacacs_server: duthost options does not contains config for ansible_ssh_user.")

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src="tacacs/tac_plus.conf.j2", dest="/etc/tacacs+/tac_plus.conf")

    # Find 'python' command symbolic link target, and fix the tac_plus config file
    fix_symbolic_link_in_config(duthost, ptfhost, "/usr/bin/python")

    # Find ld lib symbolic link target, and fix the tac_plus config file
    fix_ld_path_in_config(duthost, ptfhost)

    # config TACACS+ to use debug flag: '-d 2058', so received data will write to /var/log/tac_plus.log
    # config TACACS+ to use port 59: '-p 59', because 49 already running another tacacs server for daily work
    ptfhost.lineinfile(
        path="/etc/default/tacacs+",
        line="DAEMON_OPTS=\"-d 2058 -l /var/log/tac_plus.log -C /etc/tacacs+/tac_plus.conf -p 59\"",
        regexp='^DAEMON_OPTS=.*'
    )

    # config TACACS+ start script to check tac_plus.pid.59
    ptfhost.lineinfile(
        path="/etc/init.d/tacacs_plus",
        line="PIDFILE=/var/run/tac_plus.pid.59",
        regexp='^PIDFILE=/var/run/tac_plus.*'
    )
    check_all_services_status(ptfhost)

    # FIXME: This is a short term mitigation, we need to figure out why \nthe tacacs+ server does not start
    # reliably all of a sudden.
    wait_until(5, 1, 0, start_tacacs_server, ptfhost)
    check_all_services_status(ptfhost)


def stop_tacacs_server(ptfhost):
    def tacacs_not_running(ptfhost):
        out = ptfhost.command("service tacacs_plus status", module_ignore_errors=True)["stdout"]
        return "tacacs+ apparently not running" in out
    ptfhost.shell("service tacacs_plus stop")
    return wait_until(5, 1, 0, tacacs_not_running, ptfhost)


def remove_all_tacacs_server(duthost):
    # use grep command to extract tacacs server address from tacacs config
    find_server_command = 'show tacacs | grep -Po "TACPLUS_SERVER address \K.*"'    # noqa W605
    server_list = duthost.shell(find_server_command, module_ignore_errors=True)['stdout_lines']
    for tacacs_server in server_list:
        tacacs_server = tacacs_server.rstrip()
        if tacacs_server:
            duthost.shell("sudo config tacacs delete %s" % tacacs_server)


def cleanup_tacacs(ptfhost, tacacs_creds, duthost):
    # stop tacacs server
    stop_tacacs_server(ptfhost)

    # reset tacacs client configuration
    remove_all_tacacs_server(duthost)
    cmds = [
        "config tacacs default passkey",
        "config aaa authentication login default",
        "config aaa authentication failthrough default"
    ]
    duthost.shell_cmds(cmds=cmds)

    (skip, _) = check_skip_release(duthost, per_command_authorization_skip_versions)
    if not skip:
        duthost.shell("sudo config aaa authorization local")

    (skip, _) = check_skip_release(duthost, per_command_accounting_skip_versions)
    if not skip:
        duthost.shell("sudo config aaa accounting disable")

    duthost.user(
        name=tacacs_creds['tacacs_ro_user'], state='absent', remove='yes', force='yes', module_ignore_errors=True
    )
    duthost.user(
        name=tacacs_creds['tacacs_rw_user'], state='absent', remove='yes', force='yes', module_ignore_errors=True
    )
    duthost.user(
        name=tacacs_creds['tacacs_jit_user'], state='absent', remove='yes', force='yes', module_ignore_errors=True
    )


def restore_tacacs_servers(duthost):
    # Restore the TACACS plus server in config_db.json
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")["ansible_facts"]
    for tacacs_server in config_facts.get("TACPLUS_SERVER", {}):
        duthost.shell("sudo config tacacs add %s" % tacacs_server)

    cmds = []
    aaa_config = config_facts.get("AAA", {})
    if aaa_config:
        cfg = aaa_config.get("authentication", {}).get("login", "")
        if cfg:
            cmds.append("sonic-db-cli CONFIG_DB hset 'AAA|authentication' login %s" % cfg)

        cfg = aaa_config.get("authentication", {}).get("failthrough", "")
        if cfg.lower() == "true":
            cmds.append("config aaa authentication failthrough enable")
        elif cfg.lower() == "false":
            cmds.append("config aaa authentication failthrough disable")

        cfg = aaa_config.get("authorization", {}).get("login", "")
        if cfg:
            cmds.append("sonic-db-cli CONFIG_DB hset 'AAA|authorization' login %s" % cfg)

        cfg = aaa_config.get("accounting", {}).get("login", "")
        if cfg:
            cmds.append("sonic-db-cli CONFIG_DB hset 'AAA|accounting' login %s" % cfg)

    tacplus_config = config_facts.get("TACPLUS", {})
    if tacplus_config:
        cfg = tacplus_config.get("global", {}).get("auth_type", "")
        if cfg:
            cmds.append("config tacacs authtype %s" % cfg)

        cfg = tacplus_config.get("global", {}).get("passkey", "")
        if cfg:
            cmds.append("config tacacs passkey %s" % cfg)

        cfg = tacplus_config.get("global", {}).get("timeout", "")
        if cfg:
            cmds.append("config tacacs timeout %s" % cfg)

    # Cleanup AAA and TACPLUS config
    delete_tacacs_json = [{"AAA": {}}, {"TACPLUS": {}}]
    delete_running_config(delete_tacacs_json, duthost)

    # Restore AAA and TACPLUS config
    duthost.shell_cmds(cmds=cmds)


@contextmanager
def _context_for_check_tacacs_v6(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds): # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
    if 'ansible_hostv6' not in ptfhost_vars:
        pytest.skip("Skip IPv6 test. ptf ansible_hostv6 not configured.")
    tacacs_server_ip = ptfhost_vars['ansible_hostv6']
    tacacs_server_passkey = tacacs_creds[duthost.hostname]['tacacs_passkey']
    setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip, tacacs_server_passkey, ptfhost)
    setup_tacacs_server(ptfhost, tacacs_creds, duthost)

    yield

    cleanup_tacacs(ptfhost, tacacs_creds, duthost)
    restore_tacacs_servers(duthost)


@pytest.fixture(scope="function")
def check_tacacs_v6_func(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds): # noqa F811
    with _context_for_check_tacacs_v6(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds) as result:
        yield result


def tacacs_running(ptfhost):
    out = ptfhost.command("service tacacs_plus status", module_ignore_errors=True)["stdout"]
    return "tacacs+ running" in out


def start_tacacs_server(ptfhost):
    ptfhost.command("service tacacs_plus restart", module_ignore_errors=True)
    return wait_until(5, 1, 0, tacacs_running, ptfhost)


def ssh_remote_run(localhost, remote_ip, username, password, cmd):
    res = localhost.shell("sshpass -p {} ssh "
                          "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                          "{}@{} {}".format(password, username, remote_ip, cmd), module_ignore_errors=True)
    return res


def ssh_remote_run_retry(localhost, dutip, ptfhost, user, password, command, retry_count=3):
    while retry_count > 0:
        res = ssh_remote_run(localhost, dutip, user,
                             password, command)

        # TACACS server randomly crash after receive authorization request from IPV6
        if not tacacs_running(ptfhost):
            start_tacacs_server(ptfhost)
            retry_count -= 1
        else:
            return res

    pytest_assert(False, "cat command failed because TACACS server not running")

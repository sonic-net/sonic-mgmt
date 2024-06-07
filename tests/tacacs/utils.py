import crypt
import logging
import re
import binascii
import pytest
import time

from tests.common.errors import RunAnsibleModuleFail
from tests.common.utilities import wait_until, check_skip_release, delete_running_config
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


# per-command authorization feature not available in following versions
per_command_authorization_skip_versions = ["201811", "201911", "202012", "202106"]


# per-command accounting feature not available in following versions
per_command_accounting_skip_versions = ["201811", "201911", "202106"]


def check_output(output, exp_val1, exp_val2):
    pytest_assert(not output['failed'], output['stderr'])
    for line in output['stdout_lines']:
        fds = line.split(':')
        if fds[0] == exp_val1:
            pytest_assert(fds[4] == exp_val2)


def check_all_services_status(ptfhost):
    res = ptfhost.command("service --status-all")
    logger.info(res["stdout_lines"])


def tacacs_running(ptfhost):
    out = ptfhost.command("service tacacs_plus status", module_ignore_errors=True)["stdout"]
    return "tacacs+ running" in out


def start_tacacs_server(ptfhost):
    ptfhost.command("service tacacs_plus restart", module_ignore_errors=True)
    return wait_until(5, 1, 0, tacacs_running, ptfhost)


def stop_tacacs_server(ptfhost):
    def tacacs_not_running(ptfhost):
        out = ptfhost.command("service tacacs_plus status", module_ignore_errors=True)["stdout"]
        return "tacacs+ apparently not running" in out
    ptfhost.shell("service tacacs_plus stop")
    return wait_until(5, 1, 0, tacacs_not_running, ptfhost)


@pytest.fixture
def ensure_tacacs_server_running_after_ut(duthosts, enum_rand_one_per_hwsku_hostname):
    """make sure tacacs server running after UT finish"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    yield

    start_tacacs_server(duthost)


def setup_local_user(duthost, tacacs_creds):
    try:
        duthost.shell("sudo deluser {}".format(tacacs_creds['local_user']))
    except RunAnsibleModuleFail:
        logger.info("local user not exist")

    duthost.shell("sudo useradd {}".format(tacacs_creds['local_user']))
    duthost.shell('sudo echo "{}:{}" | chpasswd'.format(tacacs_creds['local_user'], tacacs_creds['local_user_passwd']))


def setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip, ptfhost):
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

    (skip, _) = check_skip_release(duthost, per_command_authorization_skip_versions)
    if not skip:
        duthost.shell("sudo config aaa authorization local")

    (skip, _) = check_skip_release(duthost, per_command_accounting_skip_versions)
    if not skip:
        duthost.shell("sudo config aaa accounting disable")

    # setup local user
    setup_local_user(duthost, tacacs_creds)
    return default_tacacs_servers


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
            cmds.append("config aaa authentication login %s" % cfg)

        cfg = aaa_config.get("authentication", {}).get("failthrough", "")
        if cfg.lower() == "true":
            cmds.append("config aaa authentication failthrough enable")
        elif cfg.lower() == "false":
            cmds.append("config aaa authentication failthrough disable")

        cfg = aaa_config.get("authorization", {}).get("login", "")
        if cfg:
            cmds.append("config aaa authorization %s" % cfg)

        cfg = aaa_config.get("accounting", {}).get("login", "")
        if cfg:
            cmds.append("config aaa accounting %s" % cfg)

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

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src="tacacs/tac_plus.conf.j2", dest="/etc/tacacs+/tac_plus.conf")

    # Find 'python' command symbolic link target, and fix the tac_plus config file
    fix_symbolic_link_in_config(duthost, ptfhost, "/usr/bin/python")

    # Find ld lib symbolic link target, and fix the tac_plus config file
    fix_ld_path_in_config(duthost, ptfhost)

    # config TACACS+ to use debug flag: '-d 2058', so received data will write to /var/log/tac_plus.log
    ptfhost.lineinfile(
        path="/etc/default/tacacs+",
        line="DAEMON_OPTS=\"-d 2058 -l /var/log/tac_plus.log -C /etc/tacacs+/tac_plus.conf\"",
        regexp='^DAEMON_OPTS=.*'
    )
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


def remove_all_tacacs_server(duthost):
    # use grep command to extract tacacs server address from tacacs config
    find_server_command = 'show tacacs | grep -Po "TACPLUS_SERVER address \K.*"'    # noqa W605
    server_list = duthost.shell(find_server_command, module_ignore_errors=True)['stdout_lines']
    for tacacs_server in server_list:
        tacacs_server = tacacs_server.rstrip()
        if tacacs_server:
            duthost.shell("sudo config tacacs delete %s" % tacacs_server)


def check_server_received(ptfhost, data, timeout=30):
    """
        Check if tacacs server received the data.
    """
    hex = binascii.hexlify(data.encode('ascii'))
    hex_string = hex.decode()

    """
      Extract received data from tac_plus.log, then use grep to check if the received data contains hex_string:
            1. tac_plus server start with '-d 2058' parameter to log received data in following format in tac_plus.log:
                    Thu Mar  9 06:26:16 2023 [75483]: data[140] = 0xf8, xor'ed with hash[12] = 0xab -> 0x53
                    Thu Mar  9 06:26:16 2023 [75483]: data[141] = 0x8d, xor'ed with hash[13] = 0xc2 -> 0x4f
                In above log, the 'data[140] = 0xf8' is received data.

            2. Following sed command will extract the received data from tac_plus.log:
                    sed -n 's/.*-> 0x\(..\).*/\\1/p'  /var/log/tac_plus.log     # noqa W605

            3. Following set command will join all received data to hex string:
                    sed ':a; N; $!ba; s/\\n//g'

            4. Then the grep command will check if the received hex data containes expected hex string.
                    grep '{0}'".format(hex_string)

      Also suppress following Flake8 error/warning:
            W605 : Invalid escape sequence. Flake8 can't handle sed command escape sequence, so will report false alert.
            E501 : Line too long. Following sed command difficult to split to multiple line.
    """
    sed_command = "sed -n 's/.*-> 0x\(..\).*/\\1/p'  /var/log/tac_plus.log | sed ':a; N; $!ba; s/\\n//g' | grep '{0}'".format(hex_string)   # noqa W605 E501

    # After tacplus service receive data, it need take some time to update to log file.
    def log_exist(ptfhost, sed_command):
        res = ptfhost.shell(sed_command)
        logger.info(sed_command)
        logger.info(res["stdout_lines"])
        return len(res["stdout_lines"]) > 0

    exist = wait_until(timeout, 1, 0, log_exist, ptfhost, sed_command)
    pytest_assert(exist, "Not found data: {} in tacplus server log".format(data))


def get_auditd_config_reload_timestamp(duthost):
    res = duthost.shell("sudo journalctl -u auditd --boot | grep 'audisp-tacplus re-initializing configuration'")
    logger.info("aaa config file timestamp {}".format(res["stdout_lines"]))

    if len(res["stdout_lines"]) == 0:
        return ""

    return res["stdout_lines"][-1]


def change_and_wait_aaa_config_update(duthost, command, last_timestamp=None, timeout=10):
    if not last_timestamp:
        last_timestamp = get_auditd_config_reload_timestamp(duthost)

    duthost.shell(command)

    # After AAA config update, hostcfgd will modify config file and notify auditd reload config
    # Wait auditd reload config finish
    def log_exist(duthost):
        latest_timestamp = get_auditd_config_reload_timestamp(duthost)
        return latest_timestamp != last_timestamp

    exist = wait_until(timeout, 1, 0, log_exist, duthost)
    pytest_assert(exist, "Not found aaa config update log: {}".format(command))

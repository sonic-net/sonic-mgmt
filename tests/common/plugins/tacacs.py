import pytest
import crypt
import logging

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def check_all_services_status(ptfhost):
    res = ptfhost.command("service --status-all")
    logger.info(res["stdout_lines"])


def start_tacacs_server(ptfhost):
    ptfhost.command("service tacacs_plus restart", module_ignore_errors=True)
    return "tacacs+ running" in ptfhost.command("service tacacs_plus status", module_ignore_errors=True)["stdout_lines"]


def setup_tacacs_client(duthost, creds, tacacs_server_ip):
    """setup tacacs client"""

    # configure tacacs client
    duthost.shell("sudo config tacacs passkey %s" % creds['tacacs_passkey'])

    # get default tacacs servers
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for tacacs_server in config_facts.get('TACPLUS_SERVER', {}):
        duthost.shell("sudo config tacacs delete %s" % tacacs_server)
    duthost.shell("sudo config tacacs add %s" % tacacs_server_ip)
    duthost.shell("sudo config tacacs authtype login")

    # enable tacacs+
    duthost.shell("sudo config aaa authentication login tacacs+")


def setup_tacacs_server(ptfhost, creds):
    """setup tacacs server"""

    # configure tacacs server
    extra_vars = {'tacacs_passkey': creds['tacacs_passkey'],
                  'tacacs_rw_user': creds['tacacs_rw_user'],
                  'tacacs_rw_user_passwd': crypt.crypt(creds['tacacs_rw_user_passwd'], 'abc'),
                  'tacacs_ro_user': creds['tacacs_ro_user'],
                  'tacacs_ro_user_passwd': crypt.crypt(creds['tacacs_ro_user_passwd'], 'abc'),
                  'tacacs_jit_user': creds['tacacs_jit_user'],
                  'tacacs_jit_user_passwd': crypt.crypt(creds['tacacs_jit_user_passwd'], 'abc'),
                  'tacacs_jit_user_membership': creds['tacacs_jit_user_membership']}

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src="tacacs/tac_plus.conf.j2", dest="/etc/tacacs+/tac_plus.conf")
    ptfhost.lineinfile(path="/etc/default/tacacs+", line="DAEMON_OPTS=\"-d 10 -l /var/log/tac_plus.log -C /etc/tacacs+/tac_plus.conf\"", regexp='^DAEMON_OPTS=.*')
    check_all_services_status(ptfhost)

    # FIXME: This is a short term mitigation, we need to figure out why the tacacs+ server does not start
    # reliably all of a sudden.
    wait_until(5, 1, start_tacacs_server, ptfhost)
    check_all_services_status(ptfhost)


def cleanup_tacacs(ptfhost, duthost, tacacs_server_ip):
    # stop tacacs server
    ptfhost.service(name="tacacs_plus", state="stopped")
    check_all_services_status(ptfhost)

    # reset tacacs client configuration
    duthost.shell("sudo config tacacs delete %s" % tacacs_server_ip)
    duthost.shell("sudo config tacacs default passkey")
    duthost.shell("sudo config aaa authentication login default")
    duthost.shell("sudo config aaa authentication failthrough default")


@pytest.fixture(scope="module")
def test_tacacs(ptfhost, duthosts, rand_one_dut_hostname, creds):
    duthost = duthosts[rand_one_dut_hostname]
    tacacs_server_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    setup_tacacs_client(duthost, creds, tacacs_server_ip)
    setup_tacacs_server(ptfhost, creds)

    yield

    cleanup_tacacs(ptfhost, duthost, tacacs_server_ip)


@pytest.fixture(scope="module")
def test_tacacs_v6(ptfhost, duthosts, rand_one_dut_hostname, creds):
    duthost = duthosts[rand_one_dut_hostname]
    ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
    if 'ansible_hostv6' not in ptfhost_vars:
        pytest.skip("Skip IPv6 test. ptf ansible_hostv6 not configured.")
    tacacs_server_ip = ptfhost_vars['ansible_hostv6']
    setup_tacacs_client(duthost, creds, tacacs_server_ip)
    setup_tacacs_server(ptfhost, creds)

    yield

    cleanup_tacacs(ptfhost, duthost, tacacs_server_ip)

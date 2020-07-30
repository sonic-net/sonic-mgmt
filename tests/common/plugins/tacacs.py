import pytest
import crypt

def configure_tacacs(ptfhost, duthost, creds, tacacs_server_ip, external_tacacs_info):
    """setup tacacs client and server"""

    # disable tacacs server
    ptfhost.service(name="tacacs_plus", state="stopped")

    # configure tacacs client
    duthost.shell("sudo config tacacs passkey %s" % creds['tacacs_passkey'])

    # get default tacacs servers
    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for tacacs_server in config_facts.get('TACPLUS_SERVER', {}):
        duthost.shell("sudo config tacacs delete %s" % tacacs_server)
    duthost.shell("sudo config tacacs add %s" % tacacs_server_ip)
    duthost.shell("sudo config tacacs authtype login")

    # option to connect with an external tacacs server
    if external_tacacs_info['local_username']:
        duthost.shell("sudo config tacacs add %s" % creds['tacacs_servers'][0])
        duthost.shell("sudo config tacacs authtype pap")
        duthost.shell("sudo useradd {} --password {}".format(external_tacacs_info['local_username'], external_tacacs_info['local_password']), module_ignore_errors=True)

    # enable tacacs+
    duthost.shell("sudo config aaa authentication login tacacs+")

    # configure tacacs server
    extra_vars = {'tacacs_passkey': creds['tacacs_passkey'],
                  'tacacs_rw_user': creds['tacacs_rw_user'],
                  'tacacs_rw_user_passwd': crypt.crypt(creds['tacacs_rw_user_passwd'], 'abc'),
                  'tacacs_ro_user': creds['tacacs_ro_user'],
                  'tacacs_ro_user_passwd': crypt.crypt(creds['tacacs_ro_user_passwd'], 'abc')}

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src="tacacs/tac_plus.conf.j2", dest="/etc/tacacs+/tac_plus.conf")

    # start tacacs server
    ptfhost.service(name="tacacs_plus", state="started")


def cleanup_tacacs(ptfhost, duthost, tacacs_server_ip, external_tacacs_info, creds):
    # stop tacacs server
    ptfhost.service(name="tacacs_plus", state="stopped")

    # reset tacacs client configuration
    if external_tacacs_info['local_username']:
        duthost.shell("sudo config tacacs delete %s" % creds['tacacs_servers'][0], module_ignore_errors=True)
        duthost.shell("sudo userdel %s" % external_tacacs_info['local_username'], module_ignore_errors=True)
    duthost.shell("sudo config tacacs delete %s" % tacacs_server_ip)
    duthost.shell("sudo config tacacs default passkey")
    duthost.shell("sudo config aaa authentication login default")
    duthost.shell("sudo config aaa authentication failthrough default")


def get_external_tacacs_info(request, creds):
    local_username=None
    local_password=None
    if request.config.getoption("--switch_tacacs_config"):
        local_password = request.config.getoption("--local_password")
        user_type = request.config.getoption("--local_username")
        if user_type == 'rw':
            local_username = creds['tacacs_rw_user']
        else:
            local_username = creds['tacacs_ro_user']

    return {
        'local_username' : local_username,
        'local_password' : local_password
    }


@pytest.fixture(scope="module")
def test_tacacs(request, ptfhost, duthost, creds):
    tacacs_server_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    external_tacacs_info = get_external_tacacs_info(request, creds)

    configure_tacacs(ptfhost, duthost, creds, tacacs_server_ip, external_tacacs_info)

    yield

    cleanup_tacacs(ptfhost, duthost, tacacs_server_ip, external_tacacs_info, creds)


@pytest.fixture(scope="module")
def test_tacacs_v6(request, ptfhost, duthost, creds):
    ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
    if 'ansible_hostv6' not in ptfhost_vars:
        pytest.skip("Skip IPv6 test. ptf ansible_hostv6 not configured.")
    external_tacacs_info = get_external_tacacs_info(request, creds)

    tacacs_server_ip = ptfhost_vars['ansible_hostv6']
    configure_tacacs(ptfhost, duthost, creds, tacacs_server_ip, external_tacacs_info)

    yield

    cleanup_tacacs(ptfhost, duthost, tacacs_server_ip, external_tacacs_info, creds)

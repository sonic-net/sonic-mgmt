import pytest
import crypt
from ansible_host import AnsibleHost

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

def test_rw_user(ptfhost, duthost, creds):
    """test tacacs rw user
    """

    # disable tacacs server
    ptfhost.shell("service tacacs_plus stop")

    # configure tacacs client
    duthost.shell("sudo config tacacs passkey %s" % creds['tacacs_passkey'])
   
    # get default tacacs servers
    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for tacacs_server in config_facts.get('TACPLUS_SERVER', {}):
        duthost.shell("sudo config tacacs delete %s" % tacacs_server)

    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    duthost.shell("sudo config tacacs add %s" % ptfip)
    duthost.shell("sudo config tacacs authtype login")

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
    ptfhost.shell("service tacacs_plus start")

    try:
        duthost.host.options['variable_manager'].extra_vars.update(
            {'ansible_user':creds['tacacs_rw_user'], 'ansible_password':creds['tacacs_rw_user_passwd']})

        res = duthost.shell("cat /etc/passwd")

        for l in res['stdout_lines']:
            fds = l.split(':')
            if fds[0] == "testadmin":
                assert fds[4] == "remote_user_su"
    finally:
        ptfhost.shell("service tacacs_plus stop")

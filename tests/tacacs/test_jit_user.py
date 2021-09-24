import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.tacacs import setup_tacacs_server
from .test_ro_user import ssh_remote_run
from .utils import check_output

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

def test_jit_user(localhost, duthosts, ptfhost, enum_rand_one_per_hwsku_hostname, creds_all_duts, test_tacacs):
    """check jit user. netuser -> netadmin -> netuser"""

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_jit_user'], creds_all_duts[duthost]['tacacs_jit_user_passwd'], 'cat /etc/passwd')
    
    check_output(res, 'test', 'remote_user')

    # change jit user to netadmin
    creds_all_duts[duthost]['tacacs_jit_user_membership'] = 'netadmin'
    setup_tacacs_server(ptfhost, creds_all_duts, duthost)

    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_jit_user'],
                         creds_all_duts[duthost]['tacacs_jit_user_passwd'], 'cat /etc/passwd')

    check_output(res, 'testadmin', 'remote_user_su')

    # change jit user back to netuser
    creds_all_duts[duthost]['tacacs_jit_user_membership'] = 'netuser'
    setup_tacacs_server(ptfhost, creds_all_duts, duthost)

    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_jit_user'],
                         creds_all_duts[duthost]['tacacs_jit_user_passwd'], 'cat /etc/passwd')
    check_output(res, 'test', 'remote_user')
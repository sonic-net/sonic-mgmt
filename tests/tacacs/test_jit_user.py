import logging
import pytest
from .test_ro_user import ssh_remote_run
from tests.common.helpers.tacacs_helper import setup_tacacs_server
from tests.common.utilities import check_output

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


def test_jit_user(localhost, duthosts, ptfhost, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs):
    """check jit user. netuser -> netadmin -> netuser"""

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    res = ssh_remote_run(localhost, dutip, tacacs_creds['tacacs_jit_user'],
                         tacacs_creds['tacacs_jit_user_passwd'], 'cat /etc/passwd')

    check_output(res, 'test', 'remote_user')

    # change jit user to netadmin
    tacacs_creds['tacacs_jit_user_membership'] = 'netadmin'
    setup_tacacs_server(ptfhost, tacacs_creds, duthost)

    res = ssh_remote_run(localhost, dutip, tacacs_creds['tacacs_jit_user'],
                         tacacs_creds['tacacs_jit_user_passwd'], 'cat /etc/passwd')

    check_output(res, 'testadmin', 'remote_user_su')

    # change jit user back to netuser
    tacacs_creds['tacacs_jit_user_membership'] = 'netuser'
    setup_tacacs_server(ptfhost, tacacs_creds, duthost)

    res = ssh_remote_run(localhost, dutip, tacacs_creds['tacacs_jit_user'],
                         tacacs_creds['tacacs_jit_user_passwd'], 'cat /etc/passwd')
    check_output(res, 'test', 'remote_user')

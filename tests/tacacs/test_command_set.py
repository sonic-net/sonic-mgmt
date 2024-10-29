import logging
import pytest
import paramiko
import time

from tests.common.helpers.assertions import pytest_assert
from tests.tacacs.test_authorization import setup_authorization_tacacs, ssh_run_command
from tests.common.utilities import skip_release, wait_until
from tests.common.helpers.tacacs.tacacs_helper import generate_commands_from_commandset_config
from tests.tacacs.utils import ssh_connect_remote_retry

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

TIMEOUT_LIMIT = 120


@pytest.fixture
def ro_authorization_user_client(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    with ssh_connect_remote_retry(
        dutip,
        tacacs_creds['tacacs_ro_authorization_user'],
        tacacs_creds['tacacs_ro_authorization_user_passwd'],
        duthost
    ) as ssh_client:
        yield ssh_client


def test_command_set_config(
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            setup_authorization_tacacs,
                            tacacs_creds,
                            check_tacacs,
                            ro_authorization_user_client):


    # check commands used by scripts
    commands = generate_commands_from_commandset_config()
    logger.debug("commands: {}".format(commands))

    failed_commands = []
    for subcommand in commands:
        exit_code, stdout, stderr = ssh_run_command(ro_authorization_user_client, subcommand)
        stdout_str = ",".join(stdout.readlines())
        log_message = "Command:{}\nexit_code:{}\nstdout:{}\nstderr:{}".format(subcommand, exit_code, stdout_str, stderr.readlines())

        if 'authorize failed by TACACS+ with given arguments' in stdout_str:
            failed_commands.append(log_message)

    pytest_assert(len(failed_commands) == 0, "Commands failed: {}".format(failed_commands))
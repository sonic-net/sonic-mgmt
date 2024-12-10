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


def test_command_set_config(
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            ptfhost,
                            setup_authorization_tacacs,
                            tacacs_creds,
                            check_tacacs):

    # dump config for debug
    res = ptfhost.command('cat /etc/tacacs+/tac_plus.conf')
    logger.warning("/etc/tacacs+/tac_plus.conf: {}".format(res["stdout_lines"]))

    # create SSH client
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    ssh_client = ssh_connect_remote_retry(
                                        dutip,
                                        tacacs_creds['tacacs_ro_authorization_user'],
                                        tacacs_creds['tacacs_ro_authorization_user_passwd'],
                                        duthost
                                    )

    # check commands used by scripts
    commands = generate_commands_from_commandset_config()
    logger.debug("commands: {}".format(commands))

    failed_commands = []
    for subcommand in commands:
        # cleanup syslog to speed up test
        if "/var/log/syslog" in subcommand:
            duthost.shell("sudo truncate -s 0 /var/log/syslog") 
            duthost.shell("sudo truncate -s 0 /var/log/syslog.1") 

        # provide input for sort command
        if subcommand.startswith("/usr/bin/sort") or \
            subcommand.startswith("/usr/bin/uniq"):
                subcommand = "echo test | " + subcommand

        # truncate log for debug later
        ptfhost.command(r'truncate -s 0  /var/log/tac_plus.log')

        logger.debug("Command start: '{}'".format(subcommand))
        exit_code, stdout, stderr = ssh_run_command(ssh_client, subcommand)
        stdout_str = ",".join(stdout.readlines())
        log_message = "Command:{}\nexit_code:{}\nstdout:{}\nstderr:{}".format(subcommand, exit_code, stdout_str, stderr.readlines())

        if 'authorize failed by TACACS+ with given arguments' in stdout_str:
            logger.debug("Command failed: '{}'".format(log_message))
            failed_commands.append(log_message)

            # dump log for debug
            res = ptfhost.command('cat /var/log/tac_plus.log')
            logger.debug("/var/log/tac_plus.log: {}".format(res["stdout_lines"]))

        # run command to keep duthost connection alive
        logger.debug("Command end: '{}'".format(subcommand))
        duthost.shell("echo keepalive")

    pytest_assert(len(failed_commands) == 0, "Commands failed: {}".format(failed_commands))

import pytest
import logging
import json

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.pretest,
    pytest.mark.topology('util')
]

def test_cleanup_testbed(duthost, request, ptfhost):
    deep_clean = request.config.getoption("--deep_clean")
    if deep_clean:
        logger.info("Deep cleaning DUT {}".format(duthost.hostname))
        # Remove old log files.
        duthost.shell("sudo find /var/log/ -name '*.gz' | xargs sudo rm -f", executable="/bin/bash")
        # Remove old core files.
        duthost.shell("sudo rm -f /var/core/*", executable="/bin/bash")
        # Remove old dump files.
        duthost.shell("sudo rm -rf /var/dump/*", executable="/bin/bash")

    # Cleanup rsyslog configuration file that might have damaged by test_syslog.py
    if ptfhost:
        ptfhost.shell("if [[ -f /etc/rsyslog.conf ]]; then mv /etc/rsyslog.conf /etc/rsyslog.conf.orig; uniq /etc/rsyslog.conf.orig > /etc/rsyslog.conf; fi", executable="/bin/bash")

def test_disable_container_autorestart(duthost, request):
    command_output = duthost.shell("show feature autorestart", module_ignore_errors=True)
    if command_output['rc'] != 0:
        logging.info("Feature autorestart utility not supported. Error: {}".format(command_output['stderr']))
        logging.info("Skipping disable_container_autorestart fixture")
        return
    container_autorestart_states = duthost.get_container_autorestart_states()
    state_file_name = "/tmp/autorestart_state_{}.json".format(duthost.hostname)
    # Dump autorestart state to file
    with open(state_file_name, "w") as f:
        json.dump(container_autorestart_states, f)
    # Disable autorestart for all containers
    logging.info("Disable container autorestart")
    cmd_disable = "config feature autorestart {} disabled"
    cmds_disable = []
    for name, state in container_autorestart_states.items():
        if state == "enabled":
            cmds_disable.append(cmd_disable.format(name))
    # Write into config_db
    cmds_disable.append("config save -y")
    duthost.shell_cmds(cmds=cmds_disable)



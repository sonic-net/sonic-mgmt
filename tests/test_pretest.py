import pytest
import logging
import json
import time

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.pretest,
    pytest.mark.topology('util'),
    pytest.mark.disable_loganalyzer
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

def test_disable_container_autorestart(duthost):
    command_output = duthost.shell("show feature autorestart", module_ignore_errors=True)
    if command_output['rc'] != 0:
        logging.info("Feature autorestart utility not supported. Error: {}".format(command_output['stderr']))
        logging.info("Skipping disable_container_autorestart")
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
    # Wait sometime for snmp reloading
    SNMP_RELOADING_TIME = 30
    time.sleep(SNMP_RELOADING_TIME)

def test_disable_rsyslog_rate_limit(duthost):
    features_dict, succeed = duthost.get_feature_status()
    if not succeed:
        # Something unexpected happened.
        # We don't want to fail here because it's an util
        logging.warn("Failed to retrieve feature status")
        return
    cmd_disable_rate_limit = r"docker exec -i {} sed -i 's/^\$SystemLogRateLimit/#\$SystemLogRateLimit/g' /etc/rsyslog.conf"
    cmd_reload = r"docker exec -i {} supervisorctl restart rsyslogd"
    for feature_name, state in features_dict.items():
        if state == "disabled":
            continue
        cmds = []
        cmds.append(cmd_disable_rate_limit.format(feature_name))
        cmds.append(cmd_reload.format(feature_name))
        duthost.shell_cmds(cmds=cmds)


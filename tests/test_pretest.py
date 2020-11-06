import pytest
import logging
import json
import time
import os

from common.helpers.assertions import pytest_require

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.pretest,
    pytest.mark.topology('util'),
    pytest.mark.disable_loganalyzer
]

def test_cleanup_testbed(duthosts, dut_hostname, request, ptfhost):
    duthost = duthosts[dut_hostname]
    deep_clean = request.config.getoption("--deep_clean")
    if deep_clean:
        logger.info("Deep cleaning DUT {}".format(duthost.hostname))
        # Remove old log files.
        duthost.shell("sudo find /var/log/ -name '*.gz' | sudo xargs rm -f", executable="/bin/bash")
        # Remove old core files.
        duthost.shell("sudo rm -f /var/core/*", executable="/bin/bash")
        # Remove old dump files.
        duthost.shell("sudo rm -rf /var/dump/*", executable="/bin/bash")

    # Cleanup rsyslog configuration file that might have damaged by test_syslog.py
    if ptfhost:
        ptfhost.shell("if [[ -f /etc/rsyslog.conf ]]; then mv /etc/rsyslog.conf /etc/rsyslog.conf.orig; uniq /etc/rsyslog.conf.orig > /etc/rsyslog.conf; fi", executable="/bin/bash")

def test_disable_container_autorestart(duthosts, dut_hostname):
    duthost = duthosts[dut_hostname]
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


def collect_dut_info(dut):
    status = dut.show_interface(command='status')['ansible_facts']['int_status']
    return { 'intf_status' : status }


def test_update_testbed_metadata(duthosts, tbinfo):
    metadata = {}
    tbname = tbinfo['conf-name']
    pytest_require(tbname, "skip test due to lack of testbed name.")

    for dut in duthosts:
        dutinfo = collect_dut_info(dut)
        metadata[dut.hostname] = dutinfo

    info = { tbname : metadata }
    folder = 'metadata'
    filepath = os.path.join(folder, tbname + '.json')
    try:
        if not os.path.exists(folder):
            os.mkdir(folder)
        with open(filepath, 'w') as yf:
            json.dump(info, yf, indent=4)
    except IOError as e:
        logger.warning('Unable to create file {}: {}'.format(filepath, e))


def test_disable_rsyslog_rate_limit(duthosts, dut_hostname):
    duthost = duthosts[dut_hostname]
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


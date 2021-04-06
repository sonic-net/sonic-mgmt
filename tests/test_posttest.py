import pytest
import logging
import time

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.posttest,
    pytest.mark.topology('util'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]


def test_collect_techsupport(duthosts, enum_dut_hostname):
    duthost = duthosts[enum_dut_hostname]
    """
    A util for collecting techsupport after tests.

    Since nightly test on Jenkins will do a cleanup at the beginning of tests,
    we need a method to save history logs and dumps. This util does the job.
    """
    logger.info("Collecting techsupport since yesterday")
    # Because Jenkins is configured to save artifacts from tests/logs,
    # and this util is mainly designed for running on Jenkins,
    # save path is fixed to logs for now.
    TECHSUPPORT_SAVE_PATH = 'logs/'
    out = duthost.command("generate_dump -s yesterday", module_ignore_errors=True)
    if out['rc'] == 0:
        tar_file = out['stdout_lines'][-1]
        duthost.fetch(src=tar_file, dest=TECHSUPPORT_SAVE_PATH, flat=True)

    assert True


def test_restore_container_autorestart(duthosts, enum_dut_hostname, enable_container_autorestart):
    duthost = duthosts[enum_dut_hostname]
    enable_container_autorestart(duthost)
    # Wait sometime for snmp reloading
    SNMP_RELOADING_TIME = 30
    time.sleep(SNMP_RELOADING_TIME)

def test_recover_rsyslog_rate_limit(duthosts, enum_dut_hostname):
    duthost = duthosts[enum_dut_hostname]
    features_dict, succeed = duthost.get_feature_status()
    if not succeed:
        # Something unexpected happened.
        # We don't want to fail here because it's an util
        logging.warn("Failed to retrieve feature status")
        return
    cmd_enable_rate_limit = r"docker exec -i {} sed -i 's/^#\$SystemLogRateLimit/\$SystemLogRateLimit/g' /etc/rsyslog.conf"
    cmd_reload = r"docker exec -i {} supervisorctl restart rsyslogd"
    for feature_name, state in features_dict.items():
        if 'enabled' not in state:
            continue
        cmds = []
        cmds.append(cmd_enable_rate_limit.format(feature_name))
        cmds.append(cmd_reload.format(feature_name))
        duthost.shell_cmds(cmds=cmds)


import os
import pytest
import logging
import time
from tests.common import utilities
from tests.common.helpers.assertions import pytest_require

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.posttest,
    pytest.mark.topology('util', 'any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


def test_restore_container_autorestart(duthosts, enum_dut_hostname, enable_container_autorestart):
    duthost = duthosts[enum_dut_hostname]
    enable_container_autorestart(duthost)
    # Wait sometime for snmp reloading
    SNMP_RELOADING_TIME = 30
    time.sleep(SNMP_RELOADING_TIME)


def test_recover_rsyslog_rate_limit(duthosts, enum_dut_hostname):
    duthost = duthosts[enum_dut_hostname]
    # We don't need to recover the rate limit on vs testbed
    pytest_require(duthost.facts['asic_type'] != 'vs', "Skip on vs testbed")
    features_dict, succeed = duthost.get_feature_status()
    if not succeed:
        # Something unexpected happened.
        # We don't want to fail here because it's an util
        logging.warning("Failed to retrieve feature status")
        return
    for feature_name, state in list(features_dict.items()):
        if 'enabled' not in state:
            continue
        if feature_name == "telemetry":
            # Skip telemetry if there's no docker image
            output = duthost.shell("docker images", module_ignore_errors=True)['stdout']
            if "sonic-telemetry" not in output:
                continue
        if feature_name == "frr_bmp":
            # Skip frr_bmp since it's not container just bmp option used by bgpd
            continue
        duthost.modify_syslog_rate_limit(feature_name, rl_option='enable')


def test_enable_startup_tsa_tsb_service(duthosts, localhost):
    """enable startup-tsa-tsb.service.
    Args:
        duthosts: Fixture returns a list of Ansible object DuT.
        enum_frontend_dut_hostname: Fixture returns name of frontend DuT.

    Returns:
        None.
    """
    for duthost in duthosts.frontend_nodes:
        platform = duthost.facts['platform']
        startup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/startup-tsa-tsb.conf".format(platform)
        backup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/backup-startup-tsa-tsb.bck".format(platform)
        file_check = duthost.shell("[ -f {} ]".format(backup_tsa_tsb_file_path), module_ignore_errors=True)
        if file_check.get('rc') == 0:
            out = duthost.shell("cat {}".format(backup_tsa_tsb_file_path), module_ignore_errors=True)['rc']
            if not out:
                duthost.shell("sudo mv {} {}".format(backup_tsa_tsb_file_path, startup_tsa_tsb_file_path))
        else:
            logger.info("{} file does not exist in the specified path on dut {}".
                        format(backup_tsa_tsb_file_path, duthost.hostname))


def test_collect_ptf_logs(ptfhost):
    if ptfhost is None:
        return
    log_files = ptfhost.shell('ls /tmp/*.log')['stdout'].split()
    if not os.path.exists('logs/ptf'):
        os.makedirs('logs/ptf')
    for log_file in log_files:
        ptfhost.fetch(src=log_file, dest='logs/ptf', fail_on_missing=False)


def test_collect_dualtor_logs(request, vmhost, tbinfo, active_active_ports, active_standby_ports):
    """
    Collect mux/nic simulator logs after test to local logs/server folder.
    """
    if 'dualtor' not in tbinfo['topo']['name']:
        return
    if not os.path.exists("logs/server"):
        os.makedirs("logs/server")

    log_name = None
    if active_standby_ports:
        server = tbinfo['server']
        tbname = tbinfo['conf-name']
        inv_files = utilities.get_inventory_files(request)
        http_port = utilities.get_group_visible_vars(inv_files, server).get('mux_simulator_http_port')[tbname]
        log_name = '/tmp/mux_simulator_{}.log*'.format(http_port)
    elif active_active_ports:
        vm_set = tbinfo['group-name']
        log_name = "/tmp/nic_simulator_{}.log*".format(vm_set)

    if log_name:
        log_files = vmhost.shell('ls {}'.format(log_name))['stdout'].split()
        for log_file in log_files:
            vmhost.fetch(src=log_file, dest="logs/server", fail_on_missing=False)
            vmhost.shell("rm -f {}".format(log_file))

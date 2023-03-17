import json
import logging
import os
import pytest
import random
import time
from tests.common.helpers.port_utils import get_common_supported_speeds

from collections import defaultdict

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_utils import verify_features_state
from tests.common.utilities import wait_until
from tests.common.reboot import reboot
from tests.common.platform.processes_utils import wait_critical_processes

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.pretest,
    pytest.mark.topology('util'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


FEATURE_STATE_VERIFYING_THRESHOLD_SECS = 600
FEATURE_STATE_VERIFYING_INTERVAL_SECS = 10


def test_features_state(duthosts, enum_dut_hostname, localhost):
    """Checks whether the state of each feature is valid or not.
    Args:
      duthosts: Fixture returns a list of Ansible object DuT.
      enum_dut_hostname: Fixture returns name of DuT.

    Returns:
      None.
    """
    duthost = duthosts[enum_dut_hostname]
    logger.info("Checking the state of each feature in 'CONFIG_DB' ...")
    if not wait_until(180, FEATURE_STATE_VERIFYING_INTERVAL_SECS, 0, verify_features_state, duthost):
        logger.warn("Not all states of features in 'CONFIG_DB' are valid, rebooting DUT {}".format(duthost.hostname))
        reboot(duthost, localhost)
        # Some services are not ready immeidately after reboot
        wait_critical_processes(duthost)

    pytest_assert(wait_until(FEATURE_STATE_VERIFYING_THRESHOLD_SECS, FEATURE_STATE_VERIFYING_INTERVAL_SECS, 0,
                             verify_features_state, duthost), "Not all service states are valid!")
    logger.info("The states of features in 'CONFIG_DB' are all valid.")


def test_cleanup_cache():
    folder = '_cache'
    if os.path.exists(folder):
        os.system('rm -rf {}'.format(folder))


def test_cleanup_testbed(duthosts, enum_dut_hostname, request, ptfhost):
    duthost = duthosts[enum_dut_hostname]
    deep_clean = request.config.getoption("--deep_clean")
    if deep_clean:
        logger.info("Deep cleaning DUT {}".format(duthost.hostname))
        # Remove old log files.
        duthost.shell("sudo find /var/log/ -name '*.gz' | sudo xargs rm -f", executable="/bin/bash")
        # Remove old core files.
        duthost.shell("sudo rm -f /var/core/*", executable="/bin/bash")
        # Remove old dump files.
        duthost.shell("sudo rm -rf /var/dump/*", executable="/bin/bash")

        # delete other log files that are more than a day old,
        # this step is needed to remove some backup files or the debug files added by users
        # which can create issue for log-analyzer
        duthost.shell("sudo find /var/log/ -mtime +1 | sudo xargs rm -f",
                      module_ignore_errors=True, executable="/bin/bash")

    # Cleanup rsyslog configuration file that might have damaged by test_syslog.py
    if ptfhost:
        ptfhost.shell("if [[ -f /etc/rsyslog.conf ]]; then mv /etc/rsyslog.conf /etc/rsyslog.conf.orig; "
                      "uniq /etc/rsyslog.conf.orig > /etc/rsyslog.conf; fi", executable="/bin/bash")


def test_disable_container_autorestart(duthosts, enum_dut_hostname, disable_container_autorestart):
    duthost = duthosts[enum_dut_hostname]
    disable_container_autorestart(duthost)
    # Wait sometime for snmp reloading
    SNMP_RELOADING_TIME = 30
    time.sleep(SNMP_RELOADING_TIME)


def collect_dut_info(dut):
    status = dut.show_interface(command='status')['ansible_facts']['int_status']
    features, _ = dut.get_feature_status()

    if dut.sonichost.is_multi_asic:
        front_end_asics = dut.get_frontend_asic_ids()
        back_end_asics = dut.get_backend_asic_ids()

    asic_services = defaultdict(list)
    for service in dut.sonichost.DEFAULT_ASIC_SERVICES:
        # for multi ASIC randomly select one frontend ASIC
        # and one backend ASIC
        if dut.sonichost.is_multi_asic:
            asic_services[service] = []
            if len(front_end_asics):
                fe = random.choice(front_end_asics)
                asic_services[service].append(dut.get_docker_name(service, asic_index=fe))
            if len(back_end_asics):
                be = random.choice(back_end_asics)
                asic_services[service].append(dut.get_docker_name(service, asic_index=be))

    dut_info = {
        "intf_status": status,
        "features": features,
        "asic_services": asic_services,
    }

    if dut.sonichost.is_multi_asic:
        dut_info.update(
            {
                "frontend_asics": front_end_asics,
                "backend_asics": back_end_asics
            }
        )

    return dut_info


def test_update_testbed_metadata(duthosts, tbinfo, fanouthosts):
    metadata = {}
    tbname = tbinfo['conf-name']
    pytest_require(tbname, "skip test due to lack of testbed name.")

    for dut in duthosts:
        dutinfo = collect_dut_info(dut)
        metadata[dut.hostname] = dutinfo

    info = {tbname: metadata}
    folder = 'metadata'
    filepath = os.path.join(folder, tbname + '.json')
    try:
        if not os.path.exists(folder):
            os.mkdir(folder)
        with open(filepath, 'w') as yf:
            json.dump(info, yf, indent=4)
    except IOError as e:
        logger.warning('Unable to create file {}: {}'.format(filepath, e))

    prepare_autonegtest_params(duthosts, fanouthosts)


def test_disable_rsyslog_rate_limit(duthosts, enum_dut_hostname):
    duthost = duthosts[enum_dut_hostname]
    features_dict, succeed = duthost.get_feature_status()
    if not succeed:
        # Something unexpected happened.
        # We don't want to fail here because it's an util
        logging.warn("Failed to retrieve feature status")
        return
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")
    try:
        is_dhcp_server_enable = config_facts["ansible_facts"]["DEVICE_METADATA"]["localhost"]["dhcp_server"]
    except KeyError:
        is_dhcp_server_enable = None
    for feature_name, state in list(features_dict.items()):
        if 'enabled' not in state:
            continue
        # Skip dhcp_relay check if dhcp_server is enabled
        if is_dhcp_server_enable is not None and "enabled" in is_dhcp_server_enable and feature_name == "dhcp_relay":
            continue
        duthost.modify_syslog_rate_limit(feature_name, rl_option='disable')


def collect_dut_lossless_prio(dut):
    config_facts = dut.config_facts(host=dut.hostname, source="running")['ansible_facts']

    if "PORT_QOS_MAP" not in list(config_facts.keys()):
        return []

    port_qos_map = config_facts["PORT_QOS_MAP"]
    if len(list(port_qos_map.keys())) == 0:
        return []

    """ Here we assume all the ports have the same lossless priorities """
    intf = list(port_qos_map.keys())[0]
    if 'pfc_enable' not in port_qos_map[intf]:
        return []

    result = [int(x) for x in port_qos_map[intf]['pfc_enable'].split(',')]
    return result


def collect_dut_all_prio(dut):
    config_facts = dut.config_facts(host=dut.hostname, source="running")['ansible_facts']

    if "DSCP_TO_TC_MAP" not in list(config_facts.keys()):
        return []

    dscp_to_tc_map_lists = config_facts["DSCP_TO_TC_MAP"]
    if len(dscp_to_tc_map_lists) != 1:
        return []

    profile = list(dscp_to_tc_map_lists.keys())[0]
    dscp_to_tc_map = dscp_to_tc_map_lists[profile]

    tc = [int(p) for p in list(dscp_to_tc_map.values())]
    return list(set(tc))


def collect_dut_lossy_prio(dut):
    lossless_prio = collect_dut_lossless_prio(dut)
    all_prio = collect_dut_all_prio(dut)
    return [p for p in all_prio if p not in lossless_prio]


def collect_dut_pfc_pause_delay_params(dut):
    """
    Retrieves a dictionary of pfc pause delay values for the headroom test
    Args:
        dut (Ansible host instance): device under test
    Returns:
        pfc_pause_delay_test_params: Mapped from pfc pause quanta to whether
                                the headroom test will fail or not
                                E.g. {1:True, 2:False, 3:False}
    """
    platform = dut.facts['platform']
    pfc_pause_delay_test_params = {}
    if 'cisco' and '8102' in platform.lower():
        pfc_pause_delay_test_params[0] = True
        pfc_pause_delay_test_params[1023] = True
    elif 'arista' and '7050cx3' in platform.lower():
        pfc_pause_delay_test_params[0] = True
        pfc_pause_delay_test_params[200] = False
    else:
        pfc_pause_delay_test_params = None
    
    return pfc_pause_delay_test_params


def test_collect_testbed_prio(duthosts, tbinfo):
    all_prio = {}
    lossless_prio = {}
    lossy_prio = {}

    tbname = tbinfo['conf-name']
    pytest_require(tbname, "skip test due to lack of testbed name.")

    for dut in duthosts:
        all_prio[dut.hostname] = collect_dut_all_prio(dut)
        lossless_prio[dut.hostname] = collect_dut_lossless_prio(dut)
        lossy_prio[dut.hostname] = collect_dut_lossy_prio(dut)

    prio_info = [all_prio, lossless_prio, lossy_prio]
    file_names = [tbname + '-' + x + '.json' for x in ['all', 'lossless', 'lossy']]
    folder = 'priority'

    for i in range(len(file_names)):
        filepath = os.path.join(folder, file_names[i])
        try:
            if not os.path.exists(folder):
                os.mkdir(folder)
            with open(filepath, 'w') as yf:
                json.dump({tbname: prio_info[i]}, yf, indent=4)
        except IOError as e:
            logger.warning('Unable to create file {}: {}'.format(filepath, e))


def test_collect_pfc_pause_delay_params(duthosts, tbinfo):
    pfc_pause_delay_params = {}

    tbname = tbinfo['conf-name']
    pytest_require(tbname, "skip test due to lack of testbed name.")

    for dut in duthosts:
        pfc_pause_delay_params_dut = collect_dut_pfc_pause_delay_params(dut)
        if pfc_pause_delay_params_dut is None:
            continue
        else:
            pfc_pause_delay_params[dut.hostname] = pfc_pause_delay_params_dut

    file_name = tbname + '.json'
    folder = 'pfc_headroom_test_params'

    
    filepath = os.path.join(folder, file_name)
    try:
        if not os.path.exists(folder):
            os.mkdir(folder)
        with open(filepath, 'w') as yf:
            json.dump({ tbname : pfc_pause_delay_params}, yf, indent=4)
    except IOError as e:
        logger.warning('Unable to create file {}: {}'.format(filepath, e))


def test_update_saithrift_ptf(request, ptfhost):
    '''
    Install the correct python saithrift package on the ptf
    '''
    py_saithrift_url = request.config.getoption("--py_saithrift_url")
    if not py_saithrift_url:
        pytest.skip("No URL specified for python saithrift package")
    pkg_name = py_saithrift_url.split("/")[-1]
    ptfhost.shell("rm -f {}".format(pkg_name))
    result = ptfhost.get_url(url=py_saithrift_url, dest="/root", module_ignore_errors=True, timeout=60)
    if result["failed"] or "OK" not in result["msg"]:
        pytest.skip("Download failed/error while installing python saithrift package")
    ptfhost.shell("dpkg -i {}".format(os.path.join("/root", pkg_name)))
    logging.info("Python saithrift package installed successfully")


def test_stop_pfcwd(duthosts, enum_dut_hostname, tbinfo):
    '''
     Stop pfcwd on dual tor testbeds
    '''
    dut = duthosts[enum_dut_hostname]
    dut.command('pfcwd stop')


def prepare_autonegtest_params(duthosts, fanouthosts):
    from tests.common.platform.device_utils import list_dut_fanout_connections

    cadidate_test_ports = {}
    max_interfaces_per_dut = 3
    filepath = os.path.join('metadata', 'autoneg-test-params.json')
    try:
        for duthost in duthosts:
            all_ports = list_dut_fanout_connections(duthost, fanouthosts)
            selected_ports = {}
            for dut_port, fanout, fanout_port in all_ports:
                if len(selected_ports) == max_interfaces_per_dut:
                    break
                auto_neg_mode = fanout.get_auto_negotiation_mode(fanout_port)
                if auto_neg_mode is not None:
                    speeds = get_common_supported_speeds(duthost, dut_port, fanout, fanout_port)
                    selected_ports[dut_port] = {
                        'fanout': fanout.hostname,
                        'fanout_port': fanout_port,
                        'common_port_speeds': speeds
                    }
            if len(selected_ports) > 0:
                cadidate_test_ports[duthost.hostname] = selected_ports
        if len(cadidate_test_ports) > 0:
            with open(filepath, 'w') as yf:
                json.dump(cadidate_test_ports, yf, indent=4)
        else:
            logger.warning('skipped to create autoneg test datafile because of no ports selected')
    except Exception as e:
        logger.warning('Unable to create a datafile for autoneg tests: {}. Err: {}'.format(filepath, e))


"""
    Separator for internal pretests.
    Please add public pretest above this comment and keep internal
    pretests below this comment.
"""


# This one is special. It is public, but we need to ensure that it is the last one executed in pre-test.
def test_generate_running_golden_config(duthosts):
    """
    Generate running golden config after pre test.
    """
    for duthost in duthosts:
        duthost.shell("sonic-cfggen -d --print-data > /etc/sonic/running_golden_config.json")
        if duthost.is_multi_asic:
            for asic_index in range(0, duthost.facts.get('num_asic')):
                asic_ns = 'asic{}'.format(asic_index)
                duthost.shell("sonic-cfggen -n {} -d --print-data > /etc/sonic/running_golden_config{}.json".
                              format(asic_ns, asic_index))

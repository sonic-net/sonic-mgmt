import json
import logging
import os
import pytest
import random
import time

from collections import defaultdict

from jinja2 import Template
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
from tests.common.helpers.dut_utils import verify_features_state
from tests.common.utilities import wait_until
from tests.common.reboot import reboot
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import get_host_visible_vars

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.pretest,
    pytest.mark.topology('util'),
    pytest.mark.disable_loganalyzer
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
    if not wait_until(180, FEATURE_STATE_VERIFYING_INTERVAL_SECS, verify_features_state, duthost):
        logger.warn("Not all states of features in 'CONFIG_DB' are valid, rebooting DUT {}".format(duthost.hostname))
        reboot(duthost, localhost)
        # Some services are not ready immeidately after reboot
        wait_critical_processes(duthost)

    pytest_assert(wait_until(FEATURE_STATE_VERIFYING_THRESHOLD_SECS, FEATURE_STATE_VERIFYING_INTERVAL_SECS,
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
        ptfhost.shell("if [[ -f /etc/rsyslog.conf ]]; then mv /etc/rsyslog.conf /etc/rsyslog.conf.orig; uniq /etc/rsyslog.conf.orig > /etc/rsyslog.conf; fi", executable="/bin/bash")


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
            fe = random.choice(front_end_asics)
            be = random.choice(back_end_asics)
            asic_services[service] = [
                dut.get_docker_name(service, asic_index=fe),
                dut.get_docker_name(service, asic_index=be)
            ]

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


def test_disable_rsyslog_rate_limit(duthosts, enum_dut_hostname):
    duthost = duthosts[enum_dut_hostname]
    features_dict, succeed = duthost.get_feature_status()
    if not succeed:
        # Something unexpected happened.
        # We don't want to fail here because it's an util
        logging.warn("Failed to retrieve feature status")
        return
    for feature_name, state in features_dict.items():
        if 'enabled' not in state:
            continue
        duthost.disable_syslog_rate_limit(feature_name)

def collect_dut_lossless_prio(dut):
    config_facts = dut.config_facts(host=dut.hostname, source="running")['ansible_facts']

    if "PORT_QOS_MAP" not in config_facts.keys():
        return []

    port_qos_map = config_facts["PORT_QOS_MAP"]
    if len(port_qos_map.keys()) == 0:
        return []

    """ Here we assume all the ports have the same lossless priorities """
    intf = port_qos_map.keys()[0]
    if 'pfc_enable' not in port_qos_map[intf]:
        return []

    result = [int(x) for x in port_qos_map[intf]['pfc_enable'].split(',')]
    return result

def collect_dut_all_prio(dut):
    config_facts = dut.config_facts(host=dut.hostname, source="running")['ansible_facts']

    if "DSCP_TO_TC_MAP" not in config_facts.keys():
        return []

    dscp_to_tc_map_lists = config_facts["DSCP_TO_TC_MAP"]
    if len(dscp_to_tc_map_lists) != 1:
        return []

    profile = dscp_to_tc_map_lists.keys()[0]
    dscp_to_tc_map = dscp_to_tc_map_lists[profile]

    tc = [int(p) for p in dscp_to_tc_map.values()]
    return list(set(tc))

def collect_dut_lossy_prio(dut):
    lossless_prio = collect_dut_lossless_prio(dut)
    all_prio = collect_dut_all_prio(dut)
    return [p for p in all_prio if p not in lossless_prio]

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
                json.dump({ tbname : prio_info[i]}, yf, indent=4)
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
    result = ptfhost.get_url(url=py_saithrift_url, dest="/root", module_ignore_errors=True)
    if result["failed"] != False or "OK" not in result["msg"]:
        pytest.skip("Download failed/error while installing python saithrift package")
    ptfhost.shell("dpkg -i {}".format(os.path.join("/root", pkg_name)))
    logging.info("Python saithrift package installed successfully")

def test_inject_y_cable_simulator_client(duthosts, enum_dut_hostname, tbinfo, vmhost):
    '''
    Inject the Y cable simulator client to both ToRs in a dualtor testbed
    '''
    if 'dualtor' not in tbinfo['topo']['name']:
        return

    logger.info("Injecting Y cable simulator client to {}".format(enum_dut_hostname))
    dut = duthosts[enum_dut_hostname]
    tbname = tbinfo['conf-name']
    _hostvars = get_host_visible_vars(dut.host.options['inventory'], dut.hostname)
    mux_simulator_port = _hostvars['mux_simulator_http_port'][tbname]
    y_cable_sim_client_template_path = 'templates/y_cable_simulator_client.j2'

    template_args = {
        'duts_map': json.dumps(tbinfo['duts_map'], sort_keys=True, indent=4),
        'mux_simulator_server': vmhost.mgmt_ip,
        'mux_simulator_port': mux_simulator_port,
        'dut_name': enum_dut_hostname,
        'group_name': tbinfo['group-name']
    }

    with open(y_cable_sim_client_template_path) as f:
        template = Template(f.read())

    rendered = template.render(template_args)

    dut.copy(content=rendered, dest='/tmp/y_cable_simulator_client.py')
    dut.shell('cp /tmp/y_cable_simulator_client.py /usr/lib/python3/dist-packages/')
    dut.shell('docker cp /tmp/y_cable_simulator_client.py pmon:/usr/lib/python3/dist-packages/')

    # Below changes are required after these PRs are merged:
    # * https://github.com/Azure/sonic-platform-common/pull/213
    # * https://github.com/Azure/sonic-platform-daemons/pull/197
    # For the simulated y_cable driver to work, basic configuration information of the mux simulator is required.
    # When /etc/sonic/mux_simulator.json file is found on DUT, xcvrd will try to load simulated y_cable driver.
    # File /etc/sonic/mux_simulator.json can co-exist with the 'y_cable_simulator_client.py' file injected above.
    # Process xcvrd will determine which one to load or use.
    mux_simulator_config = {
        'server_ip': vmhost.mgmt_ip,
        'server_port': mux_simulator_port,
        'vm_set': tbinfo['group-name'],
        'side': UPPER_TOR if tbinfo['duts'].index(enum_dut_hostname) == 0 else LOWER_TOR
    }
    dut.copy(content=json.dumps(mux_simulator_config, indent=2), dest='/etc/sonic/mux_simulator.json')

    dut.shell('systemctl restart pmon')

def test_stop_pfcwd(duthosts, enum_dut_hostname, tbinfo):
    '''
     Stop pfcwd on dual tor testbeds
    '''
    if 'dualtor' not in tbinfo['topo']['name']:
        pytest.skip("Skip this test on non dualTOR testbeds")

    dut = duthosts[enum_dut_hostname]
    dut.command('pfcwd stop')

"""
    Separator for internal pretests.
    Please add public pretest above this comment and keep internal
    pretests below this comment.
"""

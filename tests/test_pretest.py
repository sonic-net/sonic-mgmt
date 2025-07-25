import json
import logging
import os
import pytest
import random
import re
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
    pytest.mark.topology('util', 'any'),
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
    asic_type = dut.facts['asic_type']
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
        "asic_type": asic_type
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

    output = duthost.command('config syslog --help')['stdout']
    manually_enable_feature = False
    if 'rate-limit-feature' in output:
        # in 202305, the feature is disabled by default for warmboot/fastboot
        # performance, need manually enable it via command
        duthost.command('config syslog rate-limit-feature enable')
        manually_enable_feature = True
    for feature_name, state in list(features_dict.items()):
        if 'enabled' not in state:
            continue
        # Skip dhcp_relay check if dhcp_server is enabled
        if is_dhcp_server_enable is not None and "enabled" in is_dhcp_server_enable and feature_name == "dhcp_relay":
            continue
        if feature_name == "telemetry":
            # Skip telemetry if there's no docker image
            output = duthost.shell("docker images", module_ignore_errors=True)['stdout']
            if "sonic-telemetry" not in output:
                continue
        duthost.modify_syslog_rate_limit(feature_name, rl_option='disable')
    if manually_enable_feature:
        duthost.command('config syslog rate-limit-feature disable')


def collect_dut_lossless_prio(dut):
    dut_asic = dut.asic_instance()
    config_facts = dut_asic.config_facts(host=dut.hostname, source="running")['ansible_facts']

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
    dut_asic = dut.asic_instance()
    config_facts = dut_asic.config_facts(host=dut.hostname, source="running")['ansible_facts']

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
        pfc_pause_delay_test_params[1023] = True
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
            json.dump({tbname: pfc_pause_delay_params}, yf, indent=4)
    except IOError as e:
        logger.warning('Unable to create file {}: {}'.format(filepath, e))


def test_update_saithrift_ptf(request, ptfhost, duthosts, enum_dut_hostname):
    '''
    Install the correct python saithrift package on the ptf
    '''
    py_saithrift_url = request.config.getoption("--py_saithrift_url")
    if not py_saithrift_url:
        pytest.skip("No URL specified for python saithrift package")

    duthost = duthosts[enum_dut_hostname]
    output = duthost.shell("show version", module_ignore_errors=True)['stdout']
    version_reg = re.compile(r"sonic software version: +([^\s]+)\s", re.IGNORECASE)
    asic_reg = re.compile(r"asic: +([^\s]+)\s", re.IGNORECASE)
    # sample value: SONiC.20240510.33, SONiC.20250505.07, SONiC.internal.129741107-8524154c2d,
    # SONiC.master.882522-695c23859
    version = version_reg.findall(output)[0] if version_reg.search(output) else ""
    # only broadcom, cisco-8000, mellanox support qos sai tests
    asic = asic_reg.findall(output)[0] if asic_reg.search(output) else ""

    if "master" in version:
        branch_name = "master"
    elif "internal" in version:
        branch_name = "internal"
    else:
        # Extract year/month from version string to determine branch
        date_match = re.search(r'(\d{4})(\d{2})', version)
        if date_match:
            year, month = date_match.groups()
            branch_name = f"internal-{year}{month}"
        else:
            pytest.fail("Unable to parse or recognize version format: {}".format(version))

    # Apply special codename overrides for specific internal branches
    if branch_name == "internal-202411":
        # internal-202411 has saithrift URL hardcoded to bullseye
        debian_codename = "bullseye"
    elif (branch_name.startswith("internal-") and branch_name < "internal-202405"):
        # For internal branches older than 202405, use the original URL without modification
        # No need to get debian_codename as URL won't be modified
        debian_codename = None
    else:
        # Get debian codename from syncd container (not host OS)
        # This applies to: master branch and internal branches >= 202405 (except 202411)
        try:
            # Try to get codename from syncd container
            syncd_codename_cmd = ("docker exec syncd grep VERSION_CODENAME /etc/os-release | "
                                  "cut -d= -f2 | tr -d '\"'")
            syncd_codename_result = duthost.shell(syncd_codename_cmd, module_ignore_errors=True)
            if syncd_codename_result['rc'] == 0 and syncd_codename_result['stdout'].strip():
                debian_codename = syncd_codename_result['stdout'].strip()
            else:
                pytest.fail("Failed to get debian codename from syncd container. RC: {}, Output: '{}'".format(
                    syncd_codename_result['rc'], syncd_codename_result['stdout']))
        except Exception as e:
            pytest.fail("Exception while getting debian codename from syncd container: {}".format(str(e)))

    pkg_name = py_saithrift_url.split("/")[-1]
    ip_addr = py_saithrift_url.split("/")[2]
    ptfhost.shell("rm -f {}".format(pkg_name))

    if branch_name.startswith("internal-") and branch_name < "internal-202405":
        # For internal branches older than 202405, use the original URL without modification
        pass
    elif branch_name == "master":
        py_saithrift_url = (f"http://{ip_addr}/mssonic-public-pipelines/"
                            f"Azure.sonic-buildimage.official.{asic}/master/{asic}/"
                            f"latest/target/debs/{debian_codename}/{pkg_name}")
    else:
        # For internal branches newer than 202405 and other branches
        py_saithrift_url = (f"http://{ip_addr}/pipelines/Networking-acs-buildimage-Official/"
                            f"{asic}/{branch_name}/latest/target/debs/{debian_codename}/{pkg_name}")

    # Retry download of saithrift library
    retry_count = 5
    while retry_count > 0:
        result = ptfhost.get_url(url=py_saithrift_url, dest="/root", module_ignore_errors=True, timeout=60)
        if not result["failed"] or "OK" in result["msg"]:
            break
        time.sleep(60)
        retry_count -= 1

    if result["failed"] or "OK" not in result["msg"]:
        pytest.fail("Download failed/error while installing python saithrift package: {}".format(py_saithrift_url))
    ptfhost.shell("dpkg -i {}".format(os.path.join("/root", pkg_name)))
    # In 202405 branch, the switch_sai_thrift package is inside saithrift-0.9-py3.11.egg
    # We need to move it out to the correct location
    PY_PATH = "/usr/lib/python3/dist-packages/"
    SRC_PATH = PY_PATH + "saithrift-0.9-py3.11.egg/switch_sai_thrift"
    DST_PATH = PY_PATH + "switch_sai_thrift"
    if ptfhost.stat(path=SRC_PATH)['stat']['exists'] and not ptfhost.stat(path=DST_PATH)['stat']['exists']:
        ptfhost.copy(src=SRC_PATH, dest=PY_PATH, remote_src=True)
    logging.info("Python saithrift package installed successfully")


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
                fec_mode = duthost.get_port_fec(dut_port)
                if auto_neg_mode is not None and fec_mode is not None:
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


def test_disable_startup_tsa_tsb_service(duthosts, localhost):
    """disable startup-tsa-tsb.service.
    Args:
        duthosts: Fixture returns a list of Ansible object DuT.

    Returns:
        None.
    """
    for duthost in duthosts.frontend_nodes:
        platform = duthost.facts['platform']
        file_check = {}
        startup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/startup-tsa-tsb.conf".format(platform)
        backup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/backup-startup-tsa-tsb.bck".format(platform)
        file_check = duthost.shell("[ -f {} ]".format(startup_tsa_tsb_file_path), module_ignore_errors=True)
        if file_check.get('rc') == 0:
            out = duthost.shell("cat {}".format(startup_tsa_tsb_file_path), module_ignore_errors=True)['rc']
            if not out:
                duthost.shell("sudo mv {} {}".format(startup_tsa_tsb_file_path, backup_tsa_tsb_file_path))
                output = duthost.shell("TSB", module_ignore_errors=True)
                pytest_assert(not output['rc'], "Failed TSB")
        else:
            logger.info("{} file does not exist in the specified path on dut {}".
                        format(startup_tsa_tsb_file_path, duthost.hostname))


"""
    Separator for internal pretests.
    Please add public pretest above this comment and keep internal
    pretests below this comment.
"""


def test_backend_acl_load(duthosts, enum_dut_hostname, tbinfo):
    duthost = duthosts[enum_dut_hostname]
    pytest_require("t0-backend" in tbinfo["topo"]["name"],
                   "Skip 'test_backend_acl_load' on non t0-backend testbeds.")
    out = duthost.command("systemctl restart backend-acl.service")
    pytest_assert(out["rc"] == 0, "Failed to load backend acl: {}".format(out["stderr"]))
    rules = duthost.show_and_parse("show acl rule DATAACL")
    for rule in rules:
        if "DATAACL" not in rule["table"]:
            continue
        if ((rule["rule"].startswith("RULE") and rule["action"] != "FORWARD")
                or (rule["rule"].startswith("DEFAULT") and rule["action"] != "DROP")
                or rule["status"] != "Active"):
            pytest.fail("Backend acl not installed succesfully: {}".format(rule))


def test_patch_dualtor_mux_simulator(duthosts, tbinfo):
    def _check_mux_service(duthost):
        return "active" == duthost.shell(
            "systemctl show mux.service --property ActiveState --value")["stdout"].strip()

    pytest_require("dualtor" in tbinfo["topo"]["name"],
                   "Skip patching mux service on non-dualtor testbeds.")
    write_standby_path = None
    for duthost in duthosts:
        if write_standby_path is None:
            write_standby_path = duthost.shell("which write_standby.py")["stdout"].strip()

        duthost.shell('sed -i "s/timeout=90/timeout=160/g" %s' % write_standby_path)
        duthost.shell('sed -i "/\[Service\]/a TimeoutStartSec=180" /lib/systemd/system/mux.service')        # noqa W605
        duthost.shell('systemctl daemon-reload')
        duthost.shell('systemctl restart mux.service')

        pytest_assert(wait_until(20, 5, 0, _check_mux_service, duthost), "Fail to start mux service after patch!")


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

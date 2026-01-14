import json
import logging
import os
import pytest
import random
import re
import time

from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
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


def test_features_state(duthosts, localhost):
    """Checks whether the state of each feature is valid or not.
    Args:
      duthosts: Fixture returns a list of Ansible object DuT..

    Returns:
      None.
    """
    def check_feature_state(dut):
        logger.info("Checking the state of each feature in 'CONFIG_DB' of {}...".format(dut.hostname))
        if not wait_until(180, FEATURE_STATE_VERIFYING_INTERVAL_SECS, 0, verify_features_state, dut):
            logger.warning("Not all states of features in 'CONFIG_DB' are valid, rebooting DUT {}".format(dut.hostname))
            reboot(dut, localhost)
            # Some services are not ready immeidately after reboot
            wait_critical_processes(dut)

        pytest_assert(wait_until(FEATURE_STATE_VERIFYING_THRESHOLD_SECS, FEATURE_STATE_VERIFYING_INTERVAL_SECS, 0,
                                 verify_features_state, dut), "Not all service states are valid!")
        logger.info("The states of features in 'CONFIG_DB' are all valid.")

    with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
        for duthost in duthosts:
            executor.submit(check_feature_state, duthost)


def test_cleanup_cache():
    folder = '_cache'
    if os.path.exists(folder):
        os.system('rm -rf {}'.format(folder))


def test_cleanup_testbed(duthosts, request, ptfhost):
    deep_clean = request.config.getoption("--deep_clean")
    if deep_clean:

        def deep_clean_dut(dut):
            logger.info("Deep cleaning DUT {}".format(dut.hostname))
            # Remove old log files.
            dut.shell("sudo find /var/log/ -name '*.gz' | sudo xargs rm -f", executable="/bin/bash")
            # Remove old core files.
            dut.shell("sudo rm -f /var/core/*", executable="/bin/bash")
            # Remove old dump files.
            dut.shell("sudo rm -rf /var/dump/*", executable="/bin/bash")

            # delete other log files that are more than a day old,
            # this step is needed to remove some backup files or the debug files added by users
            # which can create issue for log-analyzer
            dut.shell("sudo find /var/log/ -mtime +1 | sudo xargs rm -f",
                      module_ignore_errors=True, executable="/bin/bash")

        with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
            for duthost in duthosts:
                executor.submit(deep_clean_dut, duthost)

    # Cleanup rsyslog configuration file that might have damaged by test_syslog.py
    if ptfhost:
        ptfhost.shell("if [[ -f /etc/rsyslog.conf ]]; then mv /etc/rsyslog.conf /etc/rsyslog.conf.orig; "
                      "uniq /etc/rsyslog.conf.orig > /etc/rsyslog.conf; fi", executable="/bin/bash")


def test_disable_container_autorestart(duthosts, disable_container_autorestart):
    with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
        for duthost in duthosts:
            executor.submit(disable_container_autorestart, duthost)

    # Wait sometime for snmp reloading
    snmp_reloading_time = 30
    time.sleep(snmp_reloading_time)


def collect_dut_info(dut, metadata):
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

    metadata[dut.hostname] = dut_info


def update_testbed_metadata(metadata, tbname, filepath):
    """Update or create testbed metadata JSON file.

    Reads existing metadata file (if present), updates or adds testbed metadata,
    and writes back to file. Handles missing files and JSON decode errors gracefully.

    Args:
        metadata: Dictionary containing DUT metadata to be stored.
        tbname: Testbed name used as key in the metadata file.
        filepath: Path to the metadata JSON file.

    Returns:
        None.
    """
    try:
        with open(filepath, 'r') as yf:
            info = json.load(yf)
        try:
            info[tbname].update(metadata)
        except KeyError:
            logger.info(f"The testbed '{tbname}' is not in the file '{filepath}', adding it.")
            info[tbname] = metadata
    except FileNotFoundError:
        logger.info(f"The testbed metadata file '{filepath}' was not found, creating new file.")
        info = {tbname: metadata}
    except json.JSONDecodeError as e:
        logger.warning(f"Error: Failed to decode JSON from the file '{filepath}': {e}, recreating the file.")
        info = {tbname: metadata}
    try:
        with open(filepath, 'w') as yf:
            json.dump(info, yf, indent=4)
    except IOError as e:
        logger.warning('Unable to create file {}: {}'.format(filepath, e))


def test_update_testbed_metadata(duthosts, tbinfo, fanouthosts):
    metadata = {}
    tbname = tbinfo['conf-name']
    pytest_require(tbname, "skip test due to lack of testbed name.")

    with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
        for duthost in duthosts:
            executor.submit(collect_dut_info, duthost, metadata)

    folder = 'metadata'
    if not os.path.exists(folder):
        os.mkdir(folder)
    filepath = os.path.join(folder, tbname + '.json')
    update_testbed_metadata(metadata, tbname, filepath)
    prepare_autonegtest_params(duthosts, fanouthosts)


def test_disable_rsyslog_rate_limit(duthosts):

    def disable_rsyslog_rate_limit(dut):
        features_dict, succeed = dut.get_feature_status()
        if not succeed:
            # Something unexpected happened.
            # We don't want to fail here because it's an util
            logging.warning("Failed to retrieve feature status")
            return
        config_facts = dut.config_facts(host=dut.hostname, source="running")
        try:
            is_dhcp_server_enable = config_facts["ansible_facts"]["DEVICE_METADATA"]["localhost"]["dhcp_server"]
        except KeyError:
            is_dhcp_server_enable = None

        output = dut.command('config syslog --help')['stdout']
        manually_enable_feature = False
        feature_exception_dict = dict()
        if 'rate-limit-feature' in output:
            # in 202305, the feature is disabled by default for warmboot/fastboot
            # performance, need manually enable it via command
            dut.command('config syslog rate-limit-feature enable')
            manually_enable_feature = True
        for feature_name, state in list(features_dict.items()):
            if 'enabled' not in state:
                continue
            # Skip dhcp_relay check if dhcp_server is enabled
            if (is_dhcp_server_enable is not None and "enabled" in is_dhcp_server_enable and
                    feature_name == "dhcp_relay"):
                continue
            if feature_name == "frr_bmp":
                continue
            if feature_name == "telemetry":
                # Skip telemetry if there's no docker image
                output = dut.shell("docker images", module_ignore_errors=True)['stdout']
                if "sonic-telemetry" not in output:
                    continue
            try:
                dut.modify_syslog_rate_limit(feature_name, rl_option='disable')
            except Exception as e:
                feature_exception_dict[feature_name] = str(e)
        if manually_enable_feature:
            dut.command('config syslog rate-limit-feature disable')
        if feature_exception_dict:
            pytest.fail(f"The test failed on some of the dockers. feature_exception_dict = {feature_exception_dict}")

    with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
        for duthost in duthosts:
            executor.submit(disable_rsyslog_rate_limit, duthost)


def test_update_snappi_testbed_metadata(duthosts, tbinfo, request):
    """
    Prepare metadata json for snappi tests, will be stored in metadata/snappi_tests/<tb>.json
    """
    is_ixia_testbed = "tgen" in (request.config.getoption("--topology") or "") \
        or "tgen" in tbinfo["topo"]["name"] or "ixia" in tbinfo["topo"]["name"] \
        or "nut" in tbinfo["topo"]["name"]

    pytest_require(is_ixia_testbed,
                   "Skip snappi metadata generation for non-tgen testbed")

    metadata = {}
    tbname = tbinfo['conf-name']
    pytest_require(tbname, "skip test due to lack of testbed name.")
    with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
        for dut in duthosts:
            executor.submit(collect_dut_info, dut, metadata)

    for dut in duthosts:
        dutinfo = metadata[dut.hostname]
        asic_to_interface = {}
        for asic in dut.asics:
            interfaces = dut.show_interface(command="status", namespace=asic.namespace)["ansible_facts"]["int_status"]
            asic_to_interface[asic.namespace] = list(interfaces.keys())
        dutinfo.update({"asic_to_interface": asic_to_interface})
        metadata[dut.hostname] = dutinfo

    folder = 'metadata/snappi_tests'
    filepath = os.path.join(folder, tbname + '.json')
    info = {tbname: metadata}
    try:
        if not os.path.exists(folder):
            os.makedirs(folder)
        with open(filepath, 'w') as yf:
            json.dump(info, yf, indent=4)
    except IOError as e:
        logger.warning('Unable to create file {}: {}'.format(filepath, e))


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
    if not port_qos_map[intf].get('pfc_enable'):
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


def get_asic_and_branch_name(duthost):
    """
    Extract asic and branch_name from duthost.
    Returns (asic, branch_name), or fails if not found.

    Supported image version patterns:
    1. Master: SONiC Software Version: SONiC.master.921927-18199d73f
    2. Internal: SONiC Software Version: SONiC.internal.135691748-dbb8d29985
    3. Official feature branch: SONiC Software Version: SONiC.20250510.14
    4. Private image: SONiC Software Version: SONiC.20250902_202505_counters.135706687-5bc1f6cba6

    For the first 3 types, strict pattern matching is applied and URL reconstruction will proceed.
    For private images (type 4) or any unmatched patterns, 'private' is returned and URL remains unchanged.
    """
    output = duthost.shell("show version", module_ignore_errors=True)['stdout']
    version_reg = re.compile(r"sonic software version: +([^\s]+)\s", re.IGNORECASE)
    asic_reg = re.compile(r"asic: +([^\s]+)\s", re.IGNORECASE)

    version = version_reg.findall(output)[0] if version_reg.search(output) else ""
    # only broadcom, cisco-8000, mellanox support qos sai tests
    asic = asic_reg.findall(output)[0] if asic_reg.search(output) else ""

    # Strict pattern matching for official images
    # Pattern 1: Master - SONiC.master.XXXXXX-XXXXXXXX
    master_pattern = re.compile(r'^SONiC\.master\.\d+-[a-f0-9]+$', re.IGNORECASE)
    if master_pattern.match(version):
        branch_name = "master"
    # Pattern 2: Internal - SONiC.internal.XXXXXXXXX-XXXXXXXXXX
    elif re.match(r'^SONiC\.internal\.\d+-[a-f0-9]+$', version, re.IGNORECASE):
        branch_name = "internal"
    # Pattern 3: Official feature branch - SONiC.YYYYMMDD.XX
    elif re.match(r'^SONiC\.\d{8}\.\d+$', version, re.IGNORECASE):
        # Extract year/month from version string to determine branch
        date_match = re.search(r'^SONiC\.(\d{4})(\d{2})\d{2}\.\d+$', version, re.IGNORECASE)
        if date_match:
            year, month = date_match.groups()
            branch_name = f"internal-{year}{month}"
        else:
            # This should not happen if regex above matched, but fallback to private
            branch_name = "private"
    else:
        # Pattern 4: Private image or any unmatched pattern
        # No strict matching - anything else is considered private
        # This includes patterns like: SONiC.20250902_202505_counters.135706687-5bc1f6cba6
        branch_name = "private"

    return asic, branch_name


def get_debian_codename_from_syncd(duthost):
    # Get debian codename from syncd container (not host OS)
    # This applies to: master branch and internal branches >= 202405 (except 202411)
    try:
        # Try to get codename from syncd container
        codename_cmd = (
            "grep VERSION_CODENAME /etc/os-release | "
            "cut -d= -f2 | tr -d '\"'"
        )

        syncd_codename_result = duthost.containers().syncd().random().exec(codename_cmd,
                                                                           shell=True,
                                                                           module_ignore_errors=True)
        if syncd_codename_result['rc'] == 0 and syncd_codename_result['stdout'].strip():
            return syncd_codename_result['stdout'].strip()
        else:
            pytest.fail("Failed to get debian codename from syncd container. RC: {}, Output: '{}'".format(
                syncd_codename_result['rc'], syncd_codename_result['stdout']))
    except Exception as e:
        pytest.fail("Exception while getting debian codename from syncd container: {}".format(str(e)))


def is_msft_url(url):
    """
    Check if the URL is a MSFT URL that should be reconstructed.
    MSFT URLs contain specific patterns that indicate they are from MSFT build system.
    Vendor URLs (like Arista) have completely different structure and should not be modified.
    """
    msft_patterns = [
        "/mssonic-public-pipelines/",
        "/pipelines/Networking-acs-buildimage-Official/"
    ]
    return any(pattern in url for pattern in msft_patterns)


def test_update_saithrift_ptf(request, ptfhost, duthosts, enum_dut_hostname):
    '''
    Install the correct python saithrift package on the ptf
    '''
    py_saithrift_url = request.config.getoption("--py_saithrift_url")
    if not py_saithrift_url:
        pytest.skip("No URL specified for python saithrift package")

    pkg_name = py_saithrift_url.split("/")[-1]
    ptfhost.shell("rm -f {}".format(pkg_name))

    # Check if this is a MSFT URL that should be reconstructed
    # Vendor URLs (like Arista) have different structure and should not be modified
    if is_msft_url(py_saithrift_url):
        duthost = duthosts[enum_dut_hostname]

        # This is a MSFT URL - proceed with reconstruction logic
        asic, branch_name = get_asic_and_branch_name(duthost)

        # Only reconstruct URL for official images (master, internal, internal-YYYYMM)
        # Type 4: Private images keep original URL unchanged to let user handle URL correctness
        if branch_name != "private":
            # Apply special codename overrides for specific internal branches
            if branch_name == "internal-202411" and asic != "mellanox":
                # internal-202411 has saithrift URL hardcoded to bullseye for non-mellanox platform
                debian_codename = "bullseye"
            elif (branch_name.startswith("internal-") and branch_name < "internal-202405"):
                # For internal branches older than 202405, use the original URL without modification
                # No need to get debian_codename as URL won't be modified
                debian_codename = None
            else:
                debian_codename = get_debian_codename_from_syncd(duthost)

            host_addr = py_saithrift_url.split("/")[2]  # can be IP or hostname

            # Reconstruct MSFT URL based on branch
            if branch_name == "master":
                # Type 1: Master image - SONiC.master.XXXXXX-XXXXXXXX
                base_url = "http://{}".format(host_addr)
                py_saithrift_url = (f"{base_url}/mssonic-public-pipelines/"
                                    f"Azure.sonic-buildimage.official.{asic}/master/{asic}/"
                                    f"latest/target/debs/{debian_codename}/{pkg_name}")
            elif not (branch_name.startswith("internal-") and branch_name < "internal-202405"):
                # Type 2: Internal image - SONiC.internal.XXXXXXXXX-XXXXXXXXXX
                # Type 3: Official feature branch image - SONiC.YYYYMMDD.XX (internal-YYYYMM)
                base_url = "http://{}".format(host_addr)
                py_saithrift_url = (f"{base_url}/pipelines/Networking-acs-buildimage-Official/"
                                    f"{asic}/{branch_name}/latest/target/debs/{debian_codename}/{pkg_name}")
            # For old internal branches (< internal-202405), use the original URL without modification
    # If not MSFT URL (vendor URL), use it as-is without any reconstruction

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

        def select_test_ports(dut):
            all_ports = list_dut_fanout_connections(dut, fanouthosts)
            selected_ports = {}
            for dut_port, fanout, fanout_port in all_ports:
                if len(selected_ports) == max_interfaces_per_dut:
                    break
                auto_neg_mode = fanout.get_auto_negotiation_mode(fanout_port)
                fec_mode = dut.get_port_fec(dut_port)
                if auto_neg_mode is not None and fec_mode is not None:
                    speeds = get_common_supported_speeds(dut, dut_port, fanout, fanout_port)
                    selected_ports[dut_port] = {
                        'fanout': fanout.hostname,
                        'fanout_port': fanout_port,
                        'common_port_speeds': speeds
                    }

            if len(selected_ports) > 0:
                cadidate_test_ports[dut.hostname] = selected_ports

        with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
            for duthost in duthosts:
                executor.submit(select_test_ports, duthost)

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

    def disable_startup_tsa_tsb(dut):
        platform = dut.facts['platform']
        startup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/startup-tsa-tsb.conf".format(platform)
        backup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/backup-startup-tsa-tsb.bck".format(platform)
        file_check = dut.shell("[ -f {} ]".format(startup_tsa_tsb_file_path), module_ignore_errors=True)
        if file_check.get('rc') == 0:
            out = dut.shell("cat {}".format(startup_tsa_tsb_file_path), module_ignore_errors=True)['rc']
            if not out:
                dut.shell("sudo mv {} {}".format(startup_tsa_tsb_file_path, backup_tsa_tsb_file_path))
                output = dut.shell("TSB", module_ignore_errors=True)
                pytest_assert(not output['rc'], "Failed TSB")
                dut.shell("sudo config save -y")
        else:
            logger.info("{} file does not exist in the specified path on dut {}".
                        format(startup_tsa_tsb_file_path, dut.hostname))

    with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
        for duthost in duthosts.frontend_nodes:
            executor.submit(disable_startup_tsa_tsb, duthost)


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


# This one is special. It is public, but we need to ensure that it is the last one executed in pre-test.
def test_generate_running_golden_config(duthosts):
    """
    Generate running golden config after pre test.
    """

    def generate_running_golden_config(dut):
        dut.shell("sonic-cfggen -d --print-data > /etc/sonic/running_golden_config.json")
        if dut.is_multi_asic:
            for asic_index in range(0, dut.facts.get('num_asic')):
                asic_ns = 'asic{}'.format(asic_index)
                dut.shell("sonic-cfggen -n {} -d --print-data > /etc/sonic/running_golden_config{}.json".
                          format(asic_ns, asic_index))

    with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
        for duthost in duthosts:
            executor.submit(generate_running_golden_config, duthost)

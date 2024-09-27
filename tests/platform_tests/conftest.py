import json
import pytest
import os
import logging
from tests.common.mellanox_data import is_mellanox_device
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.platform.device_utils import get_current_sonic_version, overwrite_script_to_backup_logs, \
    get_kexec_time, analyze_log_file, analyze_sairedis_rec, _parse_timestamp, get_data_plane_report, \
    get_report_summary, verify_mac_jumping, verify_required_events, LOGS_ON_TMPFS_PLATFORMS
from .args.counterpoll_cpu_usage_args import add_counterpoll_cpu_usage_args
from tests.common.helpers.mellanox_thermal_control_test_helper import suspend_hw_tc_service, resume_hw_tc_service

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")

@pytest.fixture(autouse=True, scope="module")
def skip_on_simx(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts["platform"]
    hwsku = duthost.facts['hwsku']
    support_platform_simx_hwsku_list = ['ACS-MSN4700', 'ACS-SN4280']
    if "simx" in platform and hwsku not in support_platform_simx_hwsku_list:
        pytest.skip('skipped on this platform: {}'.format(platform))


@pytest.fixture(scope="module")
def xcvr_skip_list(duthosts, dpu_npu_port_list, tbinfo):
    intf_skip_list = {}
    for dut in duthosts:
        platform = dut.facts['platform']
        hwsku = dut.facts['hwsku']
        f_path = os.path.join('/usr/share/sonic/device',
                              platform, hwsku, 'hwsku.json')
        intf_skip_list[dut.hostname] = []
        dut.has_sku = True
        try:
            out = dut.command("cat {}".format(f_path))
            hwsku_info = json.loads(out["stdout"])
            for int_n in hwsku_info['interfaces']:
                if hwsku_info['interfaces'][int_n].get('port_type') == "RJ45":
                    intf_skip_list[dut.hostname].append(int_n)
            for int_n in dpu_npu_port_list[dut.hostname]:
                if int_n not in intf_skip_list[dut.hostname]:
                    intf_skip_list[dut.hostname].append(int_n)

        except Exception:
            # hwsku.json does not exist will return empty skip list
            dut.has_sku = False
            logging.debug(
                "hwsku.json absent or port_type for interfaces not included for hwsku {}".format(hwsku))

        # No hwsku.json for Arista-7050-QX-32S/Arista-7050QX-32S-S4Q31
        if hwsku in ['Arista-7050-QX-32S', 'Arista-7050QX-32S-S4Q31']:
            sfp_list = ['Ethernet0', 'Ethernet1', 'Ethernet2', 'Ethernet3']
            logging.debug('Skipping sfp interfaces: {}'.format(sfp_list))
            intf_skip_list[dut.hostname].extend(sfp_list)

        # For Mx topo, skip the SFP interfaces because they are admin down
        if tbinfo['topo']['name'] == "mx" and hwsku in ["Arista-720DT-G48S4", "Nokia-7215"]:
            sfp_list = ['Ethernet48', 'Ethernet49', 'Ethernet50', 'Ethernet51']
            logging.debug('Skipping sfp interfaces: {}'.format(sfp_list))
            intf_skip_list[dut.hostname].extend(sfp_list)

    return intf_skip_list


@pytest.fixture()
def bring_up_dut_interfaces(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    Bring up outer interfaces on the DUT.

    Args:
        request: pytest request object
        duthost: Fixture for interacting with the DUT.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    if request.node.rep_call.failed:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ports = list(mg_facts['minigraph_ports'].keys())

        # Enable outer interfaces
        for port in ports:
            namespace = mg_facts["minigraph_neighbors"][port]['namespace']
            namespace_arg = '-n {}'.format(namespace) if namespace else ''
            duthost.command("sudo config interface {} startup {}".format(namespace_arg, port))


@pytest.fixture()
def capture_interface_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logging.info("Run commands to print logs")

    show_counter_cmds = [
        "show interfaces counters",
        "show interfaces counters rif",
        "show queue counters",
        "show pfc counters"
    ]
    clear_counter_cmds = [
        "sonic-clear counters",
        "sonic-clear queuecounters",
        "sonic-clear dropcounters",
        "sonic-clear rifcounters",
        "sonic-clear pfccounters"
    ]
    if duthost.facts["asic_type"] == "broadcom":
        bcm_show_cmds = [
            "bcmcmd 'show counters'",
            "bcmcmd 'cstat all'"
        ]
        bcm_clear_cmds = [
            "bcmcmd 'clear counters'"
        ]
        show_counter_cmds = show_counter_cmds + bcm_show_cmds
        clear_counter_cmds = clear_counter_cmds + bcm_clear_cmds
    duthost.shell_cmds(cmds=clear_counter_cmds,
                       module_ignore_errors=True, verbose=False)
    results = duthost.shell_cmds(
        cmds=show_counter_cmds, module_ignore_errors=True, verbose=False)['results']
    outputs = []
    for res in results:
        res.pop('stdout')
        res.pop('stderr')
        outputs.append(res)
    logging.debug("Counters before reboot test: dut={}, cmd_outputs={}".format(duthost.hostname,
                  json.dumps(outputs, indent=4)))

    yield

    results = duthost.shell_cmds(
        cmds=show_counter_cmds, module_ignore_errors=True, verbose=False)['results']
    outputs = []
    for res in results:
        res.pop('stdout')
        res.pop('stderr')
        outputs.append(res)
    logging.debug("Counters after reboot test: dut={}, cmd_outputs={}".format(duthost.hostname,
                  json.dumps(outputs, indent=4)))


@pytest.fixture()
def thermal_manager_enabled(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    thermal_manager_available = True
    if duthost.facts.get("chassis"):
        thermal_manager_available = duthost.facts.get(
            "chassis").get("thermal_manager", True)
    if not thermal_manager_available:
        pytest.skip("skipped as thermal manager is not available")


def pytest_generate_tests(metafunc):
    if 'power_off_delay' in metafunc.fixturenames:
        delays = metafunc.config.getoption('power_off_delay')
        default_delay_list = [5, 15]
        if not delays:
            # if power_off_delay option is not present, set it to default [5, 15] for backward compatible
            metafunc.parametrize('power_off_delay', default_delay_list)
        else:
            try:
                delay_list = [int(delay.strip())
                              for delay in delays.split(',')]
                metafunc.parametrize('power_off_delay', delay_list)
            except ValueError:
                metafunc.parametrize('power_off_delay', default_delay_list)


def pytest_addoption(parser):
    add_counterpoll_cpu_usage_args(parser)


@pytest.fixture(scope="function", autouse=False)
def suspend_and_resume_hw_tc_on_mellanox_device(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    suspend and resume hw thermal control service on mellanox device
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if is_mellanox_device(duthost) and duthost.is_host_service_running("hw-management-tc"):
        suspend_hw_tc_service(duthost)

    yield

    if is_mellanox_device(duthost) and duthost.is_host_service_running("hw-management-tc"):
        resume_hw_tc_service(duthost)


@pytest.fixture(scope="module")
def dpu_npu_port_list(duthosts):
    dpu_npu_port_list = {}
    cmd_get_config_db_port_key_list = 'redis-cli --raw -n 4 keys "PORT|Ethernet*"'
    cmd_dump_config_db = "sonic-db-dump -n CONFIG_DB -y"
    dpu_npu_role = 'Dpc'
    for dut in duthosts:
        dpu_npu_port_list[dut.hostname] = []
        port_key_list = dut.command(cmd_get_config_db_port_key_list)['stdout'].split('\n')
        config_db_res = json.loads(dut.command(cmd_dump_config_db)["stdout"])

        for port_key in port_key_list:
            if port_key in config_db_res:
                if dpu_npu_role == config_db_res[port_key].get('value').get('role'):
                    dpu_npu_port_list[dut.hostname].append(port_key.split("|")[-1])
    logging.info(f"dpu npu port list: {dpu_npu_port_list}")
    return dpu_npu_port_list


def advanceboot_loganalyzer_factory(duthost, request, marker_postfix=None):
    """Create pre-reboot and post-reboot analysis functions via `LogAnalyzer` with optional marker postfix"""
    test_name = request.node.name
    if "upgrade_path" in test_name:
        reboot_type_source = request.config.getoption("--upgrade_type")
    else:
        reboot_type_source = test_name
    if "warm" in reboot_type_source:
        reboot_type = "warm"
    elif "fast" in reboot_type_source:
        reboot_type = "fast"
    else:
        reboot_type = "unknown"
    platform = duthost.facts["platform"]
    logs_in_tmpfs = list()

    marker_prefix = "test_advanced_reboot_{}".format(test_name) if not marker_postfix else \
        "test_advanced_reboot_{}_{}".format(test_name, marker_postfix)
    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix=marker_prefix)
    base_os_version = list()

    def bgpd_log_handler(preboot=False):
        # check current OS version post-reboot. This can be different than preboot OS version in case of upgrade
        current_os_version = get_current_sonic_version(duthost)
        if preboot:
            if 'SONiC-OS-201811' in current_os_version:
                bgpd_log = "/var/log/quagga/bgpd.log"
            else:
                bgpd_log = "/var/log/frr/bgpd.log"
            additional_files = {'/var/log/swss/sairedis.rec': '', bgpd_log: ''}
            loganalyzer.additional_files = list(additional_files.keys())
            loganalyzer.additional_start_str = list(additional_files.values())
            return bgpd_log
        else:
            # log_analyzer may start with quagga and end with frr, and frr.log might still have old logs.
            # To avoid missing preboot log, or analyzing old logs, combine quagga and frr log into new file
            duthost.shell("cat {} {} | sort -n > {}".format(
                "/var/log/quagga/bgpd.log", "/var/log/frr/bgpd.log", "/var/log/bgpd.log"), module_ignore_errors=True)
            loganalyzer.additional_files = [
                '/var/log/swss/sairedis.rec', '/var/log/bgpd.log']

    def pre_reboot_analysis():
        log_filesystem = duthost.shell(
            "df --output=fstype -h /var/log")['stdout']
        logs_in_tmpfs.append(
            True if (log_filesystem and "tmpfs" in log_filesystem) else False)
        base_os_version.append(get_current_sonic_version(duthost))
        bgpd_log = bgpd_log_handler(preboot=True)
        if platform in LOGS_ON_TMPFS_PLATFORMS or (len(logs_in_tmpfs) > 0 and logs_in_tmpfs[0] is True):
            # For small disk devices, /var/log in mounted in tmpfs.
            # Hence, after reboot the preboot logs are lost.
            # For log_analyzer to work, it needs logs from the shutdown path
            # Below method inserts a step in reboot script to back up logs to /host/
            overwrite_script_to_backup_logs(duthost, reboot_type, bgpd_log)
        marker = loganalyzer.init()
        loganalyzer.load_common_config()

        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_boot_messages")
        expect_file = os.path.join(TEMPLATES_DIR, "expect_boot_messages")
        ignore_reg_exp = loganalyzer.parse_regexp_file(src=ignore_file)
        expect_reg_exp = loganalyzer.parse_regexp_file(src=expect_file)

        loganalyzer.ignore_regex.extend(ignore_reg_exp)
        loganalyzer.expect_regex = []
        loganalyzer.expect_regex.extend(expect_reg_exp)
        loganalyzer.match_regex = []
        return marker

    def post_reboot_analysis(marker, event_counters=None, reboot_oper=None, log_dir=None):
        bgpd_log_handler()
        if platform in LOGS_ON_TMPFS_PLATFORMS or (len(logs_in_tmpfs) > 0 and logs_in_tmpfs[0] is True):
            restore_backup = "mv /host/syslog.99 /var/log/; " + \
                             "mv /host/sairedis.rec.99 /var/log/swss/; " + \
                             "mv /host/swss.rec.99 /var/log/swss/; " + \
                             "mv /host/bgpd.log.99 /var/log/"
            duthost.shell(restore_backup, module_ignore_errors=True)
            # find the fast/warm-reboot script path
            reboot_script_path = duthost.shell('which {}'.format(
                "{}-reboot".format(reboot_type)))['stdout']
            # restore original script. If the ".orig" file does not exist (upgrade path case), ignore the error.
            duthost.shell("mv {} {}".format(reboot_script_path + ".orig", reboot_script_path),
                          module_ignore_errors=True)
        # For mac jump test, the log message we care about is uaually combined with other messages in one line,
        # which makes the length of the line longer than 1000 and get dropped by Logananlyzer. So we need to increase
        # the max allowed length.
        # The regex library in Python 2 takes very long time (over 10 minutes) to process long lines. In our test,
        # most of the combined log message for mac jump test is around 5000 characters. So we set the max allowed
        # length to 6000.
        result = loganalyzer.analyze(marker, fail=False, maximum_log_length=6000)
        analyze_result = {"time_span": dict(), "offset_from_kexec": dict()}
        offset_from_kexec = dict()

        # Parsing sairedis shall happen after parsing syslog because FDB_AGING_DISABLE is required
        # when analysing sairedis.rec log, so we need to sort the keys
        key_list = ["syslog", "bgpd.log", "sairedis.rec"]
        for i in range(0, len(key_list)):
            for message_key in list(result["expect_messages"].keys()):
                if key_list[i] in message_key:
                    key_list[i] = message_key
                    break

        for key in key_list:
            messages = result["expect_messages"][key]
            if "syslog" in key:
                get_kexec_time(duthost, messages, analyze_result)
                reboot_start_time = analyze_result.get(
                    "reboot_time", {}).get("timestamp", {}).get("Start")
                if not reboot_start_time or reboot_start_time == "N/A":
                    logging.error("kexec regex \"Rebooting with /sbin/kexec\" not found in syslog. " +
                                  "Skipping log_analyzer checks..")
                    return
                syslog_messages = messages
            elif "bgpd.log" in key:
                bgpd_log_messages = messages
            elif "sairedis.rec" in key:
                sairedis_rec_messages = messages

        # analyze_sairedis_rec() use information from syslog and must be called after analyzing syslog
        analyze_log_file(duthost, syslog_messages,
                         analyze_result, offset_from_kexec)
        analyze_log_file(duthost, bgpd_log_messages,
                         analyze_result, offset_from_kexec)
        analyze_sairedis_rec(sairedis_rec_messages,
                             analyze_result, offset_from_kexec)

        for marker, time_data in list(analyze_result["offset_from_kexec"].items()):
            marker_start_time = time_data.get("timestamp", {}).get("Start")
            reboot_start_time = analyze_result.get(
                "reboot_time", {}).get("timestamp", {}).get("Start")
            if reboot_start_time and reboot_start_time != "N/A" and marker_start_time:
                time_data["time_taken"] = (_parse_timestamp(marker_start_time) -
                                           _parse_timestamp(reboot_start_time)).total_seconds()
            else:
                time_data["time_taken"] = "N/A"

        if reboot_oper and not isinstance(reboot_oper, str):
            reboot_oper = type(reboot_oper).__name__
        get_data_plane_report(analyze_result, reboot_type,
                              log_dir, reboot_oper)
        result_summary = get_report_summary(
            duthost, analyze_result, reboot_type, reboot_oper, base_os_version)
        logging.info(json.dumps(analyze_result, indent=4))
        logging.info(json.dumps(result_summary, indent=4))
        if reboot_oper:
            report_file_name = request.node.name + "_" + reboot_oper + "_report.json"
            summary_file_name = request.node.name + "_" + reboot_oper + "_summary.json"
        else:
            report_file_name = request.node.name + "_report.json"
            summary_file_name = request.node.name + "_summary.json"

        report_file_dir = os.path.realpath((os.path.join(os.path.dirname(__file__),
                                                         "../logs/platform_tests/")))
        report_file_path = report_file_dir + "/" + report_file_name
        summary_file_path = report_file_dir + "/" + summary_file_name
        if not os.path.exists(report_file_dir):
            os.makedirs(report_file_dir)
        with open(report_file_path, 'w') as fp:
            json.dump(analyze_result, fp, indent=4)
        with open(summary_file_path, 'w') as fp:
            json.dump(result_summary, fp, indent=4)

        # After generating timing data report, do some checks on the timing data
        verification_errors = list()
        verify_mac_jumping(test_name, analyze_result, verification_errors)
        if duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
            # TBD: expand this verification to KVM - extra port events in KVM which need to be filtered
            verify_required_events(
                duthost, event_counters, analyze_result, verification_errors)
        return verification_errors

    return pre_reboot_analysis, post_reboot_analysis


@pytest.fixture()
def multihop_advanceboot_loganalyzer_factory(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request):
    """
    Advance reboot log analysis involving multiple hops.
    This fixture returns a factory function requiring the hop_index to be supplied.
    Then, it starts log analysis at the beginning of the test. At the end,
    the collected expect messages are verified and timing of start/stop is calculated.

    Args:
        duthosts : List of DUT hosts
        enum_rand_one_per_hwsku_frontend_hostname: hostname of a randomly selected DUT
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Currently, advanced reboot test would skip for kvm platform if the test has no device_type marker for vs.
    # Doing the same skip logic in this fixture to avoid running loganalyzer without the test executed
    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        device_marks = [arg for mark in request.node.iter_markers(
            name='device_type') for arg in mark.args]
        if 'vs' not in device_marks:
            pytest.skip('Testcase not supported for kvm')

    def _multihop_advanceboot_loganalyzer_factory(hop_index):
        pre_reboot_analysis, post_reboot_analysis = advanceboot_loganalyzer_factory(
            duthost, request, marker_postfix="hop-{}".format(hop_index))
        return pre_reboot_analysis, post_reboot_analysis

    yield _multihop_advanceboot_loganalyzer_factory

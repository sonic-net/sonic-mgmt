import glob
import json
import pytest
import os
import re
import logging
from collections import OrderedDict
from datetime import datetime

from tests.platform_tests.reboot_timing_constants import SERVICE_PATTERNS, OTHER_PATTERNS,\
    SAIREDIS_PATTERNS, OFFSET_ITEMS, TIME_SPAN_ITEMS, REQUIRED_PATTERNS
from tests.common.mellanox_data import is_mellanox_device
from tests.common.broadcom_data import is_broadcom_device
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.plugins.sanity_check.recover import neighbor_vm_restore
from .args.counterpoll_cpu_usage_args import add_counterpoll_cpu_usage_args
from .mellanox.mellanox_thermal_control_test_helper import suspend_hw_tc_service, resume_hw_tc_service


TEMPLATES_DIR = os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "templates")

FMT = "%b %d %H:%M:%S.%f"
FMT_YEAR = "%Y %b %d %H:%M:%S.%f"
FMT_SHORT = "%b %d %H:%M:%S"
FMT_ALT = "%Y-%m-%dT%H:%M:%S.%f%z"

LOGS_ON_TMPFS_PLATFORMS = [
    "x86_64-arista_7050_qx32",
    "x86_64-arista_7050_qx32s",
    "x86_64-arista_7060_cx32s",
    "x86_64-arista_7260cx3_64",
    "x86_64-arista_7050cx3_32s",
    "x86_64-mlnx_msn2700-r0",
    "x86_64-dell_s6100_c2538-r0",
    "armhf-nokia_ixs7215_52x-r0"
]


def _parse_timestamp(timestamp):
    for format in [FMT, FMT_YEAR, FMT_SHORT, FMT_ALT]:
        try:
            time = datetime.strptime(timestamp, format)
            return time
        except ValueError:
            continue
    raise ValueError("Unable to parse {} with any known format".format(timestamp))


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


def get_state_times(timestamp, state, state_times, first_after_offset=None):
    time = timestamp.strftime(FMT)
    state_name = state.split("|")[0].strip()
    state_status = state.split("|")[1].strip()
    state_dict = state_times.get(state_name, {"timestamp": {}})
    timestamps = state_dict.get("timestamp")
    if state_status in timestamps:
        state_dict[state_status +
                   " count"] = state_dict.get(state_status+" count") + 1
        # capture last occcurence - useful in calculating events end time
        state_dict["last_occurence"] = time
    elif first_after_offset:
        state_dict[state_status+" count"] = 1
        # capture the first occurence as the one after offset timestamp and ignore the ones before
        # this is useful to find time after a specific instance, for eg. - kexec time or FDB disable time.
        if _parse_timestamp(first_after_offset) < _parse_timestamp(time):
            timestamps[state_status] = time
    else:
        # only capture timestamp of first occurence of the entity. Otherwise, just increment the count above.
        # this is useful in capturing start point. Eg., first neighbor entry, LAG ready, etc.
        state_dict[state_status+" count"] = 1
        timestamps[state_status] = time
    return {state_name: state_dict}


def get_report_summary(duthost, analyze_result, reboot_type, reboot_oper, base_os_version):
    time_spans = analyze_result.get("time_span", {})
    time_spans_summary = OrderedDict()
    kexec_offsets = analyze_result.get("offset_from_kexec", {})
    reboot_start_time = analyze_result.get(
        "reboot_time", {}).get("timestamp", {}).get("Start")
    kexec_offsets_summary = OrderedDict()
    for entity in OFFSET_ITEMS:
        time_taken = ""
        if entity in kexec_offsets:
            time_taken = kexec_offsets.get(entity).get("time_taken", "")
        elif entity in time_spans:
            timestamp = time_spans.get(entity).get("timestamp", {})
            marker_start_time = timestamp.get(
                "Start") if "Start" in timestamp else timestamp.get("Started")
            if reboot_start_time and reboot_start_time != "N/A" and marker_start_time:
                time_taken = (_parse_timestamp(marker_start_time) -
                              _parse_timestamp(reboot_start_time)).total_seconds()
        kexec_offsets_summary.update({entity.lower(): str(time_taken)})

    for entity in TIME_SPAN_ITEMS:
        time_taken = ""
        if entity in time_spans:
            time_taken = time_spans.get(entity, {}).get("time_span", "")
        elif entity in kexec_offsets:
            marker_first_time = kexec_offsets.get(
                entity).get("timestamp", {}).get("Start")
            marker_last_time = kexec_offsets.get(entity).get("last_occurence")
            if marker_first_time and marker_last_time:
                time_taken = (_parse_timestamp(marker_last_time) -
                              _parse_timestamp(marker_first_time)).total_seconds()
        time_spans_summary.update({entity.lower(): str(time_taken)})

    lacp_sessions_dict = analyze_result.get("controlplane")
    lacp_sessions_waittime = lacp_sessions_dict.pop("lacp_sessions")\
        if lacp_sessions_dict and "lacp_sessions" in lacp_sessions_dict else None
    controlplane_summary = {"downtime": "",
                            "arp_ping": "", "lacp_session_max_wait": ""}
    if duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
        if lacp_sessions_waittime and len(lacp_sessions_waittime) > 0:
            # Filter out None values and then fine the maximum
            filtered_lacp_sessions_waittime = [value for value in lacp_sessions_waittime.values() if value is not None]
            if filtered_lacp_sessions_waittime:
                max_lacp_session_wait = max(filtered_lacp_sessions_waittime)
            else:
                max_lacp_session_wait = None
            analyze_result.get(
                "controlplane", controlplane_summary).update(
                    {"lacp_session_max_wait": max_lacp_session_wait})

    result_summary = {
        "reboot_type": "{}-{}".format(reboot_type, reboot_oper) if reboot_oper else reboot_type,
        "hwsku": duthost.facts["hwsku"],
        "hostname": duthost.hostname,
        "base_ver": base_os_version[0] if base_os_version and len(base_os_version) else "",
        "target_ver": get_current_sonic_version(duthost),
        "dataplane": analyze_result.get("dataplane", {"downtime": "", "lost_packets": ""}),
        "controlplane": analyze_result.get("controlplane", controlplane_summary),
        "time_span": time_spans_summary,
        "offset_from_kexec": kexec_offsets_summary
    }
    return result_summary


def get_kexec_time(duthost, messages, result):
    reboot_pattern = re.compile(
        r'.* NOTICE (?:admin|root): Rebooting with /sbin/kexec -e to.*...')
    reboot_time = "N/A"
    logging.info("FINDING REBOOT PATTERN")
    for message in messages:
        # Get timestamp of reboot - Rebooting string
        if re.search(reboot_pattern, message):
            logging.info(
                "FOUND REBOOT PATTERN for {}".format(duthost.hostname))
            delim = "{}|{}".format(duthost.hostname, "sonic")
            reboot_time = _parse_timestamp(re.split(delim, message)[
                                           0].strip()).strftime(FMT)
            continue
    result["reboot_time"] = {
        "timestamp": {"Start": reboot_time},
    }


def analyze_log_file(duthost, messages, result, offset_from_kexec):
    service_restart_times = dict()
    derived_patterns = OTHER_PATTERNS.get("COMMON")
    service_patterns = dict()
    # get platform specific regexes
    if is_broadcom_device(duthost):
        derived_patterns.update(OTHER_PATTERNS.get("BRCM"))
    elif is_mellanox_device(duthost):
        derived_patterns.update(OTHER_PATTERNS.get("MLNX"))
    # get image specific regexes
    if "20191130" in get_current_sonic_version(duthost):
        derived_patterns.update(OTHER_PATTERNS.get("201911"))
        service_patterns.update(SERVICE_PATTERNS.get("201911"))
    else:
        derived_patterns.update(OTHER_PATTERNS.get("LATEST"))
        service_patterns.update(SERVICE_PATTERNS.get("LATEST"))

    if not messages:
        logging.error("Expected messages not found in syslog")
        return None

    def service_time_check(message, status):
        delim = "{}|{}".format(duthost.hostname, "sonic")
        time = _parse_timestamp(re.split(delim, message)[0].strip())
        time = time.strftime(FMT)
        service_name = message.split(status + " ")[1].split()[0]
        service_name = service_name.upper()
        if service_name == "ROUTER":
            service_name = "RADV"
        service_dict = service_restart_times.get(
            service_name, {"timestamp": {}})
        timestamps = service_dict.get("timestamp")
        if status in timestamps:
            service_dict[status +
                         " count"] = service_dict.get(status+" count") + 1
        else:
            service_dict[status+" count"] = 1
        timestamps[status] = time
        service_restart_times.update({service_name: service_dict})

    for message in messages:
        # Get stopping to started timestamps for services (swss, bgp, etc)
        for status, pattern in list(service_patterns.items()):
            if re.search(pattern, message):
                service_time_check(message, status)
                break
        # Get timestamps of all other entities
        for state, pattern in list(derived_patterns.items()):
            if re.search(pattern, message):
                delim = "{}|{}".format(duthost.hostname, "sonic")
                timestamp = _parse_timestamp(
                    re.split(delim, message)[0].strip())
                state_name = state.split("|")[0].strip()
                if state_name + "|End" not in list(derived_patterns.keys()):
                    if "FDB_EVENT_OTHER_MAC_EXPIRY" in state_name or "FDB_EVENT_SCAPY_MAC_EXPIRY" in state_name:
                        fdb_aging_disable_start = service_restart_times.get("FDB_AGING_DISABLE", {})\
                            .get("timestamp", {}).get("Start")
                        if not fdb_aging_disable_start:
                            break
                        first_after_offset = fdb_aging_disable_start
                    else:
                        first_after_offset = result.get("reboot_time", {}).get(
                            "timestamp", {}).get("Start")
                    state_times = get_state_times(timestamp, state, offset_from_kexec,
                                                  first_after_offset=first_after_offset)
                    offset_from_kexec.update(state_times)
                else:
                    state_times = get_state_times(
                        timestamp, state, service_restart_times)
                    service_restart_times.update(state_times)
                if "PORT_READY" not in state_name:
                    # If PORT_READY, don't break out of the for-loop here, because we want to
                    # try to match the other regex as well
                    break
    # Calculate time that services took to stop/start
    for _, timings in list(service_restart_times.items()):
        timestamps = timings["timestamp"]
        timings["stop_time"] = (_parse_timestamp(timestamps["Stopped"]) -
                                _parse_timestamp(timestamps["Stopping"])).total_seconds() \
            if "Stopped" in timestamps and "Stopping" in timestamps else None

        timings["start_time"] = (_parse_timestamp(timestamps["Started"]) -
                                 _parse_timestamp(timestamps["Starting"])).total_seconds() \
            if "Started" in timestamps and "Starting" in timestamps else None

        if "Started" in timestamps and "Stopped" in timestamps:
            timings["time_span"] = (_parse_timestamp(timestamps["Started"]) -
                                    _parse_timestamp(timestamps["Stopped"])).total_seconds()
        elif "Start" in timestamps and "End" in timestamps:
            if "last_occurence" in timings:
                timings["time_span"] = (_parse_timestamp(timings["last_occurence"]) -
                                        _parse_timestamp(timestamps["Start"])).total_seconds()
            else:
                timings["time_span"] = (_parse_timestamp(timestamps["End"]) -
                                        _parse_timestamp(timestamps["Start"])).total_seconds()

    result["time_span"].update(service_restart_times)
    result["offset_from_kexec"] = offset_from_kexec
    return result


def analyze_sairedis_rec(messages, result, offset_from_kexec):
    sai_redis_state_times = dict()
    for message in messages:
        for state, pattern in list(SAIREDIS_PATTERNS.items()):
            if re.search(pattern, message):
                timestamp = datetime.strptime(message.split(
                    "|")[0].strip(), "%Y-%m-%d.%H:%M:%S.%f")
                state_name = state.split("|")[0].strip()
                reboot_time = result.get("reboot_time", {}).get(
                    "timestamp", {}).get("Start")
                if state_name + "|End" not in list(SAIREDIS_PATTERNS.keys()):
                    if "FDB_EVENT_OTHER_MAC_EXPIRY" in state_name or "FDB_EVENT_SCAPY_MAC_EXPIRY" in state_name:
                        fdb_aging_disable_start = result.get("time_span", {}).get("FDB_AGING_DISABLE", {})\
                            .get("timestamp", {}).get("Start")
                        if not fdb_aging_disable_start:
                            break
                        # Ignore MAC learning events before FDB aging disable, as MAC learning is still allowed
                        log_time = timestamp.strftime(FMT)
                        if _parse_timestamp(log_time) < _parse_timestamp(fdb_aging_disable_start):
                            break
                        first_after_offset = fdb_aging_disable_start
                    else:
                        first_after_offset = result.get("reboot_time", {}).get(
                            "timestamp", {}).get("Start")
                    state_times = get_state_times(timestamp, state, offset_from_kexec,
                                                  first_after_offset=first_after_offset)
                    offset_from_kexec.update(state_times)
                else:
                    state_times = get_state_times(timestamp, state, sai_redis_state_times,
                                                  first_after_offset=reboot_time)
                    sai_redis_state_times.update(state_times)

    for _, timings in list(sai_redis_state_times.items()):
        timestamps = timings["timestamp"]
        if "Start" in timestamps and "End" in timestamps:
            timings["time_span"] = (_parse_timestamp(timestamps["End"]) -
                                    _parse_timestamp(timestamps["Start"])).total_seconds()

    result["time_span"].update(sai_redis_state_times)
    result["offset_from_kexec"] = offset_from_kexec


def get_data_plane_report(analyze_result, reboot_type, log_dir, reboot_oper):
    report = {"controlplane": {"arp_ping": "", "downtime": ""},
              "dataplane": {"lost_packets": "", "downtime": ""}}
    files = glob.glob1(log_dir, '*reboot*-report.json')
    if files:
        filepath = "{}/{}".format(log_dir, files[0])
        with open(filepath) as json_file:
            report = json.load(json_file)
    analyze_result.update(report)


def verify_mac_jumping(test_name, timing_data, verification_errors):
    mac_jumping_other_addr = timing_data.get("offset_from_kexec", {})\
        .get("FDB_EVENT_OTHER_MAC_EXPIRY", {}).get("Start count", 0)
    mac_jumping_scapy_addr = timing_data.get("offset_from_kexec", {})\
        .get("FDB_EVENT_SCAPY_MAC_EXPIRY", {}).get("Start count", 0)
    mac_expiry_start = timing_data.get("offset_from_kexec", {}).get("FDB_EVENT_OTHER_MAC_EXPIRY", {})\
        .get("timestamp", {}).get("Start")
    fdb_aging_disable_start = timing_data.get("time_span", {}).get("FDB_AGING_DISABLE", {})\
        .get("timestamp", {}).get("Start")
    fdb_aging_disable_end = timing_data.get("time_span", {}).get("FDB_AGING_DISABLE", {})\
        .get("timestamp", {}).get("End")

    if "mac_jump" in test_name:
        # MAC jumping allowed - allow Scapy default MAC to jump
        logging.info("MAC jumping is allowed. Jump count for expected mac: {}, unexpected MAC: {}"
                     .format(mac_jumping_scapy_addr, mac_jumping_other_addr))
        if not mac_jumping_scapy_addr:
            verification_errors.append(
                "MAC jumping not detected when expected for address: 00-06-07-08-09-0A")
    else:
        # MAC jumping not allowed - do not allow the SCAPY default MAC to jump
        if mac_jumping_scapy_addr:
            verification_errors.append("MAC jumping is not allowed. Jump count for scapy mac: {}, other MAC: {}"
                                       .format(mac_jumping_scapy_addr, mac_jumping_other_addr))
    if mac_jumping_other_addr:
        # In both mac jump allowed and denied cases unexpected MAC addresses should NOT jump between
        # the window that starts when SAI is instructed to disable MAC learning (warmboot shutdown path)
        # and ends when SAI is instructed to enable MAC learning (warmboot recovery path)
        logging.info("Mac expiry for unexpected addresses started at {}".format(mac_expiry_start) +
                     " and FDB learning enabled at {}".format(fdb_aging_disable_end))
        if _parse_timestamp(mac_expiry_start) > _parse_timestamp(fdb_aging_disable_start) and\
           _parse_timestamp(mac_expiry_start) < _parse_timestamp(fdb_aging_disable_end):
            verification_errors.append(
                "Mac expiry detected during the window when FDB ageing was disabled")


def verify_required_events(duthost, event_counters, timing_data, verification_errors):
    for key in ["time_span", "offset_from_kexec"]:
        for pattern in REQUIRED_PATTERNS.get(key):
            if pattern == 'PORT_READY':
                observed_start_count = timing_data.get(
                    key, {}).get(pattern, {}).get("Start-changes-only count", 0)
            else:
                observed_start_count = timing_data.get(
                    key, {}).get(pattern, {}).get("Start count", 0)
            observed_end_count = timing_data.get(
                key, {}).get(pattern, {}).get("End count", 0)
            expected_count = event_counters.get(pattern)
            # If we're checking PORT_READY, allow any number of PORT_READY messages between 0 and the number of ports.
            # Some platforms appear to have a random number of these messages, other platforms have however many ports
            # are up.
            if observed_start_count != expected_count and (
                    pattern != 'PORT_READY' or observed_start_count > expected_count):
                verification_errors.append("FAIL: Event {} was found {} times, when expected exactly {} times".
                                           format(pattern, observed_start_count, expected_count))
            if key == "time_span" and observed_start_count != observed_end_count:
                verification_errors.append("FAIL: Event {} counters did not match. ".format(pattern) +
                                           "Started {} times, and ended {} times".
                                           format(observed_start_count, observed_end_count))


def overwrite_script_to_backup_logs(duthost, reboot_type, bgpd_log):
    # find the fast/warm-reboot script path
    reboot_script_path = duthost.shell('which {}'.format(
        "{}-reboot".format(reboot_type)))['stdout']
    # backup original script
    duthost.shell("cp {} {}".format(
        reboot_script_path, reboot_script_path + ".orig"))
    # find the anchor string inside fast/warm-reboot script
    rebooting_log_line = "debug.*Rebooting with.*to.*"
    # Create a backup log command to be inserted right after the anchor string defined above
    backup_log_cmds = "cat /var/log/syslog.1 /var/log/syslog > /host/syslog.99 || true;" +\
        "cat /var/log/swss/sairedis.rec.1 /var/log/swss/sairedis.rec > /host/sairedis.rec.99 || true;" +\
        "cat /var/log/swss/swss.rec.1 /var/log/swss/swss.rec > /host/swss.rec.99 || true;" +\
        "cat {}.1 {} > /host/bgpd.log.99 || true".format(bgpd_log, bgpd_log)
    # Do find-and-replace on fast/warm-reboot script to insert the backup_log_cmds string
    insert_backup_command = "sed -i '/{}/a {}' {}".format(
        rebooting_log_line, backup_log_cmds, reboot_script_path)
    duthost.shell(insert_backup_command)


def get_current_sonic_version(duthost):
    return duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']


@pytest.fixture()
def advanceboot_loganalyzer(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request):
    """
    Advance reboot log analysis.
    This fixture starts log analysis at the beginning of the test. At the end,
    the collected expect messages are verified and timing of start/stop is calculated.

    Args:
        duthosts : List of DUT hosts
        enum_rand_one_per_hwsku_frontend_hostname: hostname of a randomly selected DUT
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
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
    # Currently, advanced reboot test would skip for kvm platform if the test has no device_type marker for vs.
    # Doing the same skip logic in this fixture to avoid running loganalyzer without the test executed
    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        device_marks = [arg for mark in request.node.iter_markers(
            name='device_type') for arg in mark.args]
        if 'vs' not in device_marks:
            pytest.skip('Testcase not supported for kvm')
    platform = duthost.facts["platform"]
    logs_in_tmpfs = list()

    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix="test_advanced_reboot_{}".format(test_name))
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
            restore_backup = "mv /host/syslog.99 /var/log/; " +\
                "mv /host/sairedis.rec.99 /var/log/swss/; " +\
                "mv /host/swss.rec.99 /var/log/swss/; " +\
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

    yield pre_reboot_analysis, post_reboot_analysis


@pytest.fixture()
def advanceboot_neighbor_restore(duthosts, enum_rand_one_per_hwsku_frontend_hostname, nbrhosts, tbinfo):
    """
    This fixture is invoked at the test teardown for advanced-reboot SAD cases.
    If a SAD case fails or crashes for some reason, the neighbor VMs can be left in
    a bad state. This fixture will restore state of neighbor interfaces, portchannels
    and BGP sessions that were shutdown during the test.
    """
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    neighbor_vm_restore(duthost, nbrhosts, tbinfo)


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

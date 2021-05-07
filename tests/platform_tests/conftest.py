import glob
import json
import pytest
import os
import re
import logging
from datetime import datetime

from tests.common.fixtures.advanced_reboot import get_advanced_reboot
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from .args.advanced_reboot_args import add_advanced_reboot_args
from .args.cont_warm_reboot_args import add_cont_warm_reboot_args
from .args.normal_reboot_args import add_normal_reboot_args
from .args.api_sfp_args import add_api_sfp_args

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
FMT = "%b %d %H:%M:%S.%f"

@pytest.fixture(autouse=True, scope="module")
def skip_on_simx(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts["platform"]
    if "simx" in platform:
        pytest.skip('skipped on this platform: {}'.format(platform))


@pytest.fixture(scope="module")
def xcvr_skip_list(duthosts):
    intf_skip_list = {}
    for dut in duthosts:
        platform = dut.facts['platform']
        hwsku = dut.facts['hwsku']
        f_path = os.path.join('/usr/share/sonic/device', platform, hwsku, 'hwsku.json')
        intf_skip_list[dut.hostname] = []
        try:
            out = dut.command("cat {}".format(f_path))
            hwsku_info = json.loads(out["stdout"])
            for int_n in hwsku_info['interfaces']:
                if hwsku_info['interfaces'][int_n]['port_type'] == "RJ45":
                    intf_skip_list[dut.hostname].append(int_n)

        except Exception:
            # hwsku.json does not exist will return empty skip list
            logging.debug(
                "hwsku.json absent or port_type for interfaces not included for hwsku {}".format(hwsku))

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
        ports = mg_facts['minigraph_ports'].keys()

        # Enable outer interfaces
        for port in ports:
            duthost.no_shutdown(ifname=port)


def get_state_times(timestamp, state, state_times):
    time = timestamp.strftime(FMT)
    state_name = state.split("|")[0].strip()
    state_status = state.split("|")[1].strip()
    state_dict = state_times.get(state_name, {"timestamp": {}})
    timestamps = state_dict.get("timestamp")
    if state_status in timestamps:
        state_dict[state_status+" count"] = state_dict.get(state_status+" count", 1) + 1
    else:
        # only capture timestamp of first occurence of the entity. Otherwise, just increment the count above.
        # this is useful in capturing start point. Eg., first neighbor entry, LAG ready, etc.
        timestamps[state_status] = time
    return {state_name: state_dict}


def get_report_summary(analyze_result, reboot_type):
    processing_times = analyze_result.get("processing_time", {})
    first_occurences = analyze_result.get("first_occurence", {})
    processing_times_summary = dict()
    for entity, time_data in processing_times.items():
        processing_times_summary.update({entity.lower(): str(time_data["reboot_time"])})
    for entity, time_data in first_occurences.items():
        processing_times_summary.update({entity.lower(): str(time_data["time_since_reboot"])})
    result_summary = {
        "reboot_type": reboot_type,
        "reboot_time": str(analyze_result.get("reboot_time", {}).get("reboot_time")),
        "dataplane": {k: str(v) for k,v in analyze_result.get("dataplane", {}).items()},
        "processing_time": processing_times_summary
    }
    return result_summary


def analyze_syslog(duthost, messages, result, first_occurence_times):
    service_restart_times = dict()
    if not messages:
        logging.error("Expected messages not found in syslog")
        return None

    reboot_pattern = re.compile(r'.* NOTICE admin: Rebooting with /sbin/kexec -e to.*...')
    service_patterns = {
        "Stopping": re.compile(r'.*Stopping.*service.*'),
        "Stopped": re.compile(r'.*Stopped.*service.*'),
        "Starting": re.compile(r'.*Starting.*service.*'),
        "Started": re.compile(r'.*Started.*service.*')
    }
    other_patterns = {
        "PORT_INIT|Start": re.compile(r'.*swss#portsyncd.*main.*PortInitDone.*'),
        "LAG_READY|Start": re.compile(r'.*teamd#tlm_teamd.*try_add_lag.*The LAG \'PortChannel.*\' has been added.*'),
        "INIT_VIEW|Start": re.compile(r'.*swss#orchagent.*notifySyncd.*sending syncd.*INIT_VIEW.*'),
        "INIT_VIEW|End": re.compile(r'.*swss#orchagent.*sai_redis_notify_syncd.*switched ASIC to INIT VIEW.*'),
        "APPLY_VIEW|Start": re.compile(r'.*swss#orchagent.*notifySyncd.*sending syncd.*APPLY_VIEW.*'),
        "APPLY_VIEW|End": re.compile(r'.*swss#orchagent.*sai_redis_notify_syncd.*switched ASIC to APPLY VIEW.*'),
        "FINALIZER|Start": re.compile(r'.*WARMBOOT_FINALIZER.*Wait for database to become ready.*'),
        "FINALIZER|End": re.compile(r"(.*WARMBOOT_FINALIZER.*Finalizing warmboot.*)|(.*WARMBOOT_FINALIZER.*warmboot is not enabled.*)")
    }

    def service_time_check(message, status):
        time = datetime.strptime(message.split(duthost.hostname)[0].strip(), FMT)
        time = time.strftime(FMT)
        service_name = message.split(status + " ")[1].split()[0]
        service_dict = service_restart_times.get(service_name, {"timestamp": {}})
        timestamps = service_dict.get("timestamp")
        if status in timestamps:
            service_dict[status+" count"] = service_dict.get(status+" count", 1) + 1
        timestamps[status] = time
        service_restart_times.update({service_name: service_dict})

    reboot_time = "N/A"
    for message in messages:
        if re.search(reboot_pattern, message):
            reboot_time = datetime.strptime(message.split(duthost.hostname)[0].strip(), FMT).strftime(FMT)
            continue
        for status, pattern in service_patterns.items():
            if re.search(pattern, message):
                service_time_check(message, status)
                break
        marker_keys = other_patterns.keys()
        for state, pattern in other_patterns.items():
            if re.search(pattern, message):
                timestamp = datetime.strptime(message.split(duthost.hostname)[0].strip(), FMT)
                state_name = state.split("|")[0].strip()
                if state_name + "|End" not in marker_keys:
                    state_times = get_state_times(timestamp, state, first_occurence_times)
                    first_occurence_times.update(state_times)
                else:
                    state_times = get_state_times(timestamp, state, service_restart_times)
                    service_restart_times.update(state_times)
                break

    for _, timings in service_restart_times.items():
        timestamps = timings["timestamp"]
        timings["stop_time"] = (datetime.strptime(timestamps["Stopped"], FMT) -\
            datetime.strptime(timestamps["Stopping"], FMT)).total_seconds() \
                if "Stopped" in timestamps and "Stopping" in timestamps else None

        timings["start_time"] = (datetime.strptime(timestamps["Started"], FMT) -\
            datetime.strptime(timestamps["Starting"], FMT)).total_seconds() \
                if "Started" in timestamps and "Starting" in timestamps else None

        if "Started" in timestamps and "Stopped" in timestamps:
            timings["reboot_time"] = (datetime.strptime(timestamps["Started"], FMT) -\
                datetime.strptime(timestamps["Stopped"], FMT)).total_seconds()
        elif "Start" in timestamps and "End" in timestamps:
            timings["reboot_time"] = (datetime.strptime(timestamps["End"], FMT) -\
            datetime.strptime(timestamps["Start"], FMT)).total_seconds()

    result["processing_time"].update(service_restart_times)
    result["first_occurence"] = first_occurence_times
    finalizer_end_time = service_restart_times.get("FINALIZER",{}).get("timestamp",{}).get("End")
    result["reboot_time"] = {
        "timestamp": {"Start": reboot_time, "End": finalizer_end_time},
        "reboot_time": (datetime.strptime(finalizer_end_time, FMT) -\
            datetime.strptime(reboot_time, FMT)).total_seconds() \
                if finalizer_end_time and reboot_time != "N/A" else "N/A"
    }

    return result


def analyze_sairedis_rec(messages, result, first_occurence_times):
    sai_redis_state_times = dict()
    state_patterns = {
        "sai_switch_create|Start": re.compile(r'.*\|c\|SAI_OBJECT_TYPE_SWITCH.*'),
        "first_neighbor_entry|Start": re.compile(r'.*\|c\|SAI_OBJECT_TYPE_NEIGHBOR_ENTRY.*'),
        "sai_switch_create|End": re.compile(r'.*\|g\|SAI_OBJECT_TYPE_SWITCH.*SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID.*'),
        "default_route_set|Start": re.compile(r'.*\|(S|s)\|SAI_OBJECT_TYPE_ROUTE_ENTRY.*0\.0\.0\.0/0.*SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION=SAI_PACKET_ACTION_FORWARD.*')
    }
    marker_keys = state_patterns.keys()
    for message in messages:
        for state, pattern in state_patterns.items():
            if re.search(pattern, message):
                timestamp = datetime.strptime(message.split("|")[0].strip(), "%Y-%m-%d.%H:%M:%S.%f")
                state_name = state.split("|")[0].strip()
                if state_name + "|End" not in marker_keys:
                    state_times = get_state_times(timestamp, state, first_occurence_times)
                    first_occurence_times.update(state_times)
                else:
                    state_times = get_state_times(timestamp, state, sai_redis_state_times)
                    sai_redis_state_times.update(state_times)

    for _, timings in sai_redis_state_times.items():
        timestamps = timings["timestamp"]
        if "Start" in timestamps and "End" in timestamps:
            timings["reboot_time"] = (datetime.strptime(timestamps["End"], FMT) -\
                datetime.strptime(timestamps["Start"], FMT)).total_seconds()

    result["processing_time"].update(sai_redis_state_times)
    result["first_occurence"] = first_occurence_times


def get_data_plane_report(analyze_result, reboot_type):
    files = glob.glob('/tmp/{}-reboot-report.json'.format(reboot_type))
    if files:
        filepath = files[0]
        with open(filepath) as json_file:
            report = json.load(json_file)
    analyze_result["dataplane"] = report


@pytest.fixture()
def advanceboot_loganalyzer(duthosts, rand_one_dut_hostname, request):
    """
    Advance reboot log analysis.
    This fixture starts log analysis at the beginning of the test. At the end,
    the collected expect messages are verified and timing of start/stop is calculated.

    Args:
        duthosts : List of DUT hosts
        rand_one_dut_hostname: hostname of a randomly selected DUT
    """
    duthost = duthosts[rand_one_dut_hostname]
    test_name = request.node.name
    if "warm" in test_name:
        reboot_type = "warm"
    elif "fast" in test_name:
        reboot_type = "fast"
    else:
        reboot_type = "unknown"
    # Currently, advanced reboot test would skip for kvm platform if the test has no device_type marker for vs.
    # Doing the same skip logic in this fixture to avoid running loganalyzer without the test executed
    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        device_marks = [arg for mark in request.node.iter_markers(name='device_type') for arg in mark.args]
        if 'vs' not in device_marks:
            pytest.skip('Testcase not supported for kvm')

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="test_advanced_reboot_{}".format(test_name),
                    additional_files={'/var/log/swss/sairedis.rec': 'recording on: /var/log/swss/sairedis.rec'})
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

    yield

    result = loganalyzer.analyze(marker, fail=False)
    analyze_result = {"processing_time": dict()}
    first_occurence_times = dict()
    for key, messages in result["expect_messages"].items():
        if "syslog" in key:
            analyze_syslog(duthost, messages, analyze_result, first_occurence_times)
        elif "sairedis.rec" in key:
            analyze_sairedis_rec(messages, analyze_result, first_occurence_times)

    for marker, time_data in analyze_result["first_occurence"].items():
        marker_start_time = time_data.get("timestamp", {}).get("Start")
        reboot_start_time = analyze_result.get("reboot_time", {}).get("timestamp", {}).get("Start")
        if reboot_start_time and reboot_start_time != "N/A" and marker_start_time:
            time_data["time_since_reboot"] = (datetime.strptime(marker_start_time, FMT) -\
                datetime.strptime(reboot_start_time, FMT)).total_seconds()
        else:
            time_data["time_since_reboot"] = "N/A"

    get_data_plane_report(analyze_result, reboot_type)
    result_summary = get_report_summary(analyze_result, reboot_type)
    logging.info(json.dumps(analyze_result, indent=4))
    logging.info(json.dumps(result_summary, indent=4))
    report_file_name = request.node.name + "_report.json"
    summary_file_name = request.node.name + "_summary.json"
    report_file_dir = os.path.realpath((os.path.join(os.path.dirname(__file__),\
        "../logs/platform_tests/")))
    report_file_path = report_file_dir + "/" + report_file_name
    summary_file_path = report_file_dir + "/" + summary_file_name
    if not os.path.exists(report_file_dir):
        os.makedirs(report_file_dir)
    with open(report_file_path, 'w') as fp:
        json.dump(analyze_result, fp, indent=4)
    with open(summary_file_path, 'w') as fp:
        json.dump(result_summary, fp, indent=4)


def pytest_addoption(parser):
    add_advanced_reboot_args(parser)
    add_cont_warm_reboot_args(parser)
    add_normal_reboot_args(parser)
    add_api_sfp_args(parser)


def pytest_generate_tests(metafunc):
    if 'power_off_delay' in metafunc.fixturenames:
        delays = metafunc.config.getoption('power_off_delay')
        default_delay_list = [5, 15]
        if not delays:
            # if power_off_delay option is not present, set it to default [5, 15] for backward compatible
            metafunc.parametrize('power_off_delay', default_delay_list)
        else:
            try:
                delay_list = [int(delay.strip()) for delay in delays.split(',')]
                metafunc.parametrize('power_off_delay', delay_list)
            except ValueError:
                metafunc.parametrize('power_off_delay', default_delay_list)

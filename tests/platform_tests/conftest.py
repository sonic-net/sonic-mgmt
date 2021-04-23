import glob
import json
import pytest
import os
import re
from datetime import datetime

import logging
from tests.common.fixtures.advanced_reboot import get_advanced_reboot
from .args.advanced_reboot_args import add_advanced_reboot_args
from .args.cont_warm_reboot_args import add_cont_warm_reboot_args
from .args.normal_reboot_args import add_normal_reboot_args
from .args.api_sfp_args import add_api_sfp_args

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")

@pytest.fixture(autouse=True, scope="module")
def skip_on_simx(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts["platform"]
    if "simx" in platform:
        pytest.skip('skipped on this platform: {}'.format(platform))

@pytest.fixture(scope="module")
def xcvr_skip_list(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts['platform']
    hwsku = duthost.facts['hwsku']
    f_path = os.path.join('/usr/share/sonic/device', platform, hwsku, 'hwsku.json')
    intf_skip_list = []
    try:
        out = duthost.command("cat {}".format(f_path))
        hwsku_info = json.loads(out["stdout"])
        for int_n in hwsku_info['interfaces']:
            if hwsku_info['interfaces'][int_n]['port_type'] == "RJ45":
                intf_skip_list.append(int_n)

    except Exception:
        # hwsku.json does not exist will return empty skip list
        logging.debug(
            "hwsku.json absent or port_type for interfaces not included for hwsku {}".format(hwsku))

    return intf_skip_list

@pytest.fixture()
def bring_up_dut_interfaces(request, duthosts, rand_one_dut_hostname, tbinfo):
    """
    Bring up outer interfaces on the DUT.

    Args:
        request: pytest request object
        duthost: Fixture for interacting with the DUT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    yield
    if request.node.rep_call.failed:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ports = mg_facts['minigraph_ports'].keys()

        # Enable outer interfaces
        for port in ports:
            duthost.no_shutdown(ifname=port)

def analyze_syslog(duthost, messages):
    if not messages:
        logging.error("Expected messages not found in syslog")
        return None

    service_restart_times = dict()
    service_patterns = {
        "Stopping": re.compile(r'.*Stopping.*service.*'),
        "Stopped": re.compile(r'.*Stopped.*service.*'),
        "Starting": re.compile(r'.*Starting.*service.*'),
        "Started": re.compile(r'.*Started.*service.*')
    }

    def service_time_check(message, status):
        time = message.split(duthost.hostname)[0].strip()
        service_name = message.split(status + " ")[1].split()[0]
        service_dict = service_restart_times.get(service_name, {"timestamp": {}})
        timestamps = service_dict.get("timestamp")
        if status in timestamps:
            service_dict[status+" count"] = service_dict.get(status+" count", 1) + 1
        timestamps[status] = time
        service_restart_times.update({service_name: service_dict})

    for message in messages:
        for status, pattern in service_patterns.items():
            if re.search(pattern, message):
                service_time_check(message, status)

    logging.info(json.dumps(service_restart_times, indent=4))

    FMT = "%b %d %H:%M:%S.%f"
    for _, timings in service_restart_times.items():
        timestamps = timings["timestamp"]
        timings["stop_time"] = (datetime.strptime(timestamps["Stopped"], FMT) -\
            datetime.strptime(timestamps["Stopping"], FMT)).total_seconds() \
                if "Stopped" in timestamps and "Stopping" in timestamps else None

        timings["start_time"] = (datetime.strptime(timestamps["Started"], FMT) -\
            datetime.strptime(timestamps["Starting"], FMT)).total_seconds() \
                if "Started" in timestamps and "Starting" in timestamps else None

        timings["reboot_time"] = (datetime.strptime(timestamps["Started"], FMT) -\
            datetime.strptime(timestamps["Stopped"], FMT)).total_seconds() \
                if "Started" in timestamps and "Stopped" in timestamps else None

    files = glob.glob('/tmp/*-report.json')
    if files:
        filepath = files[0]
        with open(filepath) as json_file:
            report = json.load(json_file)
            service_restart_times.update(report)

    return service_restart_times

def analyze_sairedis_rec(messages):
    state_times = dict()
    state_patterns = {
        "sai_switch_create|Started": re.compile(r'.*\|c\|SAI_OBJECT_TYPE_SWITCH.*'),
        "sai_switch_create|Stopped": re.compile(r'.*\|g\|SAI_OBJECT_TYPE_SWITCH.*SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID.*'),
        "default_route_set|Started": re.compile(r'.*\|(S|s)\|SAI_OBJECT_TYPE_ROUTE_ENTRY.*0\.0\.0\.0/0.*SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION=SAI_PACKET_ACTION_FORWARD.*')
    }

    FMT = "%b %d %H:%M:%S.%f"
    for message in messages:
        for state, pattern in state_patterns.items():
            if re.search(pattern, message):
                state_name = state.split("|")[0].strip()
                state_status = state.split("|")[1].strip()
                state_dict = state_times.get(state_name, {"timestamp": {}})
                timestamps = state_dict.get("timestamp")
                if state_status in timestamps:
                    state_dict[state_status+" count"] = state_dict.get(state_status+" count", 1) + 1
                timestamp = datetime.strptime(message.split("|")[0].strip(), "%Y-%m-%d.%H:%M:%S.%f")
                time = timestamp.strftime(FMT)
                timestamps[state_status] = time
                state_times.update({state_name: state_dict})

    for _, timings in state_times.items():
        timestamps = timings["timestamp"]
        if "Stopped" in timestamps and "Started" in timestamps:
            timings["time"] = (datetime.strptime(timestamps["Stopped"], FMT) -\
                datetime.strptime(timestamps["Started"], FMT)).total_seconds() \

    return state_times

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
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="test_advanced_reboot", 
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
    analyze_result = dict()
    for key, messages in result["expect_messages"].items():
        if "syslog" in key:
            service_restart_times = analyze_syslog(duthost, messages)
            if service_restart_times is not None:
                analyze_result["Services"] = service_restart_times

        elif "sairedis.rec" in key:
            state_times = analyze_sairedis_rec(messages)
            if state_times is not None:
                analyze_result["sairedis_state"] = state_times

    logging.info(json.dumps(analyze_result, indent=4))
    report_file_name = request.node.name + "_report.json"
    report_file_dir = os.path.realpath((os.path.join(os.path.dirname(__file__),\
        "../logs/platform_tests/")))
    report_file_path = report_file_dir + "/" + report_file_name
    if not os.path.exists(report_file_dir):
        os.makedirs(report_file_dir)
    with open(report_file_path, 'w') as fp:
        json.dump(analyze_result, fp, indent=4)


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

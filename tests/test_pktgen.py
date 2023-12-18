import logging
import pytest
import random
import re
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

ignoreRegex = [
                ".*ERR kernel.*leaba_module_device.*on error",
                ".*ERR kernel.*leaba_module_device.*received packets while buffer is full"
]

CLEANUP_CMDS = [
                "modprobe pktgen",
                "echo 'reset' > /proc/net/pktgen/pgctrl",
                "echo 'rem_device_all' > /proc/net/pktgen/kpktgend_0"
]


PKTGEN_CMDS = [
                "echo 'add_device {}' > /proc/net/pktgen/kpktgend_0",
                "echo 'count 15000' > /proc/net/pktgen/{}",
                "echo 'pkt_size 1460' > /proc/net/pktgen/{}",
                "echo 'src_min 10.10.1.2' > /proc/net/pktgen/{}",
                "echo 'dst_min 10.10.1.3' > /proc/net/pktgen/{}",
                "echo 'src_mac {}' > /proc/net/pktgen/{}",
                "echo 'dst_mac 00:06:07:08:09:00' > /proc/net/pktgen/{}",
                "echo 'udp_src_min 5000' > /proc/net/pktgen/{}",
                "echo 'udp_src_max 5000' > /proc/net/pktgen/{}",
                "echo 'udp_dst_min 5001' > /proc/net/pktgen/{}",
                "echo 'udp_dst_max 5001' > /proc/net/pktgen/{}",
                ]


def get_port_list(duthost, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    return list(mg_facts["minigraph_ports"].keys())


@pytest.fixture(scope='module')
def setup_thresholds(duthosts, enum_dut_hostname):
    duthost = duthosts[enum_dut_hostname]
    is_chassis = duthost.get_facts().get("modular_chassis")
    cpu_threshold = 70 if is_chassis else 50
    return cpu_threshold


@pytest.fixture(scope='function', autouse='True')
def clear_pktgen(duthosts, enum_dut_hostname):
    duthost = duthosts[enum_dut_hostname]
    for cmd in CLEANUP_CMDS:
        duthost.shell(cmd)
    duthost.shell("sonic-clear counters")

    yield

    for cmd in CLEANUP_CMDS:
        duthost.shell(cmd)


def test_pktgen(duthosts, enum_dut_hostname, enum_frontend_asic_index, tbinfo, loganalyzer, setup_thresholds):
    '''
    Testcase does the following steps:
    1. Check max CPU utilized , number of core and dump files before starting the run
    2. Configure pktgen traffic and start it, check if the pktgen process has generated the packets and
       if the packets are seen across the interface
    3. Check max CPU utilized , number of core and dump files after the run is complete and verify if
       there any additional core/dump files
    '''
    duthost = duthosts[enum_dut_hostname]
    router_mac = duthost.asic_instance(enum_frontend_asic_index).get_router_mac()

    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

    cpu_threshold = setup_thresholds
    # Check CPU util before sending traffic
    cpu_before = duthost.shell("show proc cpu --verbose | sed '1,/CPU/d' | awk '{print $9}'")["stdout_lines"]
    for entry in cpu_before:
        pytest_assert(
            float(entry) < cpu_threshold,
            "Cpu util was above threshold {} for atleast 1 process"
            " before sending pktgen traffic".format(cpu_threshold))

    # Check number of existing core/crash files
    core_files_pre = duthost.shell("ls /var/core | wc -l")["stdout_lines"][0]
    dump_files_pre = duthost.shell("ls /var/dump | wc -l")["stdout_lines"][0]

    # Select a random port to run traffic
    port_list = get_port_list(duthost, tbinfo)
    port = random.choice(port_list)

    # Populate packet details
    for cmd in PKTGEN_CMDS:
        if "src_mac" in cmd:
            duthost.shell(cmd.format(router_mac, port))
        else:
            duthost.shell(cmd.format(port))

    # Send packet
    duthost.shell("sudo echo 'start' > /proc/net/pktgen/pgctrl")

    # Verify packet count from pktgen
    pktgen_param = duthost.shell("cat /proc/net/pktgen/{}".format(port))["stdout"]
    pktgen_param = pktgen_param.split("\n")[0]
    pytest_assert(int(re.match(r".*count\s(\d+)", pktgen_param).group(1)) == 15000,
                  "Mismatch between number of packets intended to be generated and number of packets generated")

    # Verify packet count from interface
    interf_counters = duthost.show_interface(command="counter")['ansible_facts']['int_counter'][port]['TX_OK']
    interf_counters = interf_counters.replace(",", "")
    pytest_assert(int(interf_counters) >= 15000, "Packets were not transmitted from the interface {}, \
    15000 packets were expected but only {} found".format(port, 15000-int(interf_counters)))

    # Check CPU util after sending traffic
    cpu_after = duthost.shell("show proc cpu --verbose | sed '1,/CPU/d' | awk '{print $9}'")["stdout_lines"]
    for entry in cpu_after:
        pytest_assert(
            float(entry) < cpu_threshold,
            "Cpu util was above threshold {} for atleast 1 process"
            " after sending pktgen traffic".format(cpu_threshold))

    # Check number of new core/crash files
    core_files_new = duthost.shell("ls /var/core | wc -l")["stdout_lines"][0]
    dump_files_new = duthost.shell("ls /var/dump | wc -l")["stdout_lines"][0]
    pytest_assert(int(core_files_new)-int(core_files_pre) == 0 and int(dump_files_new)-int(dump_files_pre) == 0,
                  "New core/dump files generated during packet generation")

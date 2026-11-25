import pytest
import time
import json
import logging
import os
import re
import ipaddress
import shutil
import signal
import subprocess
import tempfile

from test_crm import RESTORE_CMDS, get_nh_ip
from tests.common.helpers.crm import CRM_POLLING_INTERVAL
from tests.common.errors import RunAnsibleModuleFail
from tests.common.utilities import wait_until, recover_acl_rule, is_ipv6_only_topology
from tests.common.platform.interface_utils import parse_intf_status
from tests.common.mellanox_data import is_mellanox_device
from tests.common.helpers.dut_utils import get_sai_sdk_dump_file, is_virtual_platform

logger = logging.getLogger(__name__)

CRM_PERF_DUT_DIR = "/tmp/crm_perf_debug"
CRM_PERF_SAMPLE_INTERVAL = 5
CRM_PERF_IDLE_BASELINE = 60
# Appends one line per interval to $1; started detached, so its PID is written to $1.pid.
# us/sy/id/wa/st are percentages of all CPUs over the interval; st (steal) is CPU time the
# hypervisor gave to other VMs; run is the number of runnable tasks; load1/5/15 are the load
# averages over 1, 5 and 15 minutes (load15 at the first sample shows how busy the host was
# before sampling started); top lists the busiest
# processes as name[pid]=cpu%. The first time a process reaches 50% CPU, a "hot" line records
# its full command line, parent, age in seconds and container (capped at 300 such lines), and a
# "behavior" line measures it for one second: user/sys CPU %, voluntary context switches (times it
# blocked waiting for input or I/O), involuntary ones (times it was preempted), read/write
# syscalls (needs root) and the kernel function it is waiting in. A spinning process blocks ~0 times; a process
# working on requests blocks between them.
CRM_PERF_SAMPLER = r"""#!/bin/bash
out=$1
interval=$2
echo $$ > $out.pid
echo "$(date '+%F %T') nproc=$(nproc) $(grep -m1 'model name' /proc/cpuinfo)" >> $out
containers=$(docker ps --format '{{.ID}}={{.Names}}' 2>/dev/null | paste -sd ' ')
echo "$(date '+%F %T') containers: ${containers:--}" >> $out
clk_tck=$(getconf CLK_TCK)
declare -A seen
hot_logged=0

probe() {
    local stat f sysc
    stat=$(cat /proc/$1/stat 2>/dev/null) || return
    f=(${stat##*) })
    sysc=$(awk '/^syscr/ {r = $2} /^syscw/ {w = $2} END {print (r == "" ? "-" : r + w)}' /proc/$1/io 2>/dev/null)
    echo "${f[0]} ${f[11]} ${f[12]}" \
         "$(awk '/^voluntary_ctxt/ {v = $2} /^nonvoluntary_ctxt/ {n = $2} END {print v, n}' /proc/$1/status)" \
         "${sysc:--}"
}

read -r _ u n s i w q sq st _ < /proc/stat
while true; do
    procs=$(top -b -n 2 -d 1 -w 512 | awk '/^top -/{f++} f == 2 && $1 ~ /^[0-9]+$/ {print $1, $9, $12}' \
            | head -n 5)
    top5=$(echo "$procs" | awk 'NF {print $3 "[" $1 "]=" $2}' | paste -sd ' ')
    declare -A before=()
    while read -r pid cpu comm; do
        [ -n "$pid" ] && [ "${cpu%.*}" -ge 50 ] && [ -z "${seen[$pid]}" ] && [ $hot_logged -lt 300 ] || continue
        seen[$pid]=1
        hot_logged=$((hot_logged + 1))
        ctr=$(grep -o -m1 '[0-9a-f]\{64\}' /proc/$pid/cgroup 2>/dev/null | head -n 1 | cut -c1-12)
        read -r ppid age < <(ps -o ppid=,etimes= -p $pid 2>/dev/null)
        pcomm=$(ps -o comm= -p "${ppid:-0}" 2>/dev/null)
        cmd=$(tr '\0\n' '  ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-300)
        echo "$(date '+%F %T') hot pid=$pid cpu=$cpu comm=$comm container=${ctr:-host}" \
             "ppid=${ppid:--}($pcomm) age_s=${age:--} cmd=${cmd:--}" >> $out
        before[$pid]=$(probe $pid)
    done <<< "$procs"
    if [ ${#before[@]} -gt 0 ]; then
        sleep 1
        for pid in "${!before[@]}"; do
            read -r _ pu1 ps1 pv1 pn1 pc1 <<< "${before[$pid]}"
            after=$(probe $pid)
            if [ -z "$after" ] || [ -z "$pu1" ]; then
                echo "$(date '+%F %T') behavior pid=$pid exited during measurement" >> $out
                continue
            fi
            read -r pstate pu2 ps2 pv2 pn2 pc2 <<< "$after"
            sysc="-"
            [ "$pc1" = "-" ] || [ "$pc2" = "-" ] || sysc=$((pc2 - pc1))
            echo "$(date '+%F %T') behavior pid=$pid over 1s: state=$pstate" \
                 "user%=$(( (pu2 - pu1) * 100 / clk_tck )) sys%=$(( (ps2 - ps1) * 100 / clk_tck ))" \
                 "blocked=$((pv2 - pv1)) preempted=$((pn2 - pn1)) rw_syscalls=$sysc" \
                 "wchan=$(cat /proc/$pid/wchan 2>/dev/null)" >> $out
        done
    fi
    sleep $((interval - 1))
    read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
    total=$(( (u2 + n2 + s2 + i2 + w2 + q2 + sq2 + st2) - (u + n + s + i + w + q + sq + st) ))
    [ "$total" -gt 0 ] || total=1
    run=$(awk '/^procs_running/ {print $2}' /proc/stat)
    psi=$(awk '/^some/ {sub("avg10=", "", $2); print $2}' /proc/pressure/cpu 2>/dev/null)
    echo "$(date '+%F %T') us=$(( 100 * (u2 + n2 - u - n) / total ))" \
         "sy=$(( 100 * (s2 + q2 + sq2 - s - q - sq) / total )) id=$(( 100 * (i2 - i) / total ))" \
         "wa=$(( 100 * (w2 - w) / total )) st=$(( 100 * (st2 - st) / total ))" \
         "run=$run load1/5/15=$(cut -d ' ' -f1-3 /proc/loadavg | tr ' ' /) psi_some10=${psi:--} top: $top5" >> $out
    u=$u2; n=$n2; s=$s2; i=$i2; w=$w2; q=$q2; sq=$sq2; st=$st2
done
"""


class CrmPerfSampler(object):
    """Run CRM_PERF_SAMPLER on the DUT and on the test runner and copy new samples into the test log."""

    def __init__(self, duthost):
        self.duthost = duthost
        self.dut_out = os.path.join(CRM_PERF_DUT_DIR, "samples.log")
        self.runner_dir = tempfile.mkdtemp(prefix="crm_perf_debug_")
        self.runner_out = os.path.join(self.runner_dir, "samples.log")
        self.dut_lines_logged = 0
        self.runner_lines_logged = 0

    def start(self):
        script = os.path.join(CRM_PERF_DUT_DIR, "sampler.sh")
        self.duthost.shell("sudo rm -rf {0} && mkdir -p {0}".format(CRM_PERF_DUT_DIR))
        self.duthost.copy(content=CRM_PERF_SAMPLER, dest=script)
        self.duthost.shell("sudo setsid bash {} {} {} < /dev/null > /dev/null 2>&1 &".format(
            script, self.dut_out, CRM_PERF_SAMPLE_INTERVAL))

        script = os.path.join(self.runner_dir, "sampler.sh")
        with open(script, "w") as f:
            f.write(CRM_PERF_SAMPLER)
        subprocess.Popen(["setsid", "bash", script, self.runner_out, str(CRM_PERF_SAMPLE_INTERVAL)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        dut_epoch = float(self.duthost.shell("date +%s.%N")["stdout"])
        logger.info("CRM_PERF sampling started every %s s; DUT clock minus runner clock = %.1f s",
                    CRM_PERF_SAMPLE_INTERVAL, dut_epoch - time.time())

        # No Ansible calls during this window, so the samples show the DUT's own background load.
        logger.info("CRM_PERF idle baseline start (%s s)", CRM_PERF_IDLE_BASELINE)
        time.sleep(CRM_PERF_IDLE_BASELINE)
        logger.info("CRM_PERF idle baseline end")
        self.log_new_samples()

    def log_new_samples(self):
        result = self.duthost.shell("tail -n +{} {}".format(self.dut_lines_logged + 1, self.dut_out),
                                    module_ignore_errors=True)
        lines = result.get("stdout_lines", [])
        self.dut_lines_logged += len(lines)
        for line in lines:
            logger.info("CRM_PERF dut    | %s", line)

        try:
            with open(self.runner_out) as f:
                lines = f.read().splitlines()[self.runner_lines_logged:]
        except IOError:
            lines = []
        self.runner_lines_logged += len(lines)
        for line in lines:
            logger.info("CRM_PERF runner | %s", line)

    def stop(self):
        self.log_new_samples()
        self.duthost.shell("sudo kill $(cat {0}.pid); sudo rm -rf {1}".format(self.dut_out, CRM_PERF_DUT_DIR),
                           module_ignore_errors=True)
        try:
            with open(self.runner_out + ".pid") as f:
                os.kill(int(f.read()), signal.SIGTERM)
        except (IOError, ValueError, OSError):
            pass
        shutil.rmtree(self.runner_dir, ignore_errors=True)


@pytest.fixture(scope="module", autouse=True)
def crm_perf_sampler(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Sample CPU on KVM testbeds to tell CPU steal on the DUT apart from a slow test runner."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if not is_virtual_platform(duthost):
        yield None
        return
    sampler = CrmPerfSampler(duthost)
    sampler.start()
    yield sampler
    sampler.stop()


@pytest.fixture(autouse=True)
def crm_perf_test_samples(request, crm_perf_sampler):
    """Log each test's duration followed by the CPU samples taken while it ran."""
    if crm_perf_sampler is None:
        yield
        return
    start = time.time()
    logger.info("CRM_PERF start %s", request.node.nodeid)
    yield
    logger.info("CRM_PERF end %s after %.1f s", request.node.nodeid, time.time() - start)
    crm_perf_sampler.log_new_samples()


def pytest_runtest_teardown(item, nextitem):
    """ called after ``pytest_runtest_call``.

    :arg nextitem: the scheduled-to-be-next test item (None if no further
                   test item is scheduled).  This argument can be used to
                   perform exact teardowns, i.e. calling just enough finalizers
                   so that nextitem only needs to call setup-functions.
    """
    failures = []
    crm_threshold_name = RESTORE_CMDS.get("crm_threshold_name")
    restore_cmd = "sonic-db-cli CONFIG_DB hmset 'CRM|Config' \
    {threshold_name}_high_threshold {high} \
    {threshold_name}_low_threshold {low} \
    {threshold_name}_threshold_type percentage"
    if item.rep_setup.passed and not item.rep_call.skipped:
        test_name = item.function.__name__
        duthosts = item.funcargs['duthosts']
        hostname = item.funcargs['enum_rand_one_per_hwsku_frontend_hostname']
        dut = None
        if duthosts and hostname:   # unable to test hostname in duthosts
            dut = duthosts[hostname]

        if not dut:
            dut = item.funcargs['duthost']
            logger.warning('fallback to use duthost {} instead from {} {}'.format(dut.hostname, duthosts, hostname))
            hostname = dut.hostname

        # Restore CRM thresholds on the correct DUT
        if crm_threshold_name:
            crm_thresholds = item.funcargs["crm_thresholds"]
            cmd = restore_cmd.format(threshold_name=crm_threshold_name, high=crm_thresholds[crm_threshold_name]["high"],
                                     low=crm_thresholds[crm_threshold_name]["low"])
            logger.info("Restore CRM thresholds on {}. Execute: {}".format(hostname, cmd))
            # Restore default CRM thresholds
            dut.command(cmd)

        logger.info("Execute test cleanup: dut {} {}".format(hostname, json.dumps(RESTORE_CMDS, indent=4)))
        # Restore DUT after specific test steps
        # Test case name is used to mitigate incorrect cleanup if some of tests was failed on cleanup step and list of
        # cleanup commands was not cleared
        if test_name not in RESTORE_CMDS:
            return

        for cmd in RESTORE_CMDS[test_name]:
            logger.info(cmd)
            try:
                if isinstance(cmd, dict):
                    recover_acl_rule(dut, cmd["data_acl"])
                else:
                    dut.shell(cmd)
            except RunAnsibleModuleFail as err:
                failures.append("Failure during command execution '{command}':\n{error}"
                                .format(command=cmd, error=str(err)))

        RESTORE_CMDS[test_name] = []

        if RESTORE_CMDS["wait"]:
            logger.info("Waiting {} seconds to process cleanup...".format(RESTORE_CMDS["wait"]))
            time.sleep(RESTORE_CMDS["wait"])

        if failures:
            message = "\n".join(failures)
            pytest.fail(message)


@pytest.fixture(scope="module", autouse=True)
def crm_thresholds(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cmd = "sonic-db-cli CONFIG_DB hget \"CRM|Config\" {threshold_name}_{type}_threshold"
    crm_res_list = ["ipv4_route", "ipv6_route", "ipv4_nexthop", "ipv6_nexthop", "ipv4_neighbor", "ipv6_neighbor",
                    "nexthop_group_member", "nexthop_group", "acl_counter", "acl_entry", "fdb_entry"]
    res = {}
    for item in crm_res_list:
        high = duthost.command(cmd.format(threshold_name=item, type="high"))["stdout_lines"][0]
        low = duthost.command(cmd.format(threshold_name=item, type="low"))["stdout_lines"][0]
        res[item] = {}
        res[item]["high"] = high
        res[item]["low"] = low

    return res


@pytest.fixture(scope="module", autouse=True)
def crm_interface(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, enum_frontend_asic_index):
    """ Return tuple of two DUT interfaces """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    if "backend" in tbinfo["topo"]["name"]:
        crm_intf1 = mg_facts["minigraph_vlan_sub_interfaces"][0]["attachto"]
        crm_intf2 = mg_facts["minigraph_vlan_sub_interfaces"][2]["attachto"]
    else:
        crm_intf1 = None
        crm_intf2 = None
        intf_status = asichost.show_interface(command='status')['ansible_facts']['int_status']

        # 1. we try to get crm interfaces from portchannel interfaces
        for a_pc in mg_facts["minigraph_portchannels"]:
            if a_pc not in intf_status:
                continue
            if intf_status[a_pc]['oper_state'] == 'up':
                # this is a pc that I can use.
                if crm_intf1 is None:
                    crm_intf1 = a_pc
                elif crm_intf2 is None:
                    crm_intf2 = a_pc

        if crm_intf1 is not None and crm_intf2 is not None:
            return (crm_intf1, crm_intf2)

        # 2.  we try to get crm interfaces from routed interfaces
        for a_intf in mg_facts["minigraph_interfaces"]:
            intf = a_intf['attachto']
            if intf not in intf_status:
                continue
            if intf_status[intf]['oper_state'] == 'up':
                if crm_intf1 is None:
                    crm_intf1 = intf
                elif crm_intf2 is None:
                    crm_intf2 = intf

    if crm_intf1 is not None and crm_intf2 is not None:
        return (crm_intf1, crm_intf2)

    if crm_intf1 is None or crm_intf2 is None:
        pytest.skip("Not enough interfaces on this host/asic (%s/%s) to support test." % (duthost.hostname,
                                                                                          asichost.asic_index))


@pytest.fixture(scope="module", autouse=False)
def set_polling_interval(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_time = 2

    # Get polling interval
    output = duthost.command('crm show summary')['stdout']
    parsed = re.findall(r'Polling Interval: +(\d+) +second', output)
    original_crm_polling_interval = int(parsed[0])

    # Set CRM polling interval to 1 second
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))["stdout"]
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)

    yield

    # Set CRM polling interval to original value
    duthost.command("crm config polling interval {}".format(original_crm_polling_interval))["stdout"]
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)


def get_intf_list(duthost, tbinfo, enum_frontend_asic_index):
    """ Return the interface list which would influence fdb entry by mac learning """
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)
    intf_connect_with_ptf = []
    for intf, intf_desc in mg_facts["minigraph_neighbors"].items():
        if "Server" in intf_desc['name']:
            intf_connect_with_ptf.append(intf)
    return intf_connect_with_ptf


def check_interface_status(duthost, intf_list, expected_oper='up'):
    """ Check interface status """
    output = duthost.command("show interface description")
    intf_status = parse_intf_status(output["stdout_lines"][2:])
    for intf in intf_list:
        if intf not in intf_status:
            logging.info("Missing status for interface %s" % intf)
            return False
        if intf_status[intf]["oper"] != expected_oper:
            logging.info("Oper status of interface {} is {}, expected {}".format(intf, intf_status[intf]["oper"],
                                                                                 expected_oper))
            return False
    return True


def configure_a_route_with_same_prefix_as_vlan_for_mlnx(duthost, asichost, tbinfo, crm_interface, ip_ver):
    """
    For mellanox device, the crm available counter is related to LPM tree.
    When shutdown all interfaces in vlan (e.g. vlan 1000),
    it will cause the route (e.g. 192.168.0.1/21 )for vlan to be removed, we have only one route for the prefix (21),
    so after it is removed, the corresponding prefix in LPM tree will be removed too,
    which will lead to the LPM tree structure is changed.
    LPM tree change might cause available counter change dramatically,
    but we cannot estimate how long the change is ready.
    Therefore, it will lead the first case of test_crm_route fail occasionally
    because the expected available counter is not decreased.
    So, we add another route with the same prefix as the vlan's so that the LPM tree is not changed.
    """
    # Get NH IP
    nh_ip = get_nh_ip(duthost, asichost, crm_interface, ip_ver)
    prefix_len = get_vlan_prefix_len_per_ip_ver(asichost, tbinfo, ip_ver)

    if ip_ver == "4":
        dump_ip_for_construct_test_route_with_same_prefix_as_vlan_interface = '21.21.21.21'
        network_with_same_prefix_as_vlan_interface = str(
            ipaddress.IPv4Interface(
                f"{dump_ip_for_construct_test_route_with_same_prefix_as_vlan_interface}/{prefix_len}").network)
    else:
        dump_ip_for_construct_test_route_with_same_prefix_as_vlan_interface = '2021:21:21:21::21'
        network_with_same_prefix_as_vlan_interface = str(
            ipaddress.IPv6Interface(
                f"{dump_ip_for_construct_test_route_with_same_prefix_as_vlan_interface}/{prefix_len}").network)

    add_route_command = f"sudo ip {'-6' if ip_ver == '6' else ''} \
                    route add {network_with_same_prefix_as_vlan_interface} via {nh_ip}"
    route_check_command = f"show {'ipv6' if ip_ver == '6' else 'ip'} route {network_with_same_prefix_as_vlan_interface}"
    del_dump_route_with_same_prefix_as_vlan_interface_cmd = f"sudo ip {'-6' if ip_ver == '6' else ''} \
                    route del {network_with_same_prefix_as_vlan_interface} via {nh_ip}"

    duthost.shell(add_route_command, module_ignore_errors=True)
    assert wait_until(30, 5, 0, check_route_exist, duthost,
                      network_with_same_prefix_as_vlan_interface, nh_ip, route_check_command), \
           f"Failed to add route {network_with_same_prefix_as_vlan_interface} via {nh_ip}"

    get_sai_sdk_dump_file(duthost, "sai_sdk_dump_before_shutdown_vlan_ports")

    return del_dump_route_with_same_prefix_as_vlan_interface_cmd


def check_route_exist(duthost, network_with_same_prefix_as_vlan_interface, nh_ip, route_check_command):
    route_output = duthost.shell(route_check_command)["stdout"]
    return f"Routing entry for {network_with_same_prefix_as_vlan_interface}" in route_output and nh_ip in route_output


def get_vlan_prefix_len_per_ip_ver(asichost, tbinfo, ip_ver):
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)
    for vlan_port_data in mg_facts["minigraph_vlan_interfaces"]:
        if ipaddress.ip_interface(vlan_port_data['addr']).version == int(ip_ver):
            logger.info(f"vlan interface {ip_ver} prefix is: {vlan_port_data['prefixlen']}")
            return vlan_port_data['prefixlen']
    assert False, f"Not find {ip_ver} prefix for vlan interface config"


@pytest.fixture(scope="module", autouse=True)
def shutdown_unnecessary_intf(
        duthosts, tbinfo, enum_frontend_asic_index, enum_rand_one_per_hwsku_frontend_hostname, crm_interface, request):
    """ Shutdown unused interfaces to avoid fdb entry influenced by mac learning """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    intfs_connect_with_ptf = get_intf_list(duthost, tbinfo, enum_frontend_asic_index)
    ip_ver = "4" if not is_ipv6_only_topology(tbinfo) else "6"

    del_dump_route_with_same_prefix_as_vlan_interface_cmd = None
    if intfs_connect_with_ptf:
        if is_mellanox_device(duthost):
            del_dump_route_with_same_prefix_as_vlan_interface_cmd = configure_a_route_with_same_prefix_as_vlan_for_mlnx(
                duthost, asichost, tbinfo, crm_interface, ip_ver)
        logger.info("Shutdown interfaces: {}".format(intfs_connect_with_ptf))
        duthost.shutdown_multiple(intfs_connect_with_ptf)
        assert wait_until(300, 20, 0, check_interface_status, duthost, intfs_connect_with_ptf, 'down'), \
            "All interfaces should be down!"

        if is_mellanox_device(duthost):
            # Get sai sdk dump file in case test fail, we can get the LPM tree information
            get_sai_sdk_dump_file(duthost, "sai_sdk_dump_after_shutdown_vlan_ports")

    yield

    if intfs_connect_with_ptf:
        logger.info("Startup interfaces: {}".format(intfs_connect_with_ptf))
        duthost.no_shutdown_multiple(intfs_connect_with_ptf)
        assert wait_until(300, 20, 0, check_interface_status, duthost, intfs_connect_with_ptf), \
            "All interfaces should be up!"
        if is_mellanox_device(duthost) and del_dump_route_with_same_prefix_as_vlan_interface_cmd:
            duthost.shell(del_dump_route_with_same_prefix_as_vlan_interface_cmd)


@pytest.fixture(scope="module")
def collector(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """ Fixture for sharing variables between test cases """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    data = {}
    for asic in duthost.asics:
        data[asic.asic_index] = {}

    yield data


@pytest.fixture(scope="function")
def cleanup_ptf_interface(duthosts, ip_ver, enum_rand_one_per_hwsku_frontend_hostname,
                          enum_frontend_asic_index, ptfhost):

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    if ip_ver == "4":
        ip_remove_cmd = "config interface ip remove Ethernet1 2.2.2.1/24"
    else:
        ip_remove_cmd = "config interface ip remove Ethernet1 2001::2/64"
    check_vlan_cmd = "show vlan br | grep -w 'Ethernet1'"

    yield

    if duthost.facts["asic_type"] in ["marvell-prestera", "marvell"]:
        asichost.shell(ip_remove_cmd)
        # Check if member not removed
        output = asichost.shell(check_vlan_cmd, module_ignore_errors=True)
        if "Ethernet1" not in output['stdout']:
            asichost.sonichost.add_member_to_vlan(1000, 'Ethernet1', is_tagged=False)
        ptfhost.remove_ip_addresses()


@pytest.fixture(scope="module", autouse=True)
def crm_resources(duthosts, enum_rand_one_per_hwsku_frontend_hostname, set_polling_interval):
    """
    Parse the CRM resource table from the 'crm show resources all' command output,
    retrying if CRM counters are not ready.
    Returns a dictionary of the form:
    {
        "ipv4_route": {"used": 6475, "available": 140981},
    }
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    resources = {}

    def get_crm_resources(resources_dict):
        cmd_output = duthost.shell("crm show resources all")["stdout"]
        if "CRM counters are not ready" in cmd_output:
            return False

        lines = cmd_output.splitlines()
        started = False

        for line in lines:
            # Detect the start of the first resource table
            if re.search(r"^Resource Name\s+Used Count\s+Available Count", line):
                started = True
                continue

            if started:
                # Once we hit an empty or non-data line, stop
                if not line.strip() or re.search(r"^Stage\s+Bind Point", line):
                    break
                if re.match(r"^-+\s+-+\s+-+$", line):
                    continue

                parts = line.split()
                if len(parts) >= 3:
                    resource_name = parts[0].strip()
                    used_count = int(parts[1])
                    available_count = int(parts[2])
                    resources_dict[resource_name] = {
                        "used": used_count,
                        "available": available_count
                    }
        return True if resources_dict else False

    # Wait up to 360 seconds, checking every 5 seconds
    wait_until(360, 5, 0, get_crm_resources, resources)
    if not resources:
        pytest.fail("CRM counters are not ready after multiple retries.")

    return resources

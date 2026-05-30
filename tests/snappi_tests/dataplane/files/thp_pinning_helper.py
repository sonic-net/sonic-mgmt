import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require

logger = logging.getLogger(__name__)

DEFAULT_TEST_VLAN_CIDR = "20.0.0.1/24"
DEFAULT_TEST_VLAN_TGEN_SRC_IP = "20.0.0.2"
DEFAULT_EGRESS_DUT_CIDR = "30.0.0.1/24"
DEFAULT_EGRESS_TGEN_IP = "30.0.0.2"
DEFAULT_EGRESS_TGEN_MAC = "02:00:00:00:00:02"
DEFAULT_SRC_MAC_START = "12:34:56:78:00:01"
DEFAULT_SRC_MAC_STEP = "00:00:00:00:00:01"
DEFAULT_SRC_MAC_COUNT = 10000
DEFAULT_TRAFFIC_PPS_PER_PORT = 200000
DEFAULT_FRAME_SIZE = 256
DEFAULT_PINNING_DURATION_SEC = 30 * 60
DEFAULT_PINNING_PHASE1_SEC = 20 * 60
DEFAULT_PINNING_ACCUM_INTERVAL_SEC = 120
DEFAULT_PINNING_CHURN_INTERVAL_SEC = 10
DEFAULT_AHP_THRESHOLD_KB = 1024 * 1024
DEFAULT_AHP_THRESHOLD_WINDOW_SEC = 10 * 60
DEFAULT_MONITOR_INTERVAL_SEC = 30
DEFAULT_MEM_MONITOR_LOG = "/tmp/orchagent_mem_monitor.txt"
DEFAULT_PINNING_SCRIPT = "/tmp/thp_pinning_workload.sh"
DEFAULT_PINNING_LOG = "/tmp/thp_pinning_workload.log"

PINNING_PORT_PROFILES = [
    {
        "route_base": "10.88",
        "ip_cidr": "10.88.0.1/24",
        "nh": "10.88.0.2",
        "churn_base": "172.88",
        "churn_nh": "10.88.0.100",
        "mac_prefix": "00:aa:bb:ee",
        "churn_mac_prefix": "00:cc:dd:ee",
    },
    {
        "route_base": "10.92",
        "ip_cidr": "10.92.0.1/24",
        "nh": "10.92.0.2",
        "churn_base": "172.92",
        "churn_nh": "10.92.0.100",
        "mac_prefix": "00:aa:bb:cc",
        "churn_mac_prefix": "00:cc:dd:cc",
    },
]


def select_snappi_test_ports(snappi_ports, required_ports=5):
    """Select direct Snappi ports connected to one single-ASIC DUT."""
    ports_by_dut = {}
    for port in snappi_ports:
        ports_by_dut.setdefault(port["peer_device"], []).append(port)

    eligible_groups = [
        ports
        for ports in ports_by_dut.values()
        if len(ports) >= required_ports
    ]
    pytest_require(
        eligible_groups,
        "Need at least {} Snappi ports connected to the same DUT".format(required_ports)
    )

    selected_ports = sorted(
        eligible_groups,
        key=len,
        reverse=True
    )[0][:required_ports]
    duthost = selected_ports[0]["duthost"]
    pytest_require(
        duthost.facts.get("num_asic", 1) == 1,
        "THP pinning FDB storm test currently supports single-ASIC DUTs only"
    )

    return duthost, selected_ports[:4], selected_ports[4]


def select_pinning_ports(duthost, excluded_ports, required_ports=2):
    """Select admin-up, oper-up Ethernet ports not used by the FDB storm."""
    excluded_ports = set(excluded_ports)
    status = duthost.get_interfaces_status()
    candidates = []
    for intf, info in status.items():
        if not intf.startswith("Ethernet") or intf in excluded_ports:
            continue
        if info.get("admin", "up") == "up" and info.get("oper") == "up":
            candidates.append(intf)

    candidates = sorted(candidates, key=_natural_port_sort_key)
    pytest_require(
        len(candidates) >= required_ports,
        "Need {} admin-up, oper-up non-storm ports for THP pinning, got {}".format(
            required_ports, candidates)
    )
    return candidates[:required_ports]


def _natural_port_sort_key(port_name):
    digits = "".join(ch for ch in port_name if ch.isdigit())
    return int(digits) if digits else 0


def find_unused_vlan_id(duthost, start=3000, stop=3999):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    used_vlans = {
        int(vlan.replace("Vlan", ""))
        for vlan in config_facts.get("VLAN", {})
        if vlan.startswith("Vlan") and vlan.replace("Vlan", "").isdigit()
    }
    for vlan_id in range(start, stop + 1):
        if vlan_id not in used_vlans:
            return vlan_id
    pytest.fail("No unused VLAN ID found in range {}-{}".format(start, stop))
    return None


def configure_dut_for_fdb_storm(duthost, ingress_ports, egress_port, pinning_ports, vlan_id):
    """Configure 4 ingress ports in one VLAN and one routed egress port."""
    test_ports = [port["peer_port"] for port in ingress_ports] + [egress_port["peer_port"]] + pinning_ports
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]

    for port in test_ports:
        _remove_port_from_vlan_members(duthost, config_facts, port)
        _remove_port_from_portchannel_members(duthost, config_facts, port)
        _remove_port_ip_addresses(duthost, config_facts, port)

    _run_checked(duthost, "sudo config vlan add {}".format(vlan_id))
    _run_checked(duthost, "sudo config interface ip add Vlan{} {}".format(vlan_id, DEFAULT_TEST_VLAN_CIDR))
    for port in ingress_ports:
        _run_checked(duthost, "sudo config vlan member add -u {} {}".format(vlan_id, port["peer_port"]))

    _run_checked(
        duthost,
        "sudo config interface ip add {} {}".format(egress_port["peer_port"], DEFAULT_EGRESS_DUT_CIDR)
    )
    _run_checked(
        duthost,
        "sudo ip neigh replace {} lladdr {} dev {}".format(
            DEFAULT_EGRESS_TGEN_IP, DEFAULT_EGRESS_TGEN_MAC, egress_port["peer_port"])
    )

    for pinning_port, profile in zip(pinning_ports, PINNING_PORT_PROFILES):
        _run_checked(duthost, "sudo config interface ip add {} {}".format(pinning_port, profile["ip_cidr"]))

    for port in test_ports:
        _run_checked(duthost, "sudo config interface startup {}".format(port), ignore_errors=True)

    duthost.shell("sudo sonic-clear fdb all", module_ignore_errors=True)
    duthost.shell("sudo sonic-clear arp", module_ignore_errors=True)
    time.sleep(10)


def _remove_port_from_vlan_members(duthost, config_facts, port):
    for vlan, members in config_facts.get("VLAN_MEMBER", {}).items():
        if port in members:
            vlan_id = vlan.replace("Vlan", "")
            _run_checked(
                duthost,
                "sudo config vlan member del {} {}".format(vlan_id, port),
                ignore_errors=True
            )


def _remove_port_from_portchannel_members(duthost, config_facts, port):
    for member_key in config_facts.get("PORTCHANNEL_MEMBER", {}):
        portchannel = None
        member = None
        if isinstance(member_key, str) and "|" in member_key:
            portchannel, member = member_key.split("|", 1)
        elif isinstance(config_facts["PORTCHANNEL_MEMBER"].get(member_key), dict):
            members = config_facts["PORTCHANNEL_MEMBER"].get(member_key, {})
            if port in members:
                portchannel, member = member_key, port
        if member == port:
            _run_checked(
                duthost,
                "sudo config portchannel member del {} {}".format(portchannel, port),
                ignore_errors=True
            )


def _remove_port_ip_addresses(duthost, config_facts, port):
    for addr in config_facts.get("INTERFACE", {}).get(port, {}):
        if "/" in addr:
            _run_checked(
                duthost,
                "sudo config interface ip remove {} {}".format(port, addr),
                ignore_errors=True
            )


def _run_checked(duthost, cmd, ignore_errors=False):
    logger.info("Running on DUT %s: %s", duthost.hostname, cmd)
    result = duthost.shell(cmd, module_ignore_errors=ignore_errors)
    if not ignore_errors:
        pytest_assert(result["rc"] == 0, "Command failed: {}\n{}".format(cmd, result.get("stderr", "")))
    return result


def generate_fdb_storm_config(testbed_config, ingress_ports, egress_port, duration_sec=DEFAULT_PINNING_DURATION_SEC):
    """Generate stateless direct Snappi flows for the FDB storm."""
    egress_port_name = _snappi_port_name(testbed_config, egress_port)

    for index, ingress_port in enumerate(ingress_ports):
        flow = testbed_config.flows.flow(name="THP FDB storm {}".format(index))[-1]
        flow.tx_rx.port.tx_name = _snappi_port_name(testbed_config, ingress_port)
        flow.tx_rx.port.rx_name = egress_port_name

        eth, ipv4 = flow.packet.ethernet().ipv4()
        eth.src.increment.start = DEFAULT_SRC_MAC_START
        eth.src.increment.step = DEFAULT_SRC_MAC_STEP
        eth.src.increment.count = DEFAULT_SRC_MAC_COUNT
        eth.dst.value = ingress_port["duthost"].facts["router_mac"]

        ipv4.src.value = _ingress_src_ip(index)
        ipv4.dst.value = DEFAULT_EGRESS_TGEN_IP

        flow.size.fixed = DEFAULT_FRAME_SIZE
        flow.rate.pps = DEFAULT_TRAFFIC_PPS_PER_PORT
        flow.duration.fixed_seconds.seconds = duration_sec
        flow.metrics.enable = True
        flow.metrics.loss = True

    return testbed_config


def _snappi_port_name(testbed_config, snappi_port):
    return testbed_config.ports[int(snappi_port["port_id"])].name


def _ingress_src_ip(index):
    return "20.0.0.{}".format(index + 2)


def render_thp_pinning_script(pinning_ports,
                              duration_sec=DEFAULT_PINNING_DURATION_SEC,
                              phase1_sec=DEFAULT_PINNING_PHASE1_SEC,
                              accum_interval_sec=DEFAULT_PINNING_ACCUM_INTERVAL_SEC,
                              churn_interval_sec=DEFAULT_PINNING_CHURN_INTERVAL_SEC):
    profiles = PINNING_PORT_PROFILES[:len(pinning_ports)]
    arrays = {
        "PORTS": pinning_ports,
        "ROUTE_BASES": [profile["route_base"] for profile in profiles],
        "NEXTHOPS": [profile["nh"] for profile in profiles],
        "CHURN_BASES": [profile["churn_base"] for profile in profiles],
        "CHURN_NEXTHOPS": [profile["churn_nh"] for profile in profiles],
        "MAC_PREFIXES": [profile["mac_prefix"] for profile in profiles],
        "CHURN_MAC_PREFIXES": [profile["churn_mac_prefix"] for profile in profiles],
    }
    array_lines = "\n".join(_bash_array(name, values) for name, values in arrays.items())
    return """#!/bin/bash
set -u

DURATION={duration_sec}
PHASE1_END={phase1_sec}
ACCUM_INTERVAL={accum_interval_sec}
CHURN_INTERVAL={churn_interval_sec}
START_TIME=$(date +%s)
CYCLE=0
ACCUM_BATCH=0
PORT_COUNT={port_count}

{array_lines}

echo "THP pinning workload started: $(date)"
echo "Duration: $DURATION seconds, phase1: $PHASE1_END seconds"
echo "Ports: ${{PORTS[*]}}"

PID=$(pgrep -x orchagent | head -n 1)
echo "Orchagent PID: $PID"
if [ -n "$PID" ]; then
    awk '/VmRSS/{{print "Baseline RSS:", $2, $3}}' /proc/$PID/status
    sudo grep AnonHugePages /proc/$PID/smaps_rollup | awk '{{print "Baseline AnonHP:", $2, $3}}'
fi

while true; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    if [ "$ELAPSED" -ge "$DURATION" ]; then
        echo "$(date): workload duration elapsed"
        break
    fi

    CYCLE=$((CYCLE + 1))
    if [ "$ELAPSED" -lt "$PHASE1_END" ]; then
        ACCUM_BATCH=$((ACCUM_BATCH + 1))
        echo "$(date): Phase 1 cycle $CYCLE batch $ACCUM_BATCH"
        for idx in $(seq 0 $((PORT_COUNT - 1))); do
            route_base=${{ROUTE_BASES[$idx]}}
            nexthop=${{NEXTHOPS[$idx]}}
            port=${{PORTS[$idx]}}
            mac_prefix=${{MAC_PREFIXES[$idx]}}
            for i in $(seq 1 5); do
                item=$(( (ACCUM_BATCH - 1) * 5 + i ))
                sudo config route add prefix "${{route_base}}.${{item}}.0/24" nexthop "$nexthop"
                sudo ip neigh replace "${{nexthop%.*}}.$((item + 10))" \\
                    lladdr "${{mac_prefix}}:$(printf '%02x' $((ACCUM_BATCH % 256))):$(printf '%02x' $i)" \\
                    dev "$port"
            done
        done
        echo "Accumulated objects: $((ACCUM_BATCH * 5 * PORT_COUNT)) routes and neighbors"
        sleep "$ACCUM_INTERVAL"
    else
        echo "$(date): Phase 2 churn cycle $CYCLE"
        for idx in $(seq 0 $((PORT_COUNT - 1))); do
            churn_base=${{CHURN_BASES[$idx]}}
            churn_nexthop=${{CHURN_NEXTHOPS[$idx]}}
            port=${{PORTS[$idx]}}
            churn_mac_prefix=${{CHURN_MAC_PREFIXES[$idx]}}
            for i in $(seq 1 10); do
                sudo config route add prefix "${{churn_base}}.${{i}}.0/24" nexthop "$churn_nexthop"
                sudo ip neigh replace "${{churn_nexthop%.*}}.$((i + 10))" \\
                    lladdr "${{churn_mac_prefix}}:$(printf '%02x' $((CYCLE % 256))):$(printf '%02x' $i)" \\
                    dev "$port"
            done
            sleep 1
            for i in $(seq 1 10); do
                sudo config route del prefix "${{churn_base}}.${{i}}.0/24" nexthop "$churn_nexthop" 2>/dev/null
                sudo ip neigh del "${{churn_nexthop%.*}}.$((i + 10))" dev "$port" 2>/dev/null
            done
        done
        sleep "$CHURN_INTERVAL"
    fi

    PID=$(pgrep -x orchagent | head -n 1)
    if [ -n "$PID" ]; then
        RSS=$(awk '/VmRSS/{{print $2}}' /proc/$PID/status)
        AHP=$(sudo grep AnonHugePages /proc/$PID/smaps_rollup | awk '{{print $2}}')
        echo "orchagent RSS: ${{RSS}} kB | AnonHugePages: ${{AHP}} kB"
    else
        echo "orchagent is not running"
    fi
done
""".format(duration_sec=duration_sec,
           phase1_sec=phase1_sec,
           accum_interval_sec=accum_interval_sec,
           churn_interval_sec=churn_interval_sec,
           port_count=len(pinning_ports),
           array_lines=array_lines)


def _bash_array(name, values):
    quoted_values = " ".join('"{}"'.format(value) for value in values)
    return "{}=({})".format(name, quoted_values)


def start_thp_pinning_workload(duthost, script):
    duthost.copy(content=script, dest=DEFAULT_PINNING_SCRIPT)
    duthost.shell("sudo chmod +x {}".format(DEFAULT_PINNING_SCRIPT))
    result = duthost.shell(
        "nohup sudo bash {} > {} 2>&1 & echo $!".format(DEFAULT_PINNING_SCRIPT, DEFAULT_PINNING_LOG)
    )
    pid = result["stdout"].strip().splitlines()[-1]
    pytest_assert(pid.isdigit(), "Failed to start THP pinning workload: {}".format(result["stdout"]))
    return int(pid)


def stop_thp_pinning_workload(duthost, pid):
    if pid is None:
        return
    duthost.shell("if kill -0 {pid} 2>/dev/null; then sudo kill {pid}; fi".format(pid=pid),
                  module_ignore_errors=True)


def cleanup_thp_pinning_objects(duthost, pinning_ports):
    """Remove accumulated and churn objects created by the pinning workload."""
    profiles = PINNING_PORT_PROFILES[:len(pinning_ports)]
    for port, profile in zip(pinning_ports, profiles):
        cmd = """
for i in $(seq 1 1000); do
    sudo config route del prefix "{route_base}.$i.0/24" nexthop "{nh}" 2>/dev/null
    sudo ip neigh del "{nh_base}.$((i + 10))" dev "{port}" 2>/dev/null
done
for i in $(seq 1 10); do
    sudo config route del prefix "{churn_base}.$i.0/24" nexthop "{churn_nh}" 2>/dev/null
    sudo ip neigh del "{churn_nh_base}.$((i + 10))" dev "{port}" 2>/dev/null
done
""".format(route_base=profile["route_base"],
           nh=profile["nh"],
           nh_base=profile["nh"].rsplit(".", 1)[0],
           churn_base=profile["churn_base"],
           churn_nh=profile["churn_nh"],
           churn_nh_base=profile["churn_nh"].rsplit(".", 1)[0],
           port=port)
        duthost.shell(cmd, module_ignore_errors=True)


def monitor_dut_health(duthost,
                       workload_pid,
                       pinning_ports,
                       duration_sec=DEFAULT_PINNING_DURATION_SEC,
                       interval_sec=DEFAULT_MONITOR_INTERVAL_SEC,
                       ahp_threshold_kb=DEFAULT_AHP_THRESHOLD_KB,
                       ahp_threshold_window_sec=DEFAULT_AHP_THRESHOLD_WINDOW_SEC):
    """Monitor DUT health and fail on steep orchagent AnonHugePages growth."""
    duthost.shell("sudo rm -f {}; sudo touch {}".format(DEFAULT_MEM_MONITOR_LOG, DEFAULT_MEM_MONITOR_LOG),
                  module_ignore_errors=True)
    reboot_history_before = _get_reboot_history(duthost)
    start = time.time()
    last_sample = None

    while time.time() - start <= duration_sec + interval_sec:
        elapsed = int(time.time() - start)
        last_sample = collect_memory_sample(duthost, elapsed, pinning_ports)

        if elapsed <= ahp_threshold_window_sec and last_sample["anon_huge_pages_kb"] > ahp_threshold_kb:
            pytest_assert(
                False,
                "orchagent AnonHugePages exceeded {} kB within {} seconds: sample={}".format(
                    ahp_threshold_kb, ahp_threshold_window_sec, last_sample)
            )

        if elapsed > 0 and elapsed % 120 == 0:
            pytest_assert(duthost.critical_services_fully_started(), "Critical services are not fully started")

        if not _process_is_running(duthost, workload_pid):
            pytest_assert(
                elapsed >= duration_sec,
                "THP pinning workload exited before expected duration; see {}".format(DEFAULT_PINNING_LOG)
            )
            break

        time.sleep(interval_sec)

    reboot_history_after = _get_reboot_history(duthost)
    pytest_assert(
        reboot_history_after == reboot_history_before,
        "Reboot history changed during THP pinning FDB storm test"
    )
    return last_sample


def collect_memory_sample(duthost, elapsed_sec, pinning_ports):
    port_regex = "|".join(pinning_ports)
    cmd = r'''
PID=$(pgrep -x orchagent | head -n 1)
if [ -z "$PID" ]; then
    echo "orchagent is not running"
    exit 2
fi
MEM_AVAILABLE=$(awk '/MemAvailable/ {{print $2}}' /proc/meminfo)
MEM_FREE=$(awk '/MemFree/ {{print $2}}' /proc/meminfo)
RSS=$(awk '/VmRSS/ {{print $2}}' /proc/$PID/status)
AHP=$(sudo grep AnonHugePages /proc/$PID/smaps_rollup | awk '{{print $2}}')
ROUTE_COUNT=$(ip route show | grep -Ec '^(10\.88|10\.92|172\.88|172\.92)\.')
NEIGH_COUNT=$(ip neigh show | grep -Ec 'dev ({port_regex})( |$)')
LINE="timestamp=$(date +%s) elapsed_sec={elapsed_sec} orchagent_pid=$PID"
LINE="$LINE mem_available_kb=$MEM_AVAILABLE mem_free_kb=$MEM_FREE"
LINE="$LINE orchagent_rss_kb=$RSS anon_huge_pages_kb=$AHP"
LINE="$LINE route_count=$ROUTE_COUNT neigh_count=$NEIGH_COUNT"
echo "$LINE" | sudo tee -a {monitor_log}
'''.format(elapsed_sec=elapsed_sec, port_regex=port_regex, monitor_log=DEFAULT_MEM_MONITOR_LOG)
    result = duthost.shell(cmd)
    sample = _parse_key_value_sample(result["stdout"].strip().splitlines()[-1])
    return sample


def _parse_key_value_sample(line):
    sample = {}
    for item in line.split():
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        try:
            sample[key] = int(value)
        except ValueError:
            sample[key] = value
    return sample


def _process_is_running(duthost, pid):
    result = duthost.shell(
        "if kill -0 {} 2>/dev/null; then echo running; else echo stopped; fi".format(pid),
        module_ignore_errors=True
    )
    return "running" in result["stdout"]


def _get_reboot_history(duthost):
    return duthost.shell("show reboot history | head -n 5", module_ignore_errors=True)["stdout"]

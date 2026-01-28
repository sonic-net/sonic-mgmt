import logging
import os
import json
import pytest
import time

from natsort import natsorted


from .qos_helpers import (
    ansible_stdout_to_str,
    get_all_vlans,
    get_phy_intfs,
    get_addrs_in_subnet,
    get_active_vlan_members,
    get_vlan_subnet,
    natural_keys,
    get_max_priority,
)
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                     # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                        # noqa: F401
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode                   # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.pfc_storm import PFCStorm


pytestmark = [pytest.mark.topology("any")]

pytest_plugins = [
    'tests.common.fixtures.conn_graph_facts',
    'tests.qos.qos_fixtures',
]


@pytest.fixture(scope="module")
def ip_version():
    return "IPv4"


@pytest.fixture(scope="module", autouse=True)
def ensure_ptf_test_port_map(
    ptfhost,
    tbinfo,
    duthosts,
    mux_server_url,
    duts_running_config_facts,
    duts_minigraph_facts,
):
    """
    Ensure /root/ptf_test_port_map.json exists before any tests in this module.
    Delegates to the shared ptf_test_port_map helper so that routed-path selection
    for non-T0 PFC pause tests has a deterministic port map JSON available.
    """

    from tests.common.fixtures.ptfhost_utils import ptf_test_port_map as _ptf_test_port_map

    _ptf_test_port_map(
        ptfhost,
        tbinfo,
        duthosts,
        mux_server_url,
        duts_running_config_facts,
        duts_minigraph_facts,
    )


logger = logging.getLogger(__name__)

PTF_PORT_MAPPING_MODE = 'use_orig_interface'

PFC_PKT_COUNT = 1000000000

PTF_FILE_REMOTE_PATH = '~/ptftests/py3/pfc_pause_test.py'
PTF_PKT_COUNT = 20
PTF_PKT_INTVL_SEC = 0.1
# Helpers to support non-T0 (e.g., routed/L3) path inside this unified module.
# Prefer the test port map JSON created by ensure_ptf_test_port_map, but also
# fall back to the legacy ptf_port_map.json if present.
PTF_TEST_PORT_MAP_PATHS = ["/root/ptf_test_port_map.json", "/root/ptf_port_map.json"]


def _is_t0(duthost, tbinfo):
    try:
        mg = duthost.get_extended_minigraph_facts(tbinfo)
        return bool(mg.get("minigraph_vlans"))
    except Exception:
        return False


def _ptf_cmd(ptfhost):
    path_exists = ptfhost.stat(path="/root/env-python3/bin/ptf")
    return "/root/env-python3/bin/ptf" if path_exists.get("stat", {}).get("exists") else "ptf"


def _get_port_namespace(duthost, ifname):
    """Return Linux namespace for a port, or '' if single-ASIC or unresolved."""
    try:
        return duthost.get_port_asic_instance(ifname).namespace if duthost.is_multi_asic else ""
    except Exception:
        return ""


def _kernel_out_intf_for_ip(duthost, ip_dst, dut_intf_src):
    """Return Linux kernel chosen outgoing interface for ip_dst.

    Handles single-ASIC and multi-ASIC by deriving the namespace from dut_intf_src.
    Returns the interface name or None if it cannot be determined.
    """
    ns = _get_port_namespace(duthost, dut_intf_src)
    cmd = f"ip -4 route get {ip_dst}"
    if hasattr(duthost, 'get_linux_ip_cmd_for_namespace'):
        cmd = duthost.get_linux_ip_cmd_for_namespace(cmd, ns)
    res = duthost.shell(f"sudo {cmd}", module_ignore_errors=True)
    out = (((res.get("stdout", "") or '') + '\n' + (res.get('stderr', '') or ''))).strip()
    out_intf = None
    for line in out.splitlines():
        toks = line.strip().split()
        if 'dev' in toks:
            try:
                out_intf = toks[toks.index('dev') + 1]
                break
            except Exception:
                pass
    return out_intf


def _run_ptf_routed(ptfhost, tbinfo, ip_src, ip_dst, port_src, port_dst, dscp, dscp_bg, router_mac, queue_paused):
    def _q(v):
        return f"'{v}'"
    params = [
        f"ip_src={_q(ip_src)}",
        f"ip_dst={_q(ip_dst)}",
        f"dscp={dscp}",
        f"dscp_bg={dscp_bg}",
        f"port_src={port_src}",
        f"port_dst={port_dst}",
        f"pkt_count={PTF_PKT_COUNT}",
        f"pkt_intvl={PTF_PKT_INTVL_SEC}",
        f"queue_paused={int(queue_paused)}",
        f"testbed_type={_q(tbinfo['topo']['name'])}",
        "dst_mac_is_router=1",
        f"router_mac={_q(router_mac)}",
        "dut_has_mac=1",
        "debug=0",
    ]
    params_str = ";".join(params)
    test_dir = os.path.dirname(PTF_FILE_REMOTE_PATH)
    cmd = (
        f"{_ptf_cmd(ptfhost)} --test-dir {test_dir} "
        "pfc_pause_test.PfcPauseTest --platform-dir ptftests --platform remote "
        f'--test-params="{params_str}" --relax --debug info'
    )
    logger.info("PTF cmd: %s", cmd)

    res = ptfhost.shell(cmd, chdir="/root")
    pytest_assert(res.get("rc", 1) == 0, f"PTF failed: {res}")
    passes = total = None
    for line in (res.get("stdout", "") or "").splitlines():
        if line.strip().startswith("Passes:"):
            try:
                parts = line.split()
                passes = int(parts[1])
                total = int(parts[3])
            except Exception:
                continue
    pytest_assert(passes is not None and total is not None, f"Bad PTF output: {res}")
    return float(passes) / float(total)


def _prepare_ptf_routed(ptfhost, duthost, ip_src, ip_dst, port_src, port_dst):
    ptfhost.shell(f"ip -4 addr flush dev eth{port_src} || true")
    ptfhost.shell(f"ip -4 addr flush dev eth{port_dst} || true")
    ptfhost.shell(f"ip -4 addr add {ip_src}/32 dev eth{port_src} || true")
    ptfhost.shell(f"ip -4 addr add {ip_dst}/32 dev eth{port_dst} || true")
    try:
        duthost.shell(f"docker exec -i swss arping {ip_src} -c 3")
        duthost.shell(f"docker exec -i swss arping {ip_dst} -c 3")
    except Exception:
        pass


def _pin_neighbors_routed(duthost, ptfhost, ip_src, ip_dst, ptf_port_src, ptf_port_dst, dut_intf_src, dut_intf_dst):
    try:
        mac_src = (ptfhost.command(f"cat /sys/class/net/eth{ptf_port_src}/address").get("stdout", "") or "").strip()
        mac_dst = (ptfhost.command(f"cat /sys/class/net/eth{ptf_port_dst}/address").get("stdout", "") or "").strip()
        ns_src = _get_port_namespace(duthost, dut_intf_src)
        ns_dst = _get_port_namespace(duthost, dut_intf_dst)
        if mac_src:
            cmd_src = (
                duthost.get_linux_ip_cmd_for_namespace(
                    f"ip neigh replace {ip_src} lladdr {mac_src} nud permanent dev {dut_intf_src}", ns_src
                ) if hasattr(duthost, 'get_linux_ip_cmd_for_namespace') else
                f"ip neigh replace {ip_src} lladdr {mac_src} nud permanent dev {dut_intf_src}"
            )
            duthost.shell(f"sudo {cmd_src}")
        if mac_dst:
            cmd_dst = (
                duthost.get_linux_ip_cmd_for_namespace(
                    f"ip neigh replace {ip_dst} lladdr {mac_dst} nud permanent dev {dut_intf_dst}", ns_dst
                ) if hasattr(duthost, 'get_linux_ip_cmd_for_namespace') else
                f"ip neigh replace {ip_dst} lladdr {mac_dst} nud permanent dev {dut_intf_dst}"
            )
            duthost.shell(f"sudo {cmd_dst}")
    except Exception:
        pass


def _unpin_neighbors_routed(duthost, ip_src, ip_dst, dut_intf_src, dut_intf_dst):
    ns_src = _get_port_namespace(duthost, dut_intf_src)
    ns_dst = _get_port_namespace(duthost, dut_intf_dst)
    try:
        cmd_src = (
            duthost.get_linux_ip_cmd_for_namespace(
                f"ip neigh del {ip_src} dev {dut_intf_src}", ns_src
            ) if hasattr(duthost, 'get_linux_ip_cmd_for_namespace') else
            f"ip neigh del {ip_src} dev {dut_intf_src}"
        )
        duthost.shell(f"sudo {cmd_src}", module_ignore_errors=True)
    except Exception:
        pass
    try:
        cmd_dst = (
            duthost.get_linux_ip_cmd_for_namespace(
                f"ip neigh del {ip_dst} dev {dut_intf_dst}", ns_dst
            ) if hasattr(duthost, 'get_linux_ip_cmd_for_namespace') else
            f"ip neigh del {ip_dst} dev {dut_intf_dst}"
        )
        duthost.shell(f"sudo {cmd_dst}", module_ignore_errors=True)
    except Exception:
        pass


def _get_preferred_dut_ports_from_map(ptfhost):
    """Return DUT ports preferred by PTF port map JSON, if present.

    This provides a deterministic ordering hint for routed-path selection but is
    best-effort only; failures to read or parse the JSON are ignored.
    """
    preferred_dut_ports = []
    for path in PTF_TEST_PORT_MAP_PATHS:
        try:
            stat = ptfhost.stat(path=path)
            if not stat.get("stat", {}).get("exists"):
                continue
            content = ptfhost.command(f"cat {path}")
            data = json.loads(content.get("stdout", "") or "{}")
            if isinstance(data, dict):
                values = data.values()
            elif isinstance(data, list):
                values = data
            else:
                continue
            for v in values:
                if isinstance(v, dict) and v.get("dut_port"):
                    preferred_dut_ports.append(v["dut_port"])
        except Exception:
            # Best-effort hint only; ignore IO/JSON errors.
            continue
    return preferred_dut_ports


def _pick_best_routed_candidate(duthost, tbinfo, test_ports, candidates):
    """Select the best routed path among candidates based on kernel out-intf.

    Returns a tuple (dut_intf_src, info, ip_src, ip_dst, ptf_port_src,
    ptf_port_dst, router_mac) or None if no suitable path is found.
    """
    try:
        mg = duthost.get_extended_minigraph_facts(tbinfo)
        pc_info = mg.get("minigraph_portchannels", {}) or {}
    except Exception:
        pc_info = {}
    port_to_pc = {}
    for pc_name, meta in pc_info.items():
        for mem in meta.get("members", []) or []:
            port_to_pc[mem] = pc_name

    best = None
    for dut_intf_src in candidates:
        info = test_ports[dut_intf_src]
        ip_src = info.get("test_neighbor_addr")
        ip_dst = info.get("rx_neighbor_addr")
        rx_intf = info.get("rx_port", [])
        if not ip_src or not ip_dst or not rx_intf:
            continue
        rx_intf_list = rx_intf if isinstance(rx_intf, list) else [rx_intf]

        # Find kernel route out-intf for ip_dst (namespace-aware).
        out_intf = _kernel_out_intf_for_ip(duthost, ip_dst, dut_intf_src)
        if not out_intf:
            continue

        exact_idx = None
        pc_idx = None
        for i, dst_intf in enumerate(rx_intf_list):
            if out_intf == dst_intf:
                exact_idx = i
                break
            pc = port_to_pc.get(dst_intf)
            if pc and out_intf == pc and pc_idx is None:
                pc_idx = i
        if exact_idx is None and pc_idx is None:
            continue

        rx_ids = info.get("rx_port_id", [])
        rx_ids = rx_ids if isinstance(rx_ids, list) else [rx_ids]
        idx = exact_idx if exact_idx is not None else pc_idx
        if idx is None or idx >= len(rx_ids):
            continue
        ptf_port_dst = rx_ids[idx]
        ptf_port_src = info.get("test_port_id")
        if ptf_port_src is None:
            continue

        try:
            asic_inst = duthost.get_port_asic_instance(dut_intf_src)
            router_mac = (
                asic_inst.get_router_mac()
                if asic_inst
                else duthost.asic_instance().get_router_mac()
            )
        except Exception:
            router_mac = duthost.asic_instance().get_router_mac()

        if exact_idx is not None:
            return (dut_intf_src, info, ip_src, ip_dst, ptf_port_src, ptf_port_dst, router_mac)
        if best is None:
            best = (dut_intf_src, info, ip_src, ip_dst, ptf_port_src, ptf_port_dst, router_mac)

    return best


def _select_routed_path(duthost, ptfhost, tbinfo, test_ports, selected_ports):
    """Select a deterministic routed path for non-T0 tests.

    Starts from setup_pfc_test-selected ports and then prefers ports present in
    the PTF test port map JSON.
    """
    # Prefer ports present in PTF mapping (deterministic), but always start
    # from the ports chosen by setup_pfc_test.
    candidates = list(selected_ports.keys())
    preferred_dut_ports = _get_preferred_dut_ports_from_map(ptfhost)
    for dutp in preferred_dut_ports:
        if dutp in test_ports and dutp not in candidates:
            candidates.append(dutp)

    return _pick_best_routed_candidate(duthost, tbinfo, test_ports, candidates)


PTF_PASS_RATIO_THRESH = 0.6

# Maximum number of interfaces to test on a DUT.
MAX_TEST_INTFS_COUNT = 2


@pytest.fixture(scope="module", autouse=True)
def pfc_test_setup(duthosts, rand_one_dut_hostname, tbinfo, ptfhost):
    """
    Generate configurations for the tests

    Args:
        duthosts(AnsibleHost) : multi dut instance
        rand_one_dut_hostname(string) : one of the dut instances from the multi dut

    Yields:
        setup(dict): DUT interfaces, PTF interfaces, PTF IP addresses, and PTF MAC addresses
    """

    # Get all the active physical interfaces enslaved to the VLAN.
    # These interfaces are actually server-facing interfaces at T0.
    duthost = duthosts[rand_one_dut_hostname]
    all_vlans = get_all_vlans(duthost)
    vlan_list = []
    for _, vlan in all_vlans.items():
        vlan_members, vlan_id = get_active_vlan_members(duthost, vlan)

        # Get VLAN subnet.
        vlan_subnet = get_vlan_subnet(duthost, vlan)

        # Generate IP addresses for servers in the VLAN.
        vlan_ip_addrs = list()
        if 'dualtor' in tbinfo['topo']['name']:
            servers = mux_cable_server_ip(duthost)
            for intf, value in natsorted(list(servers.items())):
                vlan_ip_addrs.append(value['server_ipv4'].split('/')[0])
        else:
            vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, len(vlan_members))

        # Find corresponding interfaces on PTF.
        phy_intfs = get_phy_intfs(duthost)
        phy_intfs.sort(key=natural_keys)
        vlan_members.sort(key=natural_keys)
        vlan_members_index = [phy_intfs.index(intf) for intf in vlan_members]
        ptf_intfs = ['eth' + str(i) for i in vlan_members_index]

        duthost.command('sonic-clear fdb all')

        # Disable DUT's PFC watchdog.
        duthost.shell('sudo pfcwd stop')

        testbed_type = tbinfo['topo']['name']

        vlan_list.append({
            'vlan_members': vlan_members,
            'vlan_id': vlan_id,
            'ptf_intfs': ptf_intfs,
            'vlan_ip_addrs': vlan_ip_addrs,
            'testbed_type': testbed_type
        })

    yield vlan_list

    duthost.command('sonic-clear fdb all')

    # Enable DUT's PFC watchdog.
    duthost.shell('sudo pfcwd start_default')


def run_test(pfc_test_setup, fanouthosts, duthost, ptfhost, conn_graph_facts,       # noqa: F811
             fanout_info, traffic_params, pause_prio=None, queue_paused=True,
             send_pause=True, pfc_pause=True, max_test_intfs_count=128):
    """
    Run the test

    Args:
        pfc_test_setup(fixture) : setup fixture
        fanouthosts(AnsibleHost) : fanout instance
        duthost(AnsibleHost) : dut instance
        ptfhost(AnsibleHost) : ptf instance
        conn_graph_facts(fixture) : Testbed topology
        fanout_info(fixture) : fanout graph info
        traffic_params(dict) : dict containing the dscp of test dscp and background dscp
        pause_prio(string) : priority of PFC frame
        queue_paused(bool) : if the queue is expected to be paused
        send_pause(bool) : send pause frames or not
        pfc_pause(bool) : send PFC pause frames or not
        max_test_intfs_count(int) : maximum count of interfaces to test.
                                    By default, it is a very large value to cover all the interfaces

    Return:
        Number of iterations and number of passed iterations for each tested interface.
    """

    setup = pfc_test_setup
    results = dict()

    for vlan in setup:
        testbed_type = vlan['testbed_type']
        dut_intfs = vlan['vlan_members']
        vlan_id = vlan['vlan_id']
        ptf_intfs = vlan['ptf_intfs']
        ptf_ip_addrs = vlan['vlan_ip_addrs']
        # Clear DUT's PFC counters.
        duthost.sonic_pfc_counters(method="clear")

        all_peer_dev = set()
        storm_handle = None
        for i in range(min(max_test_intfs_count, len(ptf_intfs))):
            src_index = i
            dst_index = (i + 1) % len(ptf_intfs)

            src_intf = ptf_intfs[src_index]
            dst_intf = ptf_intfs[dst_index]

            src_ip = ptf_ip_addrs[src_index]
            dst_ip = ptf_ip_addrs[dst_index]

            # DUT interface to pause.
            dut_intf_paused = dut_intfs[dst_index]

            if send_pause:
                peer_device = conn_graph_facts['device_conn'][duthost.hostname][dut_intf_paused]['peerdevice']
                peer_port = conn_graph_facts['device_conn'][duthost.hostname][dut_intf_paused]['peerport']
                peer_info = {'peerdevice': peer_device,
                             'pfc_fanout_interface': peer_port
                             }

                if not pfc_pause:
                    pause_prio = None

                if not storm_handle:
                    storm_handle = PFCStorm(
                        duthost,
                        fanout_info,
                        fanouthosts,
                        pfc_queue_idx=pause_prio,
                        pfc_frames_number=PFC_PKT_COUNT,
                        peer_info=peer_info,
                    )

                storm_handle.update_peer_info(peer_info)

                if not all_peer_dev or peer_device not in all_peer_dev:
                    storm_handle.deploy_pfc_gen()
                all_peer_dev.add(peer_device)
                storm_handle.start_storm()
                # Wait for PFC pause frame generation.
                time.sleep(1)

            # Run PTF test.
            logger.info("Running test: src intf: {} dest intf: {}".format(
                dut_intfs[src_index], dut_intfs[dst_index]))
            intf_info = '--interface %d@%s --interface %d@%s' % (
                src_index, src_intf, dst_index, dst_intf)

            test_params = ("ip_src=\'%s\';" % src_ip
                           + "ip_dst=\'%s\';" % dst_ip
                           + "dscp=%d;" % traffic_params['dscp']
                           + "dscp_bg=%d;" % traffic_params['dscp_bg']
                           + "pkt_count=%d;" % PTF_PKT_COUNT
                           + "pkt_intvl=%f;" % PTF_PKT_INTVL_SEC
                           + "port_src=%d;" % src_index
                           + "port_dst=%d;" % dst_index
                           + "queue_paused=%s;" % queue_paused
                           + "dut_has_mac=False;"
                           + "vlan_id=%s;" % vlan_id
                           + "testbed_type=\'%s\'" % testbed_type)

            # ptf_runner; from tests.ptf_runner import ptf_runner
            # need to check the output of ptf cmd, could not use the ptf_runner directly
            path_exists = ptfhost.stat(path="/root/env-python3/bin/ptf")
            if path_exists["stat"]["exists"]:
                cmd = '/root/env-python3/bin/ptf --test-dir %s pfc_pause_test %s --test-params="%s"' % (
                    os.path.dirname(PTF_FILE_REMOTE_PATH), intf_info, test_params)
            else:
                cmd = 'ptf --test-dir %s pfc_pause_test %s --test-params="%s"' % (
                    os.path.dirname(PTF_FILE_REMOTE_PATH), intf_info, test_params)
            print(cmd)

            res = ptfhost.shell(cmd)
            out = ansible_stdout_to_str(res.get('stdout', ''))
            passes = total = None
            for line in (out or '').splitlines():
                if line.strip().startswith('Passes:'):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            passes = int(parts[1])
                            total = int(parts[3])
                        except Exception:
                            pass
                    break
            if passes is None or total is None:
                err = ansible_stdout_to_str(res.get('stderr', ''))
                for line in (err or '').splitlines():
                    if line.strip().startswith('Passes:'):
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                passes = int(parts[1])
                                total = int(parts[3])
                            except Exception:
                                pass
                        break
            if passes is None or total is None:
                print('Unknown PTF test result format')
                results[dut_intf_paused] = [0, 0]
            else:
                results[dut_intf_paused] = [passes, total]
            time.sleep(1)

            if send_pause:
                # Stop PFC / FC storm.
                storm_handle.stop_storm()
                time.sleep(1)

    return results


def test_pfc_pause_lossless(pfc_test_setup, fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
                            conn_graph_facts, fanout_graph_facts,               # noqa: F811
                            lossless_prio_dscp_map, setup_pfc_test, tbinfo, enum_fanout_graph_facts):  # noqa: F811
    """Unified pause-only test: L2/VLAN on T0; routed/L3 on non-T0."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if _is_t0(duthost, tbinfo):
        # Original T0 path (unchanged semantics)
        test_errors = ""
        setup = pfc_test_setup
        lossless_prios = sorted(lossless_prio_dscp_map.keys())
        pytest_assert(lossless_prios, 'No lossless priorities available')
        prio = lossless_prios[0]
        dscp = lossless_prio_dscp_map[prio]
        other_lossless_prio = 4 if prio == 3 else 3
        other_lossless_dscps = lossless_prio_dscp_map[other_lossless_prio]
        max_priority = get_max_priority(setup[0]['testbed_type'])
        lossy_dscps = list(set(range(max_priority)) - set(other_lossless_dscps) - set(dscp))
        other_dscps = other_lossless_dscps + lossy_dscps[0:2]
        for dscp_bg in other_dscps:
            logger.info("Testing dscp: %s and background dscp: %s", dscp, dscp_bg)
            traffic_params = {'dscp': dscp[0], 'dscp_bg': dscp_bg}
            results = run_test(
                pfc_test_setup,
                fanouthosts,
                duthost,
                ptfhost,
                conn_graph_facts,
                fanout_graph_facts,
                traffic_params,
                queue_paused=True,
                send_pause=True,
                pfc_pause=True,
                pause_prio=prio,
                max_test_intfs_count=MAX_TEST_INTFS_COUNT,
            )
            if results is None:
                test_errors += f"Dscp: {dscp}, Background Dscp: {dscp_bg}, Result is empty\n"
            errors = {}
            for intf, pair in (results or {}).items():
                if len(pair) != 2:
                    continue
                pass_count, total_count = pair
                if total_count == 0:
                    continue
                # For pause test, success means suppressed traffic (low pass ratio).
                # Flag error only if suppression failed (ratio >= threshold).
                if pass_count >= total_count * PTF_PASS_RATIO_THRESH:
                    errors[intf] = pair
            if errors:
                test_errors += "Dscp: {}, Background Dscp: {}, errors occurred: {}\n".format(
                    dscp, dscp_bg, " ".join([f"{k}:{v}" for k, v in errors.items()])
                )
        pytest_assert(len(test_errors) == 0, test_errors)
    else:
        # Non-T0 routed/L3 path (IPv4-only)
        setup_info = setup_pfc_test
        if setup_info.get('ip_version') == 'IPv6':
            pytest.skip('PTF pfc_pause_test is IPv4-only; skipping IPv6 variant')
        test_ports = setup_info['test_ports']
        selected_ports = setup_info['selected_test_ports']
        neighbors = setup_info['neighbors']
        pytest_assert(test_ports and selected_ports, 'setup_pfc_test returned no test ports')
        pytest_assert(lossless_prio_dscp_map, 'lossless_prio_dscp_map is empty')
        lossless_prios = sorted(lossless_prio_dscp_map.keys())
        pause_prio = lossless_prios[0]
        dscps = lossless_prio_dscp_map[pause_prio]
        pytest_assert(dscps, f'No DSCPs for prio {pause_prio}')
        dscp = dscps[0]
        other_dscps = [d for p, ds in lossless_prio_dscp_map.items() if p != pause_prio for d in ds]
        if not other_dscps:
            other_dscps.append(dscps[1] if len(dscps) > 1 else dscp)
        dscp_bg = other_dscps[0]
        sel = _select_routed_path(duthost, ptfhost, tbinfo, test_ports, selected_ports)
        if not sel:
            pytest.skip('No deterministic routed path (PTF-captureable) found')
        dut_intf_src, info, ip_src, ip_dst, ptf_port_src, ptf_port_dst, router_mac = sel
        # Determine dst DUT interface for pinning
        rx_intf = info.get('rx_port', [])
        rx_intf_list = rx_intf if isinstance(rx_intf, list) else [rx_intf]
        rx_ids = info.get('rx_port_id', [])
        rx_ids = rx_ids if isinstance(rx_ids, list) else [rx_ids]
        try:
            idx = rx_ids.index(ptf_port_dst)
        except ValueError:
            idx = 0
        dut_intf_dst = (
            rx_intf_list[idx]
            if idx < len(rx_intf_list)
            else (rx_intf_list[0] if rx_intf_list else 'unknown')
        )
        logger.info(
            "PFC path: src_if=%s dst_if=%s ptf_src=%s ptf_dst=%s ip_src=%s ip_dst=%s router_mac=%s",
            dut_intf_src, dut_intf_dst, ptf_port_src, ptf_port_dst, ip_src, ip_dst, router_mac,
        )
        # Best-effort: log kernel-chosen out_intf for ip_dst
        _out_intf = _kernel_out_intf_for_ip(duthost, ip_dst, dut_intf_src)
        logger.info("Kernel out_intf for %s: %s", ip_dst, _out_intf or 'unknown')

        peer = neighbors.get(dut_intf_src)
        pytest_assert(peer, f'No neighbor info for {dut_intf_src}')
        peer_info = {'peerdevice': peer['peerdevice'], 'pfc_fanout_interface': peer['peerport']}
        # Baseline
        _prepare_ptf_routed(ptfhost, duthost, ip_src, ip_dst, ptf_port_src, ptf_port_dst)
        baseline_ratio = _run_ptf_routed(
            ptfhost,
            tbinfo,
            ip_src,
            ip_dst,
            ptf_port_src,
            ptf_port_dst,
            dscp,
            dscp_bg,
            router_mac,
            queue_paused=False,
        )
        logger.info('Baseline pass ratio (no PFC): %s', baseline_ratio)
        pytest_assert(
            baseline_ratio >= PTF_PASS_RATIO_THRESH,
            f'Baseline below threshold: {baseline_ratio} < {PTF_PASS_RATIO_THRESH}',
        )
        # Pause phase
        storm = PFCStorm(
            duthost,
            enum_fanout_graph_facts,
            fanouthosts,
            pfc_queue_index=pause_prio,
            pfc_frames_number=1000000,
            send_pfc_frame_interval=0,
            peer_info=peer_info,
        )
        storm.deploy_pfc_gen()
        try:
            _pin_neighbors_routed(
                duthost,
                ptfhost,
                ip_src,
                ip_dst,
                ptf_port_src,
                ptf_port_dst,
                dut_intf_src,
                dut_intf_dst,
            )
            storm.start_storm()
            time.sleep(1)
            pfc_ratio = _run_ptf_routed(
                ptfhost,
                tbinfo,
                ip_src,
                ip_dst,
                ptf_port_src,
                ptf_port_dst,
                dscp,
                dscp_bg,
                router_mac,
                queue_paused=True,
            )
        finally:
            storm.stop_storm()
            _unpin_neighbors_routed(duthost, ip_src, ip_dst, dut_intf_src, dut_intf_dst)
        logger.info('PFC pause phase pass ratio: %s', pfc_ratio)
        pytest_assert(
            pfc_ratio < PTF_PASS_RATIO_THRESH,
            f'PFC pause did not suppress: {pfc_ratio} >= {PTF_PASS_RATIO_THRESH}',
        )


def test_no_pfc(
    pfc_test_setup,
    fanouthosts,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    ptfhost,
    conn_graph_facts,  # noqa: F811
    fanout_graph_facts,  # noqa: F811
    lossless_prio_dscp_map,
    setup_pfc_test,  # noqa: F811
    tbinfo,
):
    """Unified baseline-only test: L2/VLAN on T0; routed/L3 on non-T0."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if _is_t0(duthost, tbinfo):
        # Original T0 path (no pause)
        test_errors = ""
        setup = pfc_test_setup
        lossless_prios = sorted(lossless_prio_dscp_map.keys())
        pytest_assert(lossless_prios, 'No lossless priorities available')
        prio = lossless_prios[0]
        if prio not in lossless_prio_dscp_map or len(lossless_prio_dscp_map[prio]) == 0:
            pytest.skip(f"lossless prio {prio} not enabled on testing port")
        dscp = lossless_prio_dscp_map[prio]
        other_lossless_prio = 4 if prio == 3 else 3
        other_lossless_dscps = lossless_prio_dscp_map[other_lossless_prio]
        max_priority = get_max_priority(setup[0]['testbed_type'])
        lossy_dscps = list(set(range(max_priority)) - set(other_lossless_dscps) - set(dscp))
        other_dscps = other_lossless_dscps + lossy_dscps[0:2]
        for dscp_bg in other_dscps:
            logger.info("Testing dscp: %s and background dscp: %s", dscp, dscp_bg)
            traffic_params = {'dscp': dscp[0], 'dscp_bg': dscp_bg}
            results = run_test(
                pfc_test_setup,
                fanouthosts,
                duthost,
                ptfhost,
                conn_graph_facts,
                fanout_graph_facts,
                traffic_params,
                queue_paused=False,
                send_pause=False,
                pfc_pause=None,
                pause_prio=None,
                max_test_intfs_count=MAX_TEST_INTFS_COUNT,
            )
            if results is None:
                test_errors += f"Dscp: {dscp}, Background Dscp: {dscp_bg}, Result is empty\n"
            errors = {}
            for intf, pair in (results or {}).items():
                if len(pair) != 2:
                    continue
                pass_count, total_count = pair
                if total_count == 0:
                    continue
                if pass_count < total_count * PTF_PASS_RATIO_THRESH:
                    errors[intf] = pair
            if errors:
                test_errors += "Dscp: {}, Background Dscp: {}, errors occurred: {}\n".format(
                    dscp, dscp_bg, " ".join([f"{k}:{v}" for k, v in errors.items()])
                )
        pytest_assert(len(test_errors) == 0, test_errors)
    else:
        # Non-T0 routed/L3 baseline-only path (IPv4-only)
        setup_info = setup_pfc_test
        if setup_info.get('ip_version') == 'IPv6':
            pytest.skip('PTF pfc_pause_test is IPv4-only; skipping IPv6 variant')
        test_ports = setup_info['test_ports']
        selected_ports = setup_info['selected_test_ports']
        pytest_assert(test_ports and selected_ports, 'setup_pfc_test returned no test ports')
        pytest_assert(lossless_prio_dscp_map, 'lossless_prio_dscp_map is empty')
        lossless_prios = sorted(lossless_prio_dscp_map.keys())
        pause_prio = lossless_prios[0]
        dscp_list = lossless_prio_dscp_map[pause_prio]
        pytest_assert(dscp_list, f'No DSCPs for prio {pause_prio}')
        dscp = dscp_list[0]
        other_dscps = [d for p, ds in lossless_prio_dscp_map.items() if p != pause_prio for d in ds]
        dscp_bg = other_dscps[0] if other_dscps else dscp
        sel = _select_routed_path(duthost, ptfhost, tbinfo, test_ports, selected_ports)
        if not sel:
            pytest.skip('No suitable routed path found for baseline test')
        dut_intf_src, info, ip_src, ip_dst, ptf_port_src, ptf_port_dst, router_mac = sel
        logger.info(
            "PFC baseline path: src_if=%s ptf_src=%s ptf_dst=%s ip_src=%s ip_dst=%s router_mac=%s",
            dut_intf_src, ptf_port_src, ptf_port_dst, ip_src, ip_dst, router_mac,
        )
        # Best-effort: log kernel-chosen out_intf for ip_dst
        _out_intf = _kernel_out_intf_for_ip(duthost, ip_dst, dut_intf_src)
        logger.info("Kernel out_intf for %s: %s", ip_dst, _out_intf or 'unknown')

        _prepare_ptf_routed(ptfhost, duthost, ip_src, ip_dst, ptf_port_src, ptf_port_dst)
        baseline_ratio = _run_ptf_routed(
            ptfhost,
            tbinfo,
            ip_src,
            ip_dst,
            ptf_port_src,
            ptf_port_dst,
            dscp,
            dscp_bg,
            router_mac,
            queue_paused=False,
        )
        logger.info('Baseline pass ratio (no PFC): %s', baseline_ratio)
        pytest_assert(
            baseline_ratio >= PTF_PASS_RATIO_THRESH,
            f'Baseline below threshold: {baseline_ratio} < {PTF_PASS_RATIO_THRESH}',
        )


def test_pfc_pause(pfc_test_setup, fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
                   conn_graph_facts, fanout_graph_facts,               # noqa: F811
                   lossless_prio_dscp_map, setup_pfc_test, tbinfo, enum_fanout_graph_facts):  # noqa: F811
    """Combined baseline + pause test in one:
    - On T0: uses VLAN/L2 path (original PTF semantics)
    - On non-T0: uses routed/L3 path (neighbor pinning + router DMAC)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if _is_t0(duthost, tbinfo):
        # Choose a single DSCP pair and validate both phases
        setup = pfc_test_setup
        lossless_prios = sorted(lossless_prio_dscp_map.keys())
        pytest_assert(lossless_prios, 'No lossless priorities available')
        prio = lossless_prios[0]
        if prio not in lossless_prio_dscp_map or len(lossless_prio_dscp_map[prio]) == 0:
            pytest.skip(f"lossless prio {prio} not enabled on testing port")
        dscp_list = lossless_prio_dscp_map[prio]
        other_prio = 4 if prio == 3 else 3
        other_list = lossless_prio_dscp_map[other_prio]
        max_priority = get_max_priority(setup[0]['testbed_type'])
        lossy_dscps = list(set(range(max_priority)) - set(other_list) - set(dscp_list))
        dscp = dscp_list[0]
        dscp_bg = (other_list + lossy_dscps[0:1])[0]
        traffic = {'dscp': dscp, 'dscp_bg': dscp_bg}
        # Baseline
        base = run_test(pfc_test_setup, fanouthosts, duthost, ptfhost, conn_graph_facts, fanout_graph_facts,
                        traffic, queue_paused=False, send_pause=False, pfc_pause=None, pause_prio=None,
                        max_test_intfs_count=MAX_TEST_INTFS_COUNT)
        # Pause
        pfc = run_test(pfc_test_setup, fanouthosts, duthost, ptfhost, conn_graph_facts, fanout_graph_facts,
                       traffic, queue_paused=True, send_pause=True, pfc_pause=True, pause_prio=prio,
                       max_test_intfs_count=MAX_TEST_INTFS_COUNT)
        # Evaluate ratios conservatively across tested interfaces

        def _best_ratio(res):
            ratios = []
            for v in (res or {}).values():
                if isinstance(v, list) and len(v) == 2 and v[1]:
                    ratios.append(float(v[0]) / float(v[1]))
            return min(ratios) if ratios else 0.0
        base_ratio = _best_ratio(base)
        pfc_ratio = _best_ratio(pfc)
        logger.info("T0 combined: baseline=%s, pfc=%s", base_ratio, pfc_ratio)
        pytest_assert(
            base_ratio >= PTF_PASS_RATIO_THRESH,
            f"Baseline below threshold: {base_ratio} < {PTF_PASS_RATIO_THRESH}",
        )
        pytest_assert(
            pfc_ratio < PTF_PASS_RATIO_THRESH,
            f"PFC pause did not suppress: {pfc_ratio} >= {PTF_PASS_RATIO_THRESH}",
        )
    else:
        # Routed/L3 combined
        setup_info = setup_pfc_test
        if setup_info.get('ip_version') == 'IPv6':
            pytest.skip('PTF pfc_pause_test is IPv4-only; skipping IPv6 variant')
        test_ports = setup_info['test_ports']
        selected_ports = setup_info['selected_test_ports']
        neighbors = setup_info['neighbors']
        pytest_assert(test_ports and selected_ports, 'setup_pfc_test returned no test ports')
        # Pick DSCP pair
        pytest_assert(lossless_prio_dscp_map, 'lossless_prio_dscp_map is empty')
        lossless_prios = sorted(lossless_prio_dscp_map.keys())
        pause_prio = lossless_prios[0]
        dscps = lossless_prio_dscp_map[pause_prio]
        pytest_assert(dscps, f'No DSCPs for {pause_prio}')
        dscp = dscps[0]
        other_dscps = [d for p, ds in lossless_prio_dscp_map.items() if p != pause_prio for d in ds]
        if not other_dscps:
            other_dscps.append(dscps[1] if len(dscps) > 1 else dscp)
        dscp_bg = other_dscps[0]
        sel = _select_routed_path(duthost, ptfhost, tbinfo, test_ports, selected_ports)
        if not sel:
            pytest.skip('No deterministic routed path (PTF-captureable) found')
        dut_intf_src, info, ip_src, ip_dst, ptf_port_src, ptf_port_dst, router_mac = sel
        rx_intf = info.get('rx_port', [])
        rx_intf_list = rx_intf if isinstance(rx_intf, list) else [rx_intf]
        rx_ids = info.get('rx_port_id', [])
        rx_ids = rx_ids if isinstance(rx_ids, list) else [rx_ids]
        try:
            idx = rx_ids.index(ptf_port_dst)
        except ValueError:
            idx = 0
        dut_intf_dst = (
            rx_intf_list[idx]
            if idx < len(rx_intf_list)
            else (rx_intf_list[0] if rx_intf_list else 'unknown')
        )
        logger.info(
            "PFC path: src_if=%s dst_if=%s ptf_src=%s ptf_dst=%s ip_src=%s ip_dst=%s router_mac=%s",
            dut_intf_src, dut_intf_dst, ptf_port_src, ptf_port_dst, ip_src, ip_dst, router_mac,
        )
        # Best-effort: log kernel-chosen out_intf for ip_dst
        _out_intf = _kernel_out_intf_for_ip(duthost, ip_dst, dut_intf_src)
        logger.info("Kernel out_intf for %s: %s", ip_dst, _out_intf or 'unknown')

        peer = neighbors.get(dut_intf_src)
        pytest_assert(peer, f'No neighbor info for {dut_intf_src}')
        peer_info = {'peerdevice': peer['peerdevice'], 'pfc_fanout_interface': peer['peerport']}
        # Baseline
        _prepare_ptf_routed(ptfhost, duthost, ip_src, ip_dst, ptf_port_src, ptf_port_dst)
        base_ratio = _run_ptf_routed(
            ptfhost,
            tbinfo,
            ip_src,
            ip_dst,
            ptf_port_src,
            ptf_port_dst,
            dscp,
            dscp_bg,
            router_mac,
            queue_paused=False,
        )
        logger.info('Baseline pass ratio (no PFC): %s', base_ratio)
        pytest_assert(
            base_ratio >= PTF_PASS_RATIO_THRESH,
            f'Baseline below threshold: {base_ratio} < {PTF_PASS_RATIO_THRESH}',
        )
        # Pause phase
        storm = PFCStorm(
            duthost,
            enum_fanout_graph_facts,
            fanouthosts,
            pfc_queue_index=pause_prio,
            pfc_frames_number=1000000,
            send_pfc_frame_interval=0,
            peer_info=peer_info,
        )
        storm.deploy_pfc_gen()
        try:
            _pin_neighbors_routed(
                duthost,
                ptfhost,
                ip_src,
                ip_dst,
                ptf_port_src,
                ptf_port_dst,
                dut_intf_src,
                dut_intf_dst,
            )
            storm.start_storm()
            time.sleep(1)
            pfc_ratio = _run_ptf_routed(
                ptfhost,
                tbinfo,
                ip_src,
                ip_dst,
                ptf_port_src,
                ptf_port_dst,
                dscp,
                dscp_bg,
                router_mac,
                queue_paused=True,
            )
        finally:
            storm.stop_storm()
            _unpin_neighbors_routed(duthost, ip_src, ip_dst, dut_intf_src, dut_intf_dst)
        logger.info('PFC pause phase pass ratio: %s', pfc_ratio)
        pytest_assert(
            pfc_ratio < PTF_PASS_RATIO_THRESH,
            f'PFC pause did not suppress: {pfc_ratio} >= {PTF_PASS_RATIO_THRESH}',
        )

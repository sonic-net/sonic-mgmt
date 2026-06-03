"""
Single-Node WRED Drop Test with Rate Sweep

Validates WRED (Weighted Random Early Detection) packet dropping on a single
DUT (D3) with 3 TGEN ports using IPv6 traffic.  Two ingress streams  --  each
swept through the same rates  --  oversubscribe a single egress port on a lossy
queue (WRED profile with ecn=ecn_none).  Traffic is sent WITHOUT ECN-capable
transport bits (ECN=00) so the DUT drops rather than marks.

The WRED profile and lossy queue are discovered dynamically from CONFIG_DB.

Pass criteria:
    - At no congestion (total < 100 %): wred_dropped == 0
    - As congestion increases: drop rate is monotonically non-decreasing

Topology:
    TGEN P1 --+
              +--> D3 (egress port P3) --> TGEN P3
    TGEN P2 --+

    T1D3:3  --  3 TGEN ports connected to DUT D3
"""

import pytest

from spytest import st, tgapi, SpyTestDict
import tests.cisco.tortuga.vxlan.vxlan_utils as vxlan_obj
import qos_test_utils as common_util
import traffic_stream_ixia_api as stream_api
import qos_test_utils as qos_utils

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ECN_NOT_ECT = 0b00  # Non-ECN-capable transport  --  WRED will drop, not mark
FRAME_SIZE = 1350   # TODO parametrize sizes [320, 640, 1350, 4086]
SWEEP_RATES = [49.95, 51, 52, 53, 54, 55, 60, 70, 80, 90, 99]    # Each stream's line rate % (total = 2x)
TRAFFIC_RUN_SECS = 10 
TRAFFIC_DRAIN_SECS = 2
DROP_PROBABILITY = 90             # Override green_drop_probability for test
VARIABLE_PKTS_PER_BURST = 100000  # Fixed packet count per stream

# Continuous-traffic test parameters
CONT_SWEEP_RATES = [49.95, 51, 52, 53, 54, 55, 60, 70, 80, 90, 99] # Each stream's line rate %
CONT_TRAFFIC_RUN_SECS = 20         # Longer run for steady-state measurement
CONT_DROP_MARGIN = 5.0             # Acceptable margin above max expected drop %


# IPv6 addressing  --  one /64 per DUT port
PORT_SUBNETS = {
    1: {'dut': '2001:db8:1::1', 'tgen': '2001:db8:1::2'},
    2: {'dut': '2001:db8:2::1', 'tgen': '2001:db8:2::2'},
    3: {'dut': '2001:db8:3::1', 'tgen': '2001:db8:3::2'},
}

# MAC addresses for TGEN NGPF device groups
TGEN_MACS = {
    1: '00:0a:01:00:01:01',
    2: '00:0a:01:00:02:01',
    3: '00:0a:01:00:03:01',
}

# Module-level state
data = SpyTestDict()


# ---------------------------------------------------------------------------
# Module-level fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def wred_module_setup():
    """
    Module fixture: configure DUT ports with IPv6, create TGEN NGPF
    device groups, init QoS, discover WRED queue configuration.
    """
    st.ensure_min_topology('T1D3:3')
    vars = st.get_testbed_vars()
    dut = vars.D3

    # Map DUT and TGEN port names
    dut_ports = {
        1: vars.D3T1P1,
        2: vars.D3T1P2,
        3: vars.D3T1P3,
    }
    tgen_ports = {
        1: 'T1D3P1',
        2: 'T1D3P2',
        3: 'T1D3P3',
    }

    # Verify all ports share the same speed
    speeds = {}
    for idx, port in dut_ports.items():
        speeds[idx] = common_util.get_if_speed(dut, port)
    if len(set(speeds.values())) != 1:
        st.report_fail('msg', f"Port speeds are not uniform: {speeds}")
    port_speed = list(speeds.values())[0]
    st.log(f"All 3 DUT ports are {port_speed}G")

    # QoS reload + IXIA PFC/FCoE L1 config
    stream_api.init_qos_on_dut(dut)
    qos_utils.load_config_db(dut)

    # Discover lossy WRED queue config on the egress port (P3)
    wred_cfg = qos_utils.discover_lossy_wred_queue_config(dut, dut_ports[3])
    if wred_cfg is None:
        st.log("No lossy WRED profile found on egress port -- "
               "queues use tail-drop (100% drop). Skipping test.")
        pytest.skip("No lossy WRED drop profile configured on egress port")

    # Store in module data
    data.dut = dut
    data.dut_ports = dut_ports
    data.tgen_ports = tgen_ports
    data.port_speed = port_speed
    data.wred_cfg = wred_cfg

    # ---- Override drop probability to DROP_PROBABILITY% ----
    profile_name = wred_cfg['wred_profile']
    config = qos_utils.get_config_db(dut)
    profile = config["WRED_PROFILE"][profile_name]
    data.saved_green_drop_prob = profile.get("green_drop_probability", None)
    st.log(f"Overriding green_drop_probability on {profile_name}: "
           f"{data.saved_green_drop_prob} -> {DROP_PROBABILITY}")
    config["WRED_PROFILE"][profile_name]["green_drop_probability"] = str(DROP_PROBABILITY)

    st.show(dut, "ecnconfig -l", skip_tmpl=True)

    # ---- Speed up queue watermark counterpoll (default 60s is too slow) ----
    qos_utils.set_queue_watermark_poll_interval(dut, 1000)

    # ---- Enable WRED queue counterpoll for ECN/WRED counter visibility ----
    st.log("Enabling wredqueue counterpoll")
    st.config(dut, "sudo counterpoll wredqueue enable", skip_error_check=True)

    # ---- Clean up any existing IP/VLAN config on the DUT ----
    st.banner("Cleaning up existing IP/VLAN configuration")
    qos_utils.cleanup_config(dut)

    # ---- Configure IPv6 on DUT ----
    st.banner("Configuring IPv6 addresses on DUT ports")
    ip_cfg = ''
    for idx, port in dut_ports.items():
        ip_cfg += f'sudo config interface ip add {port} {PORT_SUBNETS[idx]["dut"]}/64\n'
    st.config(dut, ip_cfg, skip_tmpl=True, skip_error_check=True)
    st.wait(3)

    # ---- Configure TGEN NGPF device groups (IPv6) ----
    st.banner("Configuring TGEN NGPF IPv6 device groups")
    int_dict = {}
    for idx in (1, 2, 3):
        int_dict[tgen_ports[idx]] = {
            'host_ip': PORT_SUBNETS[idx]['tgen'],
            'gateway': PORT_SUBNETS[idx]['dut'],
            'mac': TGEN_MACS[idx],
        }
    handles = vxlan_obj.config_tgen_interface(int_dict, addr_family='ipv6')
    data.tgen_handles = handles
    data.int_dict = int_dict

    # Get tg handle (same object for all ports)
    tg = handles[tgen_ports[1]]['tg_handle']
    data.tg = tg

    # Start all protocols so NDP resolves
    tg.tg_topology_test_control(action='start_all_protocols')
    st.wait(10)

    # Ping verify each TGEN endpoint -> DUT gateway
    for idx in (1, 2, 3):
        gw = PORT_SUBNETS[idx]['dut']
        int_h = handles[tgen_ports[idx]]['int_handle']
        ping_ok = vxlan_obj.ping_gateway(handles, tgen_ports[idx], gw, int_h)
        if not ping_ok:
            st.report_fail('msg', f"Ping failed: TGEN {tgen_ports[idx]} -> {gw}")

    # ---- Yield to test(s) ----
    yield

    # ---- Teardown ----
    st.banner("WRED module teardown")
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    # Restore queue watermark counterpoll to default
    qos_utils.restore_queue_watermark_poll_interval(dut)

    # Restore original green_drop_probability
    if data.saved_green_drop_prob is not None:
        profile_name = data.wred_cfg['wred_profile']
        config = qos_utils.get_config_db(dut)
        st.log(f"Restoring green_drop_probability on {profile_name}: "
               f"{DROP_PROBABILITY} -> {data.saved_green_drop_prob}")
        config["WRED_PROFILE"][profile_name]["green_drop_probability"] = data.saved_green_drop_prob
        st.show(dut, "ecnconfig -l", skip_tmpl=True)

    # Destroy TGEN device groups
    for port_key, h in handles.items():
        try:
            tg.tg_interface_config(port_handle=h['port_handle'],
                                   handle=h['int_handle'], mode='destroy')
        except Exception as e:
            st.log(f"TGEN cleanup {port_key}: {e}")

    # Remove IPv6 from DUT
    ip_rm = ''
    for idx, port in dut_ports.items():
        ip_rm += f'sudo config interface ip remove {port} {PORT_SUBNETS[idx]["dut"]}/64\n'
    st.config(dut, ip_rm, skip_tmpl=True, skip_error_check=True)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test_l3_wred_drop_rate_sweep():
    """
    Sweep two identical streams through increasing rates to oversubscribe a
    lossy egress queue.  Traffic uses ECN=00 (not ECN-capable) so the DUT's
    WRED profile drops rather than marks.  At each step collect WRED drop
    counters, queue counters, and watermarks.  Verify WRED drop rate is 0
    when total < 100 % and monotonically non-decreasing thereafter.
    """
    dut = data.dut
    tg = data.tg
    wred_cfg = data.wred_cfg
    tc = wred_cfg['tc']
    dscp = wred_cfg['dscp']
    queue = wred_cfg['queue']
    egress_intf = data.dut_ports[3]
    ingress_p1 = data.dut_ports[1]
    ingress_p2 = data.dut_ports[2]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    # Pseudo-node dict expected by qos_utils capture helpers
    nodes = {'dut': dut}
    intf_map = {'dut': [egress_intf]}

    ip_tos = qos_utils.compute_ip_tos(dscp, ECN_NOT_ECT)

    results = []
    try:
        for sweep_rate in SWEEP_RATES:
            total_rate = 2 * sweep_rate
            st.banner(f"=== Rate sweep: {sweep_rate}% + "
                      f"{sweep_rate}% = {total_rate}% (lossy TC {tc}) ===")

            # ---- Create stream 1 (T1D3P1 -> T1D3P3) ----
            st.banner(f"Creating stream 1 at {sweep_rate}% "
                      f"(DSCP={dscp}, ECN=00, frame={FRAME_SIZE})")
            tg_kwargs_s1 = dict(
                port_handle=handles[tgen_ports[1]]['port_handle'],
                port_handle2=handles[tgen_ports[3]]['port_handle'],
                mode='create',
                transmit_mode='single_burst',
                pkts_per_burst=VARIABLE_PKTS_PER_BURST,
                rate_percent=sweep_rate,
                frame_size=FRAME_SIZE,
                circuit_endpoint_type='ipv6',
                ipv6_traffic_class=ip_tos,
                emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
                emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
            )
            s1_result = tg.tg_traffic_config(**tg_kwargs_s1)
            if s1_result.get('status') != '1':
                st.report_fail('msg', f"Failed to create stream 1: {s1_result}")
            s1_stream_id = s1_result['stream_id']

            # ---- Create stream 2 (T1D3P2 -> T1D3P3) ----
            tg_kwargs_s2 = dict(
                port_handle=handles[tgen_ports[2]]['port_handle'],
                port_handle2=handles[tgen_ports[3]]['port_handle'],
                mode='create',
                transmit_mode='single_burst',
                pkts_per_burst=VARIABLE_PKTS_PER_BURST,
                rate_percent=sweep_rate,
                frame_size=FRAME_SIZE,
                circuit_endpoint_type='ipv6',
                ipv6_traffic_class=ip_tos,
                emulation_src_handle=handles[tgen_ports[2]]['int_handle'],
                emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
            )
            s2_result = tg.tg_traffic_config(**tg_kwargs_s2)
            if s2_result.get('status') != '1':
                st.error(f"Failed to create stream 2 at {sweep_rate}%")
                tg.tg_traffic_config(mode='remove', stream_id=s1_stream_id)
                continue
            s2_stream_id = s2_result['stream_id']

            try:
                # (a) Stop any lingering traffic
                tg.tg_traffic_control(action='stop')
                st.wait(TRAFFIC_DRAIN_SECS)

                # (b) Zero-baseline: clear all counters
                qos_utils.clear_all_counters(dut)
                qos_utils.clear_wred_counters(dut, [egress_intf], tc)
                st.wait(2, "Wait for counter clear to take effect")

                # (debug) Save and log config before traffic
                st.config(dut, "config save -y /tmp/ap.json", skip_error_check=True)
                saved_cfg = st.show(dut, "cat /tmp/ap.json", skip_tmpl=True, skip_error_check=True)
                st.log(f"Saved config (/tmp/ap.json):\n{saved_cfg}")
                vlan_cfg = st.show(dut, "show vlan config", skip_tmpl=True, skip_error_check=True)
                st.log(f"VLAN config:\n{vlan_cfg}")

                # Capture WRED counters BEFORE traffic (baseline)
                wred_before = qos_utils.capture_wred_counters(nodes, intf_map, tc)
                queue_name = f"UC{tc}"
                q_data_before = wred_before.get('dut', {}).get(egress_intf, {}).get(queue_name, {})
                wred_before_val = q_data_before.get('wred_drop_pkts', 0)
                transmitted_before = q_data_before.get('packets', 0)
                st.log(f"WRED counters BEFORE traffic: wred_drop_pkts={wred_before_val}, "
                       f"transmitted={transmitted_before}")

                # Capture interface counters BEFORE traffic
                intf_before = st.show(dut, "show interface counters",
                                      skip_tmpl=True, skip_error_check=True)
                st.log(f"Interface counters BEFORE traffic:\n{intf_before}")

                # (c) Start traffic
                tg.tg_traffic_control(action='run')
                st.wait(TRAFFIC_RUN_SECS)

                # (d) Stop traffic
                tg.tg_traffic_control(action='stop')
                st.wait(TRAFFIC_DRAIN_SECS)

                # ---- Collect data AFTER traffic ----
                # Interface counters AFTER traffic
                intf_after = st.show(dut, "show interface counters",
                                     skip_tmpl=True, skip_error_check=True)
                st.log(f"Interface counters AFTER traffic:\n{intf_after}")

                # WRED counters AFTER traffic
                wred_after = qos_utils.capture_wred_counters(nodes, intf_map, tc)
                q_data = wred_after.get('dut', {}).get(egress_intf, {}).get(queue_name, {})
                wred_after_val = q_data.get('wred_drop_pkts', 0)
                transmitted = q_data.get('packets', 0)
                st.log(f"WRED counters AFTER traffic: wred_drop_pkts={wred_after_val}, transmitted={transmitted}")

                # Calculate DELTA (AFTER - BEFORE) for both drops and transmitted
                wred_dropped = wred_after_val - wred_before_val
                transmitted_delta = transmitted - transmitted_before
                st.log(f"WRED DELTA: drops={wred_after_val}-{wred_before_val}={wred_dropped}, "
                       f"transmitted={transmitted}-{transmitted_before}={transmitted_delta}")

                # total_pkts = transmitted_delta + dropped (all packets that entered the queue this iteration)
                total_pkts = transmitted_delta + wred_dropped

                # Queue watermark (counterpoll interval set to 1s in fixture)
                st.wait(1, "Wait for queue watermark counterpoll to update")
                q_wm = qos_utils.capture_queue_watermark_values(
                    nodes, intf_map, tc)
                wm_val = q_wm.get('dut', {}).get(egress_intf, 0)

                # Buffer pool watermark
                bp_raw = qos_utils.get_buffer_pool_watermark(dut)
                bp_wm = qos_utils.parse_buffer_pool_watermark(bp_raw) if bp_raw else {}

                # Queue counters
                q_cnt_raw = st.show(dut, f"show queue counters {egress_intf}",
                                    skip_tmpl=True, skip_error_check=True)
                st.log(f"Queue counters for {egress_intf}:\n{q_cnt_raw}")

                # Drop counters
                drop_raw = st.show(dut, "show dropcounters count",
                                   skip_tmpl=True, skip_error_check=True)
                st.log(f"Drop counters:\n{drop_raw}")

                # Compute drop rate
                drop_rate = (wred_dropped / total_pkts * 100.0) if total_pkts > 0 else 0.0

                iteration = {
                    'sweep_rate': sweep_rate,
                    'total_rate': total_rate,
                    'wred_dropped': wred_dropped,
                    'total_pkts': total_pkts,
                    'drop_rate': drop_rate,
                    'q_wm': wm_val,
                    'bp_wm': bp_wm,
                }
                results.append(iteration)

                st.log(f"  >> rate={sweep_rate}% total={total_rate}% "
                       f"wred_dropped={wred_dropped} total_pkts={total_pkts} "
                       f"drop={drop_rate:.3f}% q_wm={wm_val}")

            finally:
                # Delete both streams after each iteration
                tg.tg_traffic_config(mode='remove', stream_id=s2_stream_id)
                tg.tg_traffic_config(mode='remove', stream_id=s1_stream_id)

    finally:
        # Ensure traffic is stopped
        tg.tg_traffic_control(action='stop')

    # ---- Log tabular summary ----
    platform_name = qos_utils.get_dut_platform(dut) or "unknown"
    st.banner(f"SUMMARY: WRED Drop Rate Sweep (Platform: {platform_name})")
    hdr = (f"{'Rate%':>6} {'Total%':>7} {'WRED_drop':>12} {'Total_pkts':>12} "
           f"{'Drop%':>8} {'Q_wm':>12}")
    st.log(hdr)
    st.log("-" * len(hdr))
    for r in results:
        st.log(f"{r['sweep_rate']:>6} {r['total_rate']:>7.1f} "
               f"{r['wred_dropped']:>12} {r['total_pkts']:>12} "
               f"{r['drop_rate']:>8.3f} {r['q_wm']:>12}")

    # ---- Assertions ----
    if not results:
        st.report_fail('msg', "No rate-sweep iterations completed")

    # 1) No congestion (total < 100%): expect 0 WRED drops
    for r in results:
        if r['total_rate'] < 100.0 and r['wred_dropped'] != 0:
            st.report_fail('msg',
                f"WRED dropped {r['wred_dropped']} pkts at "
                f"{r['total_rate']}% (expected 0  --  no congestion)")

    # 2) Congestion (total > 100%): expect WRED drops > 0
    for r in results:
        if r['total_rate'] > 100.0 and r['wred_dropped'] == 0:
            st.report_fail('msg',
                f"No WRED drops at {r['total_rate']}% "
                f"(expected drops  --  egress is oversubscribed)")

    # 3) Monotonicity: drop_rate[i] >= drop_rate[i-1] (with tolerance for
    #    WRED probabilistic noise at low congestion levels).
    MONO_TOL = 0.2  # allow up to 0.2 pct-point dip between adjacent steps
    for i in range(1, len(results)):
        prev = results[i - 1]
        curr = results[i]
        if curr['drop_rate'] < prev['drop_rate'] - MONO_TOL:
            st.report_fail('msg',
                f"WRED drop rate decreased: "
                f"{prev['sweep_rate']}%->{prev['drop_rate']:.3f}% > "
                f"{curr['sweep_rate']}%->{curr['drop_rate']:.3f}% "
                f"(tolerance {MONO_TOL}%)")

    st.report_pass('test_case_passed')


def test_l3_wred_drop_continuous_traffic():
    """
    Continuous-traffic variant of the WRED drop test.

    Two continuous streams (transmit_mode='continuous') each run at
    CONT_SWEEP_RATES % of line rate.  Total input = 2 * rate.

    WRED drop behavior:
    - min_expected = (total_rate - 100) / total_rate * 100 - margin (excess that must be dropped)
    - max_expected = min_expected + drop_probability + margin (WRED adds probabilistic drops)

    All rates are > 50 % so total always exceeds 100 % -> drops expected.
    """
    dut = data.dut
    tg = data.tg
    wred_cfg = data.wred_cfg
    tc = wred_cfg['tc']
    dscp = wred_cfg['dscp']
    queue = wred_cfg['queue']
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    nodes = {'dut': dut}
    intf_map = {'dut': [egress_intf]}

    ip_tos = qos_utils.compute_ip_tos(dscp, ECN_NOT_ECT)

    # Get drop probability from WRED config (default to DROP_PROBABILITY if not found)
    drop_prob = float(wred_cfg.get('green_drop_probability', DROP_PROBABILITY))
    st.log(f"WRED green_drop_probability = {drop_prob}%")

    results = []
    try:
        for sweep_rate in CONT_SWEEP_RATES:
            total_rate = 2 * sweep_rate
            # min_expected = excess that MUST be dropped (line rate > 100%)
            # e.g., 120% input -> (120-100)/120 * 100 = 16.67% min drop
            min_expected = max(((total_rate - 100.0) / total_rate * 100.0) - CONT_DROP_MARGIN, 0)
            # max_expected = min + WRED probabilistic drops + margin
            max_expected = min_expected + drop_prob + CONT_DROP_MARGIN
            st.banner(f"=== Continuous: {sweep_rate}% + {sweep_rate}% = "
                      f"{total_rate}% (drop range: {min_expected:.1f}% - {max_expected:.1f}%) ===")

            # ---- Create stream 1 (T1D3P1 -> T1D3P3) ----
            tg_kwargs_s1 = dict(
                port_handle=handles[tgen_ports[1]]['port_handle'],
                port_handle2=handles[tgen_ports[3]]['port_handle'],
                mode='create',
                transmit_mode='continuous',
                rate_percent=sweep_rate,
                frame_size=FRAME_SIZE,
                circuit_endpoint_type='ipv6',
                ipv6_traffic_class=ip_tos,
                emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
                emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
            )
            s1_result = tg.tg_traffic_config(**tg_kwargs_s1)
            if s1_result.get('status') != '1':
                st.report_fail('msg', f"Failed to create stream 1: {s1_result}")
            s1_stream_id = s1_result['stream_id']

            # ---- Create stream 2 (T1D3P2 -> T1D3P3) ----
            tg_kwargs_s2 = dict(
                port_handle=handles[tgen_ports[2]]['port_handle'],
                port_handle2=handles[tgen_ports[3]]['port_handle'],
                mode='create',
                transmit_mode='continuous',
                rate_percent=sweep_rate,
                frame_size=FRAME_SIZE,
                circuit_endpoint_type='ipv6',
                ipv6_traffic_class=ip_tos,
                emulation_src_handle=handles[tgen_ports[2]]['int_handle'],
                emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
            )
            s2_result = tg.tg_traffic_config(**tg_kwargs_s2)
            if s2_result.get('status') != '1':
                st.error(f"Failed to create stream 2 at {sweep_rate}%")
                tg.tg_traffic_config(mode='remove', stream_id=s1_stream_id)
                continue
            s2_stream_id = s2_result['stream_id']

            try:
                # (a) Stop any lingering traffic
                tg.tg_traffic_control(action='stop')
                st.wait(TRAFFIC_DRAIN_SECS)

                # (b) Clear counters
                qos_utils.clear_all_counters(dut)
                qos_utils.clear_wred_counters(dut, [egress_intf], tc)

                # Capture WRED counters BEFORE traffic (baseline for NPU counters
                # that are not cleared by sonic-clear)
                wred_before = qos_utils.capture_wred_counters(nodes, intf_map, tc)
                queue_name = f"UC{tc}"
                q_data_before = wred_before.get('dut', {}).get(egress_intf, {}).get(queue_name, {})
                wred_before_val = q_data_before.get('wred_drop_pkts', 0)
                transmitted_before = q_data_before.get('packets', 0)

                # (c) Run continuous traffic for CONT_TRAFFIC_RUN_SECS
                tg.tg_traffic_control(action='run')
                st.wait(CONT_TRAFFIC_RUN_SECS)

                # (d) Stop traffic
                tg.tg_traffic_control(action='stop')
                st.wait(TRAFFIC_DRAIN_SECS)

                # ---- Collect data ----
                wred_after = qos_utils.capture_wred_counters(nodes, intf_map, tc)
                q_data = wred_after.get('dut', {}).get(egress_intf, {}).get(queue_name, {})
                wred_after_val = q_data.get('wred_drop_pkts', 0)
                transmitted = q_data.get('packets', 0)

                # Calculate DELTA (AFTER - BEFORE) for both drops and transmitted
                wred_dropped = wred_after_val - wred_before_val
                transmitted_delta = transmitted - transmitted_before
                # total_pkts = transmitted_delta + dropped (all packets that entered the queue this iteration)
                total_pkts = transmitted_delta + wred_dropped

                st.wait(1, "Wait for queue watermark counterpoll to update")
                q_wm = qos_utils.capture_queue_watermark_values(
                    nodes, intf_map, tc)
                wm_val = q_wm.get('dut', {}).get(egress_intf, 0)

                q_cnt_raw = st.show(dut, f"show queue counters {egress_intf}",
                                    skip_tmpl=True, skip_error_check=True)
                st.log(f"Queue counters for {egress_intf}:\n{q_cnt_raw}")

                drop_rate = (wred_dropped / total_pkts * 100.0) if total_pkts > 0 else 0.0

                iteration = {
                    'sweep_rate': sweep_rate,
                    'total_rate': total_rate,
                    'min_expected': min_expected,
                    'max_expected': max_expected,
                    'wred_dropped': wred_dropped,
                    'total_pkts': total_pkts,
                    'drop_rate': drop_rate,
                    'q_wm': wm_val,
                }
                results.append(iteration)

                st.log(f"  >> rate={sweep_rate}% total={total_rate}% "
                       f"wred_dropped={wred_dropped} total_pkts={total_pkts} "
                       f"drop={drop_rate:.3f}% range=[{min_expected:.1f}%-{max_expected:.1f}%] "
                       f"q_wm={wm_val}")

            finally:
                tg.tg_traffic_config(mode='remove', stream_id=s2_stream_id)
                tg.tg_traffic_config(mode='remove', stream_id=s1_stream_id)

    finally:
        tg.tg_traffic_control(action='stop')

    # ---- Log tabular summary ----
    platform_name = qos_utils.get_dut_platform(dut) or "unknown"
    st.banner(f"SUMMARY: L3 1node WRED Continuous Traffic Drop (Platform: {platform_name})")
    st.log(f"WRED drop_probability = {drop_prob}%, margin = {CONT_DROP_MARGIN}%")
    hdr = (f"{'Rate%':>6} {'Total%':>7} {'Min%':>8} {'Max%':>8} {'WRED_drop':>12} "
           f"{'Total_pkts':>12} {'Drop%':>8} {'Status':>8} {'Q_wm':>12}")
    st.log(hdr)
    st.log("-" * len(hdr))
    for r in results:
        if r['drop_rate'] < r['min_expected']:
            status = 'LOW'
        elif r['drop_rate'] > r['max_expected']:
            status = 'HIGH'
        else:
            status = 'OK'
        st.log(f"{r['sweep_rate']:>6} {r['total_rate']:>7.1f} "
               f"{r['min_expected']:>8.1f} {r['max_expected']:>8.1f} {r['wred_dropped']:>12} "
               f"{r['total_pkts']:>12} {r['drop_rate']:>8.3f} "
               f"{status:>8} {r['q_wm']:>12}")

    # ---- Assertions ----
    if not results:
        st.report_fail('msg', "No continuous-traffic iterations completed")

    # 1) No congestion (total < 100%): expect 0 WRED drops
    for r in results:
        if r['total_rate'] < 100.0 and r['wred_dropped'] != 0:
            st.report_fail('msg',
                f"WRED dropped {r['wred_dropped']} pkts at "
                f"{r['total_rate']}% (expected 0  --  no congestion)")

    # 2) Congestion (total > 100%): expect WRED drops > 0
    for r in results:
        if r['total_rate'] > 100.0 and r['wred_dropped'] == 0:
            st.report_fail('msg',
                f"No WRED drops at {r['total_rate']}% "
                f"(expected drops  --  egress is oversubscribed)")

    # 3) Drop rate should be >= min_expected (at least excess must be dropped)
    for r in results:
        if r['total_rate'] > 100.0 and r['drop_rate'] < r['min_expected']:
            st.report_fail('msg',
                f"Drop rate {r['drop_rate']:.3f}% at {r['total_rate']}% "
                f"is below minimum expected {r['min_expected']:.1f}% "
                f"(excess traffic must be dropped)")

    # 4) Drop rate should be <= max_expected (min + drop_prob + margin)
    for r in results:
        if r['total_rate'] > 100.0 and r['drop_rate'] > r['max_expected']:
            st.report_fail('msg',
                f"Drop rate {r['drop_rate']:.3f}% at {r['total_rate']}% "
                f"exceeds maximum expected {r['max_expected']:.1f}% "
                f"(min={r['min_expected']:.1f}% + drop_prob={drop_prob}% + margin={CONT_DROP_MARGIN}%)")

    st.report_pass('test_case_passed')

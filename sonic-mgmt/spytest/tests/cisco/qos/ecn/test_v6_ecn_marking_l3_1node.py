"""
Single-Node ECN Marking Accuracy Test with Rate Sweep

Validates ECN (Explicit Congestion Notification) marking on a single DUT (D3)
with 3 TGEN ports using IPv6 traffic.  
Two ingress streams each of [49.95, 51, 53, 54, 55, 60, 75] line rate oversubscribe
a single egress port.
The WRED/ECN profile is discovered dynamically from CONFIG_DB.

Pass criteria:
    - At no congestion (total < 100 %): ecn_marked == 0
    - As congestion increases: marking rate is monotonically non-decreasing

Topology:
    TGEN P1 --+
              +--> D3 (egress port P3) --> TGEN P3
    TGEN P2 --+

    T1D3:3  --  3 TGEN ports connected to DUT D3
"""

import time
import pytest

from spytest import st, tgapi, SpyTestDict
import tests.cisco.tortuga.vxlan.vxlan_utils as vxlan_obj
import qos_test_utils as common_util
import traffic_stream_ixia_api as stream_api
import qos_test_utils as qos_utils

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ECN_ECT_1 = 0b01
FRAME_SIZE = 1350
SWEEP_RATES = [49.95, 51, 53, 54, 55, 60, 75, 80, 85, 90, 95, 100]  # % line rate for each stream (total = 2x this)
TRAFFIC_RUN_SECS = 10
TRAFFIC_DRAIN_SECS = 15
MARKING_PROBABILITY = 20  # Override green_drop_probability for test
FIRST_CE_TOLERANCE = 25   # Max spread (in packets) of first CE across congested iterations
#VARIABLE_PKTS_PER_BURST = 50000  # Fixed packet count for variable-rate stream
VARIABLE_PKTS_PER_BURST = 100000  # Fixed packet count for variable-rate stream


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
def ecn_module_setup():
    """
    Module fixture: configure DUT ports with IPv6, create TGEN NGPF
    device groups, init QoS, discover ECN queue configuration.
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

    # Discover ECN queue config on the egress port (P3)
    ecn_cfg = qos_utils.discover_ecn_queue_config(dut, dut_ports[3])

    # Store in module data
    data.dut = dut
    data.dut_ports = dut_ports
    data.tgen_ports = tgen_ports
    data.port_speed = port_speed
    data.ecn_cfg = ecn_cfg

    # ---- Override marking probability to MARKING_PROBABILITY% ----
    data.saved_green_drop_prob = None
    '''
    profile_name = ecn_cfg['wred_profile']
    config = qos_utils.get_config_db(dut)
    profile = config["WRED_PROFILE"][profile_name]
    data.saved_green_drop_prob = profile.get("green_drop_probability", None)
    st.log(f"Overriding green_drop_probability on {profile_name}: "
           f"{data.saved_green_drop_prob} -> {MARKING_PROBABILITY}")
    config["WRED_PROFILE"][profile_name]["green_drop_probability"] = str(MARKING_PROBABILITY)
    st.show(dut, "ecnconfig -l", skip_tmpl=True)
    '''

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

    # TGEN UDS ECN counters disabled  --  tg_custom_filter_config(mode='getstats')
    # calls packet_stats which triggers a fatal IXIA error (dirname required).
    # DUT WRED counters are the primary ECN counter source.
    # egress_ph = handles[tgen_ports[3]]['port_handle']
    # try:
    #     qos_utils.setup_ecn_uds_counters(tg, egress_ph)
    #     data.uds_configured = True
    # except Exception as e:
    #     st.log(f"UDS ECN counter setup failed (non-fatal): {e}")
    #     data.uds_configured = False
    data.uds_configured = False

    # ---- Yield to test(s) ----
    yield

    # ---- Teardown ----
    st.banner("ECN module teardown")
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    # Restore queue watermark counterpoll to default
    qos_utils.restore_queue_watermark_poll_interval(dut)

    # Restore original green_drop_probability
    if data.saved_green_drop_prob is not None:
        profile_name = data.ecn_cfg['wred_profile']
        config = qos_utils.get_config_db(dut)
        st.log(f"Restoring green_drop_probability on {profile_name}: "
               f"{MARKING_PROBABILITY} -> {data.saved_green_drop_prob}")
        config["WRED_PROFILE"][profile_name]["green_drop_probability"] = \
            data.saved_green_drop_prob
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

def test_l3_ecn_marking_rate_sweep():
    """
    Sweep the variable-rate stream from 1 % to 64 % while the fixed stream
    runs at 98.9 %.  At each step collect WRED/ECN counters, queue counters,
    watermarks, PFC counters, and drop counters.  Verify ECN marking rate is
    0 when total < 100 % and monotonically non-decreasing thereafter.
    """
    dut = data.dut
    tg = data.tg
    ecn_cfg = data.ecn_cfg
    tc = ecn_cfg['tc']
    dscp = ecn_cfg['dscp']
    queue = ecn_cfg['queue']
    egress_intf = data.dut_ports[3]
    ingress_p1 = data.dut_ports[1]
    ingress_p2 = data.dut_ports[2]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    # Pseudo-node dict expected by qos_utils capture helpers
    nodes = {'dut': dut}
    intf_map = {'dut': [egress_intf]}

    # Egress TGEN port handle for packet capture
    egress_port_handle = handles[tgen_ports[3]]['port_handle']

    ip_tos = qos_utils.compute_ip_tos(dscp, ECN_ECT_1)

    results = []
    try:
        for sweep_rate in SWEEP_RATES:
            total_rate = 2 * sweep_rate
            st.banner(f"=== Rate sweep: {sweep_rate}% + "
                      f"variable {sweep_rate}% = {total_rate}% ===")

            st.banner(f"Creating stream at {sweep_rate}% "
                    f"(DSCP={dscp}, ECT=01, frame={FRAME_SIZE})")
            tg_kwargs_fixed = dict(
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
            fixed_result = tg.tg_traffic_config(**tg_kwargs_fixed)
            if fixed_result.get('status') != '1':
                st.report_fail('msg', f"Failed to create fixed stream: {fixed_result}")
            fixed_stream_id = fixed_result['stream_id']
            stream_api.set_pfc_priority_group(tg, fixed_result, tc)

            # ---- Create variable stream (T1D3P2 -> T1D3P3) ----
            tg_kwargs_var = dict(
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
            var_result = tg.tg_traffic_config(**tg_kwargs_var)
            if var_result.get('status') != '1':
                st.error(f"Failed to create variable stream at {sweep_rate}%")
                continue
            var_stream_id = var_result['stream_id']
            stream_api.set_pfc_priority_group(tg, var_result, tc)

            try:
                # (a) Stop any lingering traffic
                tg.tg_traffic_control(action='stop')
                st.wait(TRAFFIC_DRAIN_SECS)

                # (b) Zero-baseline: clear all counters
                qos_utils.clear_all_counters(dut)
                qos_utils.clear_wred_counters(dut, [egress_intf], tc)
                st.wait(2)

                # (b1) Capture BASELINE counters BEFORE traffic
                # (counters are cumulative, so we need delta = after - before)
                wred_before = qos_utils.capture_wred_counters(nodes, intf_map, tc)
                queue_name = f"UC{tc}"
                q_before = wred_before.get('dut', {}).get(egress_intf, {}).get(queue_name, {})
                ecn_before = q_before.get('ecn_marked_pkts', 0)
                tx_before = q_before.get('packets', 0)
                drop_before = q_before.get('wred_drop_pkts', 0)

                # (debug) Save and log config before traffic
                st.config(dut, "config save -y /tmp/ap.json", skip_error_check=True)
                saved_cfg = st.show(dut, "cat /tmp/ap.json", skip_tmpl=True, skip_error_check=True)
                st.log(f"Saved config (/tmp/ap.json):\n{saved_cfg}")
                vlan_cfg = st.show(dut, "show vlan config", skip_tmpl=True, skip_error_check=True)
                st.log(f"VLAN config:\n{vlan_cfg}")

                # (b2) Start packet capture on egress TGEN port
                '''
                capture_started = qos_utils.start_packet_capture(
                    tg, egress_port_handle, port_name='egress_tgen', capture_mode='continuous')
                '''

                # (c) Start traffic
                tg.tg_traffic_control(action='run')
                st.wait(TRAFFIC_RUN_SECS)

                # (d) Stop traffic
                tg.tg_traffic_control(action='stop')
                st.wait(TRAFFIC_DRAIN_SECS)

                # (d2) Stop packet capture and retrieve raw packets
                pkt_dict = None

                # ---- Collect data ----
                # WRED/ECN counters AFTER traffic
                wred_after = qos_utils.capture_wred_counters(nodes, intf_map, tc)
                q_after = wred_after.get('dut', {}).get(egress_intf, {}).get(queue_name, {})
                ecn_after = q_after.get('ecn_marked_pkts', 0)
                tx_after = q_after.get('packets', 0)
                drop_after = q_after.get('wred_drop_pkts', 0)

                # Compute DELTA (counters are cumulative)
                ecn_marked = ecn_after - ecn_before
                transmitted = tx_after - tx_before
                wred_dropped = drop_after - drop_before
                # total_pkts = transmitted + dropped (all packets that entered the queue)
                total_pkts = transmitted + wred_dropped

                # Queue watermark (counterpoll interval set to 1s in fixture)
                st.wait(1, "Wait for queue watermark counterpoll to update")
                q_wm = qos_utils.capture_queue_watermark_values(
                    nodes, intf_map, tc)
                wm_val = q_wm.get('dut', {}).get(egress_intf, 0)

                # Buffer pool watermark
                bp_raw = qos_utils.get_buffer_pool_watermark(dut)
                bp_wm = qos_utils.parse_buffer_pool_watermark(bp_raw) if bp_raw else {}

                # PFC TX on both ingress ports
                pfc_p1 = qos_utils.get_pfc_tx_count(dut, ingress_p1, tc)
                pfc_p2 = qos_utils.get_pfc_tx_count(dut, ingress_p2, tc)

                st.show(dut, "show interface counters",
                                   skip_tmpl=True, skip_error_check=True)
                # Drop counters
                drop_raw = st.show(dut, "show dropcounters count",
                                   skip_tmpl=True, skip_error_check=True)

                # Queue counters
                q_cnt_raw = st.show(dut, f"show queue counters {egress_intf}",
                                    skip_tmpl=True, skip_error_check=True)
                st.log(f"Queue counters for {egress_intf}:\n{q_cnt_raw}")

                # TGEN UDS disabled  --  see comment in fixture
                uds = {}
                # if data.uds_configured:
                #     try:
                #         uds = qos_utils.get_ecn_uds_counters(
                #             tg, handles[tgen_ports[3]]['port_handle'])
                #     except Exception as e:
                #         st.log(f"UDS read failed (non-fatal): {e}")

                # Compute marking rate
                marking_rate = (ecn_marked / total_pkts * 100.0) if total_pkts > 0 else 0.0
                if ecn_marked == 0:
                    st.log("  >> No ECN-marked packets detected")
                elif marking_rate > 100.0:
                    st.log(f"  >> WARNING: Marking rate {marking_rate:.1f}% exceeds 100%! "
                           f"(ecn_marked={ecn_marked}, total_pkts={total_pkts})")
                    st.log(f"     Before: ecn={ecn_before}, tx={tx_before}, drop={drop_before}")
                    st.log(f"     After:  ecn={ecn_after}, tx={tx_after}, drop={drop_after}")

                # Find first CE packet in capture
                first_ce = None
                if pkt_dict is not None and ecn_marked > 0:
                    first_ce = qos_utils.find_first_ce_packet(pkt_dict, egress_port_handle)
                    if first_ce is not None:
                        st.log(f"  >> First CE packet at index {first_ce}")
                    else:
                        st.log("  >> No CE packets found in capture")

                iteration = {
                    'sweep_rate': sweep_rate,
                    'total_rate': total_rate,
                    'ecn_marked': ecn_marked,
                    'total_pkts': total_pkts,
                    'marking_rate': marking_rate,
                    'q_wm': wm_val,
                    'bp_wm': bp_wm,
                    'pfc_tx_p1': pfc_p1,
                    'pfc_tx_p2': pfc_p2,
                    'uds': uds,
                    'pkt_dict': pkt_dict,
                    'first_ce': first_ce,
                }
                results.append(iteration)

                st.log(f"  >> rate={sweep_rate}% total={total_rate}% "
                       f"ecn_marked={ecn_marked} total_pkts={total_pkts} "
                       f"marking={marking_rate:.3f}% q_wm={wm_val} "
                       f"pfc_p1={pfc_p1} pfc_p2={pfc_p2}")

            finally:
                # Delete both streams after each iteration
                tg.tg_traffic_config(mode='remove', stream_id=var_stream_id)
                tg.tg_traffic_config(mode='remove', stream_id=fixed_stream_id)

    finally:
        # Ensure traffic is stopped
        tg.tg_traffic_control(action='stop')

    # ---- Log tabular summary ----
    platform_name = qos_utils.get_dut_platform(dut) or "unknown"
    st.banner(f"SUMMARY: L3 1node ECN Marking Rate Sweep (Platform: {platform_name})")
    hdr = (f"{'Rate%':>6} {'Total%':>7} {'ECN_marked':>12} {'Total_pkts':>12} "
           f"{'Mark%':>8} {'Q_wm':>12} {'PFC_P1':>8} {'PFC_P2':>8} {'1st_CE':>8}")
    st.log(hdr)
    st.log("-" * len(hdr))
    for r in results:
        ce_str = str(r['first_ce']) if r['first_ce'] is not None else '-'
        st.log(f"{r['sweep_rate']:>6} {r['total_rate']:>7.1f} "
               f"{r['ecn_marked']:>12} {r['total_pkts']:>12} "
               f"{r['marking_rate']:>9.3f} {r['q_wm']:>12} "
               f"{r['pfc_tx_p1']:>8} {r['pfc_tx_p2']:>8} {ce_str:>8}")

    # ---- Assertions ----
    if not results:
        st.report_fail('msg', "No rate-sweep iterations completed")

    # 1) No congestion at lowest rate (total < 100%): expect 0 ECN marking
    first = results[0]
    if first['total_rate'] < 100.0 and first['ecn_marked'] != 0:
        st.report_fail('msg',
            f"ECN marked {first['ecn_marked']} pkts at {first['total_rate']}% "
            f"(expected 0  --  no congestion)")

    # 2) Monotonicity: marking_rate[i] >= marking_rate[i-1]
    for i in range(1, len(results)):
        prev = results[i - 1]
        curr = results[i]
        if curr['marking_rate'] < prev['marking_rate']:
            st.report_fail('msg',
                f"ECN marking rate decreased: "
                f"{prev['sweep_rate']}%->{prev['marking_rate']:.3f}% > "
                f"{curr['sweep_rate']}%->{curr['marking_rate']:.3f}%")

    # 3) Capture analysis: first CE packet proximity
    #    - Uncongested iterations (total < 100%): first_ce must be None
    #    - Congested iterations: all first_ce values within FIRST_CE_TOLERANCE
    congested_ce = []
    for r in results:
        if r['total_rate'] < 100.0:
            if r['first_ce'] is not None:
                st.report_fail('msg',
                    f"CE packet found at index {r['first_ce']} at "
                    f"{r['total_rate']}% (expected none  --  no congestion)")
        else:
            if r['first_ce'] is not None:
                congested_ce.append((r['sweep_rate'], r['first_ce']))

    if len(congested_ce) >= 2:
        ce_indices = [ce for _, ce in congested_ce]
        ce_min = min(ce_indices)
        ce_max = max(ce_indices)
        spread = ce_max - ce_min
        st.log(f"First-CE spread across congested iterations: "
               f"min={ce_min} max={ce_max} spread={spread} "
               f"(tolerance={FIRST_CE_TOLERANCE})")
        for rate, ce_idx in congested_ce:
            st.log(f"  rate={rate}% -> first_ce={ce_idx}")
        if spread > FIRST_CE_TOLERANCE:
            st.report_fail('msg',
                f"First CE packet spread {spread} exceeds tolerance "
                f"{FIRST_CE_TOLERANCE} (min={ce_min}, max={ce_max})")

    st.report_pass('test_case_passed')

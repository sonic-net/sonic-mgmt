import re
import time
import pytest
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st, tgapi
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg
from tests.cisco.hwqual.platform_snt_cfg import get_vrf_traffic_config
from apis.common.sonic_hooks import SonicHooks

def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)

def verify_tgen_traffic_stats(CfgDataG, k):

    if CfgDataG.is_single_tgen_port:
        ph1_traffic_stats = tgapi.get_traffic_stats(CfgDataG.tg, port_handle=CfgDataG.tg_ph1)
        if int(ph1_traffic_stats.rx.total_packets) < int(ph1_traffic_stats.tx.total_packets):
            pkt_loss = int(ph1_traffic_stats.tx.total_packets) - int(ph1_traffic_stats.rx.total_packets)
            report_fail(f" {CfgDataG.logprefix} Traffic drop for {CfgDataG.traffic_cfg_type}:{k} - {pkt_loss} packets")
        else:
            st.log(f" {CfgDataG.logprefix} No Traffic drop for {CfgDataG.traffic_cfg_type}:{k}")
    else:
        no_drop = True
        ph1_traffic_stats = tgapi.get_traffic_stats(CfgDataG.tg, port_handle=CfgDataG.tg_ph1)
        ph2_traffic_stats = tgapi.get_traffic_stats(CfgDataG.tg, port_handle=CfgDataG.tg_ph2)

        if int(ph2_traffic_stats.rx.total_packets) < int(ph1_traffic_stats.tx.total_packets):
            pkt_loss = int(ph1_traffic_stats.tx.total_packets) - int(ph2_traffic_stats.rx.total_packets)
            report_fail(f" {CfgDataG.logprefix} Traffic drop from {CfgDataG.D1T1P1} to {CfgDataG.D1T1P2} {CfgDataG.traffic_cfg_type}:{k} - {pkt_loss} packets")
            no_drop = False

        if int(ph1_traffic_stats.rx.total_packets) < int(ph2_traffic_stats.tx.total_packets):
            pkt_loss = int(ph2_traffic_stats.tx.total_packets) - int(ph1_traffic_stats.rx.total_packets)
            report_fail(f" {CfgDataG.logprefix} Traffic drop from {CfgDataG.D1T1P2} to {CfgDataG.D1T1P1} {CfgDataG.traffic_cfg_type}:{k} - {pkt_loss} packets")
            no_drop = False

        if no_drop:
            st.log(f" {CfgDataG.logprefix} No Traffic drop for {CfgDataG.traffic_cfg_type}:{k}")


def stop_tgen_traffic(CfgDataG, k):
    st.log(f" {CfgDataG.logprefix} Stopping Traffic {CfgDataG.traffic_cfg_type}:{k}")
    CfgDataG.tg.tg_traffic_control(action='stop', handle=CfgDataG.stream_ids)
    time.sleep(15)

def run_tgen_traffic(CfgDataG, k, v):

    # Prepare all streams for the traffic
    CfgDataG.stream_ids = []
    streams = v.get('streams')
    for stream in streams:
        #Configure tgen traffic stream
        res = CfgDataG.tg.tg_traffic_config(
            port_handle=CfgDataG.tg_ph1,
            mac_dst=CfgDataG.dut_base_mac,
            mac_src=CfgDataG.T1D1P1_mac,
            rate_percent=CfgDataG.util,
            mode='create',
            l2_encap='ethernet_ii',
            ip_src_addr= CfgDataG.T1D1P1_ipv4,
            ip_dst_addr=v.get('stream_addr'),
            l3_protocol= v.get('stream_type'),
            ip_ttl=v.get('ttl'),
            length_mode=stream.get('length_mode'),
            data_pattern = stream.get('pattern'),
            data_pattern_mode = stream.get('pattern_mode'),
            frame_size_min=stream.get('minframelength'),
            frame_size_max=stream.get('maxframelength'),
            mac_discovery_gw=CfgDataG.D1T1P1_ipv4,
            transmit_mode='continuous'
        )
        CfgDataG.stream_ids.append(res['stream_id'])

        if not CfgDataG.is_single_tgen_port:
            res = CfgDataG.tg.tg_traffic_config(
                port_handle=CfgDataG.tg_ph2,
                mac_dst=CfgDataG.dut_base_mac,
                mac_src=CfgDataG.T1D1P2_mac,
                rate_percent=CfgDataG.util,
                mode='create',
                l2_encap='ethernet_ii',
                ip_src_addr= CfgDataG.T1D1P2_ipv4,
                ip_dst_addr=v.get('bi_stream_addr'),
                l3_protocol= v.get('stream_type'),
                ip_ttl=v.get('ttl'),
                length_mode=stream.get('length_mode'),
                data_pattern = stream.get('pattern'),
                data_pattern_mode = stream.get('pattern_mode'),
                frame_size_min=stream.get('minframelength'),
                frame_size_max=stream.get('maxframelength'),
                mac_discovery_gw=CfgDataG.D1T1P2_ipv4,
                transmit_mode='continuous'
            )
            CfgDataG.stream_ids.append(res['stream_id'])


    result=CfgDataG.tg.tg_traffic_control(action='run', handle=CfgDataG.stream_ids)
    if not result:
        report_fail(f"{CfgDataG.logprefix} Traffic control for {CfgDataG.traffic_cfg_type}:{k} Failed")
        return False;
    else:
        st.log(f"{CfgDataG.logprefix} Traffic control for {CfgDataG.traffic_cfg_type}:{k} Success")

    st.log(f"{CfgDataG.logprefix} Running traffic {CfgDataG.traffic_cfg_type}:{k} for {v.get('duration')}Sec")
    return True


def start_tgen_traffic(CfgDataG):

    # Retrieve traffic_list for intended pid/traffic_type
    traffic_list = get_vrf_traffic_config(CfgDataG.traffic_cfg_type)
    if not len(traffic_list):
        report_fail(f"{CfgDataG.logprefix} No Valid traffic cfg for {CfgDataG.product_id}")
        return False

    for traffic_inst in traffic_list:
        # Check traffic config is not empty
        key = next(iter(traffic_inst), None)
        if key is not None:
            traffic_cfg = traffic_inst[key]
            if traffic_cfg is None:
                report_fail(f"{CfgDataG.logprefix} SNT traffic cfg not defined for {CfgDataG.traffic_cfg_type}:{key}")
                continue

            res = run_tgen_traffic(CfgDataG, key, traffic_cfg)
            if not res:
                return False
            else:
                st.tg_wait(int(traffic_cfg.get('duration')))
                stop_tgen_traffic(CfgDataG, key)
                verify_tgen_traffic_stats(CfgDataG, key)

    return True

def stop_cont_tgen_traffic(CfgDataG):
    stop_tgen_traffic(CfgDataG, 0)
    verify_tgen_traffic_stats(CfgDataG, 0)
    return True

def start_cont_tgen_traffic(CfgDataG):
    # Retrieve traffic_list for intended pid/traffic_type
    traffic_list = get_vrf_traffic_config(CfgDataG.traffic_cfg_type)
    if not len(traffic_list):
        report_fail(f"{CfgDataG.logprefix} No Valid traffic cfg for {CfgDataG.product_id}")
        return False

    for traffic_inst in traffic_list:
        # Check traffic config is not empty
        key = next(iter(traffic_inst), None)
        if key is not None:
            traffic_cfg = traffic_inst[key]
            if traffic_cfg is None:
                report_fail(f"{CfgDataG.logprefix} SNT traffic cfg not defined for {CfgDataG.traffic_cfg_type}:{key}")
                continue
            res = run_tgen_traffic(CfgDataG, key, traffic_cfg)
            if not res:
                return False
            else:
                return True
    return True

def setup_dut_vrf_config(CfgDataG):

    # Check if Vrf0 with required interfaces exists
    if hwqual_common.is_vrf_configured(CfgDataG.dut, "Vrf0", CfgDataG.D1T1P1):
        st.log(f"{CfgDataG.logprefix} Target already configured for VRF traffic")
        return True

    traffic_cfggen = "/opt/cisco/bin/traffic-cfggen.py"

    if CfgDataG.is_ext_loop:
        loop_flag = "-p"
    else:
        loop_flag = "-e"

    tgen_flag = "-b 5.5.5.5" if not CfgDataG.is_single_tgen_port else ""

    cmd = f"{traffic_cfggen} vrf {loop_flag} -i {CfgDataG.D1T1P1} -o {CfgDataG.D1T1P2} {tgen_flag} -s 3.3.3.3 -a"
    st.log(f"{CfgDataG.logprefix} VRF Config command: {cmd}")
    st.config(CfgDataG.dut, cmd, max_time=1800)
    return True

def setup_tgen_interface_config(CfgDataG):

    CfgDataG.tg.tg_traffic_control(
        action='reset',
        port_handle=[CfgDataG.tg_ph1]
    )

    #Configure tgen interface T1D1P1
    res1=CfgDataG.tg.tg_interface_config(
            port_handle=CfgDataG.tg_ph1,
            mode='config',
            intf_ip_addr=CfgDataG.T1D1P1_ipv4,
            gateway=CfgDataG.D1T1P1_ipv4,
            src_mac_addr=CfgDataG.T1D1P1_mac,
            arp_send_req='1'
    )
    st.log("INTFCONF: "+str(res1))
    CfgDataG.tg_ipv4h1 = res1['ipv4_handle']

    if not CfgDataG.is_single_tgen_port:
        CfgDataG.T1D1P2_ipv4 = hwqual_common.get_connected_interface_ipaddress(CfgDataG, CfgDataG.D1T1P2)

        CfgDataG.tg.tg_traffic_control(
            action='reset',
            port_handle=[CfgDataG.tg_ph2]
        )

        #Configure tgen interface T1D1P2
        res2=CfgDataG.tg.tg_interface_config(
            port_handle=CfgDataG.tg_ph2,
            mode='config',
            intf_ip_addr=CfgDataG.T1D1P2_ipv4,
            gateway=CfgDataG.D1T1P2_ipv4,
            src_mac_addr=CfgDataG.T1D1P2_mac,
            arp_send_req='1'
        )
        st.log("INTFCONF: "+str(res2))
        CfgDataG.tg_ipv4h2 = res2['ipv4_handle']

    return True

def install_hwqual_pkg(CfgDataG):
    """
    Install hardware qual debian pkg
    """

    try:
        if not hwqual_common.deploy_hwqual_pkg(CfgDataG):
            return False
    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} VRF traffic test failed: {e}")
        return False

    return True

def vrf_traffic_stop(CfgDataG, result):
    stop_cont_tgen_traffic(CfgDataG)
    return True

def vrf_traffic_start(CfgDataG, result):
    st.log(f"{CfgDataG.logprefix} Starting VRF traffic test")

    try:
        if not install_hwqual_pkg(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} hwqual dpkg install failed")
            return False
        st.log(f"{CfgDataG.logprefix} hwqual dpkg install success")

        # Setup DUT VRF configuration
        if not setup_dut_vrf_config(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} Setup dut VRF config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Setup dut VRF config Success")

        # Setup traffic generator interface
        if not setup_tgen_interface_config(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} Tgen interface config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Tgen interface config Success")

        # Start traffic
        if not start_cont_tgen_traffic(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} VRF traffic start Failed")
            return False
        st.log(f"{CfgDataG.logprefix} VRF traffic started successfully")
        st.report_pass(f"{CfgDataG.logprefix} Test Passed", CfgDataG.dut)

    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} VRF traffic start failed: {e}")
        return False

    return True

def vrf_traffic_validation(CfgDataG, result):
    st.log(f"{CfgDataG.logprefix} Validating VRF traffic test")

    try:
        if not install_hwqual_pkg(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} hwqual dpkg install failed")
            return False
        st.log(f"{CfgDataG.logprefix} hwqual dpkg install success")

        # Setup DUT VRF configuration
        if not setup_dut_vrf_config(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} Setup dut VRF config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Setup dut VRF config Success")

        # Setup traffic generator interface
        if not setup_tgen_interface_config(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} Tgen interface config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Tgen interface config Success")

        # Start traffic
        if not start_tgen_traffic(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} VRF traffic test Failed")
            return False
        st.log(f"{CfgDataG.logprefix} VRF traffic test completed successfully")
        st.report_pass(f"{CfgDataG.logprefix} Test Passed", CfgDataG.dut)

    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} VRF traffic test failed: {e}")
        return False

    return True


def check_vrf_traffic(CfgDataG, test_type, result):
    '''
    '''
    match test_type:
        case "vrf_traffic_validation":
            res = vrf_traffic_validation(CfgDataG, result)
            if not res:
                return False

        case "vrf_traffic_start":
            res = vrf_traffic_start(CfgDataG, result)
            if not res:
                return False

        case "vrf_traffic_stop":
            res = vrf_traffic_stop(CfgDataG, result)
            if not res:
                return False

        case _:  # Default case
            st.error(f"Unknown test type: {test_type}")
            return False

    return True

def test_vrf_traffic_check(CfgDataG, traffic_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {traffic_check} check")

    for check_item in traffic_check:
        if not check_vrf_traffic(CfgDataG, check_item, result):
            report_fail(f"{CfgDataG.logprefix}: Validation of {check_item} failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {check_item} data ok")

    return True
